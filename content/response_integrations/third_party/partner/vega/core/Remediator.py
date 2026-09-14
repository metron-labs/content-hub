"""Map closed SecOps Vega cases back to Vega status-only mutations."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .constants import (
    ENTITY_TYPE_ALERT,
    ENTITY_TYPE_INCIDENT,
    SOAR_CASE_DETAILS_PATH,
    SOAR_CASE_SEARCH_PATH,
    SOAR_SEARCH_PAGE_SIZE,
    SOAR_TIME_RANGE_MODIFIED,
    VENDOR_NAME,
)
from .utils import parse_iso_timestamp, safe_log, utc_now

SYNC_MODE_INCIDENT = "incident"
SYNC_MODE_ALERTS = "alerts"
_SOAR_TIMEOUT = 30


def _event_vega_id(event: dict) -> str:
    if not isinstance(event, dict):
        return ""
    for key in ("vega_id", "product_log_id", "event_class_id", "DeviceEventClassID"):
        value = str(event.get(key) or "").strip()
        if value:
            return value
    return ""


def _event_entity_type(event: dict) -> str:
    raw = str(event.get("vega_entity_type") or event.get("event_type") or "").strip()
    if raw.lower() == "incident":
        return ENTITY_TYPE_INCIDENT
    return ENTITY_TYPE_ALERT


def _is_child_event_id(identifier: str) -> bool:
    return ":event:" in identifier


def _is_alert_event(payload: dict) -> bool:
    return str(payload.get("vega_entity_type") or "").strip().lower() == "alert event"


def _as_dict(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            parsed = json.loads(value)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _fields_from_event_card(card: dict) -> dict:
    payload: dict = {}
    for group in card.get("fields") or []:
        if not isinstance(group, dict):
            continue
        for item in group.get("items") or []:
            if not isinstance(item, dict):
                continue
            key = str(item.get("originalName") or item.get("name") or "").strip()
            if key:
                payload[key] = item.get("value")
    return payload


def _flatten_event(event: dict) -> dict:
    payload = dict(event) if isinstance(event, dict) else {}
    extra = _as_dict(
        payload.get("additional_properties")
        or payload.get("additionalProperties")
        or payload.get("AdditionalProperties")
    )
    field_values = _fields_from_event_card(payload)
    merged = dict(extra)
    merged.update(field_values)
    merged.update(payload)
    return merged


def _iter_case_events(case_payload: dict) -> list[dict]:
    """Events from a case dict (SDK ticket payload or GetCaseFullDetails)."""
    if not isinstance(case_payload, dict):
        return []
    direct = case_payload.get("events") or case_payload.get("security_events") or []
    events: list[dict] = [item for item in direct if isinstance(item, dict)]
    alerts = (
        case_payload.get("cyber_alerts")
        or case_payload.get("cyberAlerts")
        or case_payload.get("alerts")
        or case_payload.get("alertCards")
        or case_payload.get("alert_cards")
        or []
    )
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        nested = (
            alert.get("security_events")
            or alert.get("securityEvents")
            or alert.get("events")
            or alert.get("involvedRelations")
            or alert.get("involved_relations")
            or alert.get("securityEventCards")
            or alert.get("security_event_cards")
            or []
        )
        events.extend(item for item in nested if isinstance(item, dict))
        extra = _as_dict(
            alert.get("additional_properties") or alert.get("additionalProperties")
        )
        if extra:
            events.append(extra)
    return events


def extract_sync_targets(case_payload: dict) -> dict:
    """Classify a closed case as incident-only or alerts-only.

    Incident case → resolve the Vega incident only.
    Related-alert batch or unrelated alert case → resolve those Vega alerts
    only. ``vega_incident_id`` on related alerts is not a close target.
    """
    incident_ids: list[str] = []
    alert_ids: list[str] = []
    seen_incidents: set[str] = set()
    seen_alerts: set[str] = set()
    for event in _iter_case_events(case_payload):
        payload = _flatten_event(event)
        identifier = _event_vega_id(payload)
        if _is_alert_event(payload) or _is_child_event_id(identifier):
            continue
        entity_type = _event_entity_type(payload)
        if entity_type == ENTITY_TYPE_INCIDENT:
            if identifier and identifier not in seen_incidents:
                seen_incidents.add(identifier)
                incident_ids.append(identifier)
            continue
        if identifier and identifier not in seen_alerts:
            seen_alerts.add(identifier)
            alert_ids.append(identifier)
    if incident_ids:
        return {
            "mode": SYNC_MODE_INCIDENT,
            "incident_ids": incident_ids,
            "alert_ids": [],
        }
    return {
        "mode": SYNC_MODE_ALERTS,
        "incident_ids": [],
        "alert_ids": alert_ids,
    }


def _iso_ms(millis: int) -> str:
    return datetime.fromtimestamp(max(0, int(millis)) / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )


def _time_to_ms(value) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 1e12:
            return int(number)
        if number > 1e9:
            return int(number * 1000)
        return 0
    parsed = parse_iso_timestamp(str(value))
    if parsed is None:
        return 0
    return int(parsed.timestamp() * 1000)


def _case_close_ms(payload: dict) -> int:
    for key in (
        "closedTime",
        "closeTime",
        "closureTime",
        "updateTime",
        "lastUpdateTime",
        "updatedTime",
        "modificationTimeUnixTimeInMs",
        "modification_time_unix_time_in_ms",
    ):
        millis = _time_to_ms(payload.get(key))
        if millis:
            return millis
    return 0


def _api_root(siemplify) -> str:
    return str(
        getattr(siemplify, "API_ROOT", "") or getattr(siemplify, "api_root", "") or ""
    ).rstrip("/")


def _environment(siemplify) -> str:
    try:
        return str(siemplify.context.connector_info.environment or "").strip()
    except Exception:
        return ""


def _json_response(response) -> dict:
    if response is None:
        return {}
    raise_for_status = getattr(response, "raise_for_status", None)
    if callable(raise_for_status):
        raise_for_status()
    parser = getattr(response, "json", None)
    if not callable(parser):
        return {}
    payload = parser()
    return payload if isinstance(payload, dict) else {}


class SoarRemediator:
    """Close matching Vega alerts or incidents when SOAR cases close."""

    def __init__(self, manager, siemplify, logger_instance=None) -> None:
        self.manager = manager
        self.siemplify = siemplify
        self.logger = logger_instance

    def run_once(self, state: dict) -> dict:
        state = dict(state or {})
        processed = set(state.get("processed_ids") or [])
        now_ms = int(utc_now().timestamp() * 1000)
        last_check_ms = int(state.get("last_check_ms") or 0)
        if last_check_ms <= 0:
            state["processed_ids"] = list(processed)[-5000:]
            state["last_check_ms"] = now_ms
            safe_log(
                self.logger,
                "info",
                "Outbound Vega sync baseline set; cases closed after this run will sync.",
            )
            return {
                "state": state,
                "message": "Close-sync baseline set (no historical closes sent).",
            }

        cases = self._closed_vega_cases(last_check_ms, now_ms)
        synced = 0
        for case_payload in cases:
            case_key = str(
                case_payload.get("id")
                or case_payload.get("identifier")
                or case_payload.get("caseId")
                or ""
            ).strip()
            processed_key = f"case:{case_key}" if case_key else ""
            if processed_key and processed_key in processed:
                continue
            targets = extract_sync_targets(case_payload)
            mode = targets.get("mode")
            incident_ids = [
                item for item in (targets.get("incident_ids") or []) if item not in processed
            ]
            alert_ids = [
                item for item in (targets.get("alert_ids") or []) if item not in processed
            ]
            if mode == SYNC_MODE_INCIDENT and not incident_ids:
                if processed_key:
                    processed.add(processed_key)
                continue
            if mode != SYNC_MODE_INCIDENT and not alert_ids:
                if processed_key:
                    processed.add(processed_key)
                continue
            try:
                if mode == SYNC_MODE_INCIDENT:
                    self.manager.resolve_incidents(incident_ids)
                    processed.update(incident_ids)
                    synced += 1
                elif alert_ids:
                    self.manager.resolve_alerts(alert_ids)
                    processed.update(alert_ids)
                    synced += 1
                if processed_key:
                    processed.add(processed_key)
            except Exception as exc:
                entity_type = (
                    ENTITY_TYPE_INCIDENT if mode == SYNC_MODE_INCIDENT else ENTITY_TYPE_ALERT
                )
                safe_log(
                    self.logger,
                    "warning",
                    "Failed to sync Vega %s %s: %s",
                    entity_type,
                    case_key or incident_ids or alert_ids,
                    exc,
                )
        state["processed_ids"] = list(processed)[-5000:]
        state["last_check_ms"] = now_ms
        return {
            "state": state,
            "message": f"Synced {synced} closed Vega case(s).",
        }

    def _closed_vega_cases(self, since_ms: int, until_ms: int) -> list[dict]:
        sdk_cases = self._closed_cases_from_sdk(since_ms)
        if sdk_cases is not None:
            return sdk_cases
        return self._closed_cases_from_rest(since_ms, until_ms)

    def _closed_cases_from_sdk(self, since_ms: int) -> list[dict] | None:
        """Job/action SDK only. Connectors do not expose this method."""
        method = getattr(
            self.siemplify,
            "get_alerts_ticket_ids_from_cases_closed_since_timestamp",
            None,
        )
        getter = getattr(self.siemplify, "get_cases_by_ticket_id", None)
        if not callable(method) or not callable(getter):
            return None
        try:
            ticket_ids = method(int(since_ms)) or []
        except TypeError:
            # Job SDK requires (timestamp, rule_generator). Vega titles vary, so
            # use REST search instead of guessing one rule generator.
            return None
        except Exception as exc:
            safe_log(self.logger, "warning", "Closed-case SDK lookup failed: %s", exc)
            return []
        cases: list[dict] = []
        for ticket_id in ticket_ids:
            if not str(ticket_id).startswith(f"{VENDOR_NAME}:"):
                continue
            try:
                payload = getter(ticket_id) or {}
            except Exception as exc:
                safe_log(self.logger, "warning", "Case fetch failed for %s: %s", ticket_id, exc)
                continue
            if isinstance(payload, dict) and payload:
                cases.append(payload)
        return cases

    def _closed_cases_from_rest(self, since_ms: int, until_ms: int) -> list[dict]:
        session = getattr(self.siemplify, "session", None)
        root = _api_root(self.siemplify)
        if session is None or not root:
            safe_log(
                self.logger,
                "warning",
                "Outbound Vega sync skipped: connector has no SOAR session/API_ROOT "
                "to search closed cases.",
            )
            return []
        summaries = self._search_closed_case_summaries(session, root, since_ms, until_ms)
        cases: list[dict] = []
        for summary in summaries:
            case_id = str(summary.get("id") or summary.get("identifier") or "").strip()
            if not case_id:
                continue
            details = self._get_case_details(session, root, case_id)
            if details:
                cases.append(details)
            elif summary:
                cases.append(summary)
        safe_log(
            self.logger,
            "info",
            "Close-sync found %s closed Vega case(s) via SOAR search.",
            len(cases),
        )
        return cases

    def _search_closed_case_summaries(
        self, session, root: str, since_ms: int, until_ms: int
    ) -> list[dict]:
        url = f"{root}/{SOAR_CASE_SEARCH_PATH}?format=camel"
        environment = _environment(self.siemplify)
        collected: list[dict] = []
        page = 0
        while True:
            payload = {
                "isCaseClosed": True,
                "title": VENDOR_NAME,
                "startTime": _iso_ms(since_ms),
                "endTime": _iso_ms(until_ms),
                "timeRangeFilter": SOAR_TIME_RANGE_MODIFIED,
                "pageSize": SOAR_SEARCH_PAGE_SIZE,
                "requestedPage": page,
            }
            if environment:
                payload["environments"] = [environment]
            try:
                response = session.post(url, json=payload, timeout=_SOAR_TIMEOUT)
                body = _json_response(response)
            except Exception as exc:
                safe_log(self.logger, "warning", "Closed-case SOAR search failed: %s", exc)
                break
            rows = body.get("results") or body.get("Results") or []
            if not isinstance(rows, list) or not rows:
                break
            for row in rows:
                if not isinstance(row, dict):
                    continue
                title = str(row.get("title") or row.get("name") or "").strip()
                if title and not title.startswith(VENDOR_NAME):
                    continue
                closed_ms = _case_close_ms(row)
                if closed_ms and closed_ms < since_ms:
                    continue
                collected.append(row)
            if len(rows) < SOAR_SEARCH_PAGE_SIZE:
                break
            page += 1
            if page > 20:
                break
        return collected

    def _get_case_details(self, session, root: str, case_id: str) -> dict:
        path = SOAR_CASE_DETAILS_PATH.format(case_id=case_id)
        url = f"{root}/{path}?format=camel"
        try:
            response = session.get(url, timeout=_SOAR_TIMEOUT)
            payload = _json_response(response)
        except Exception as exc:
            safe_log(
                self.logger,
                "warning",
                "GetCaseFullDetails failed for case %s: %s",
                case_id,
                exc,
            )
            return {}
        return payload if isinstance(payload, dict) else {}
