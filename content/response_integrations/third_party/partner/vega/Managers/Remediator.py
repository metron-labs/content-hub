"""Map closed SecOps Vega cases back to Vega update mutations."""
from __future__ import annotations

from constants import ENTITY_TYPE_ALERT, ENTITY_TYPE_INCIDENT, VENDOR_NAME
from utils import resolve_outgoing_fields, safe_log


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


def extract_sync_targets(case_payload: dict) -> list[dict]:
    events = case_payload.get("events") or case_payload.get("security_events") or []
    targets = []
    seen = set()
    for event in events:
        identifier = _event_vega_id(event if isinstance(event, dict) else {})
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        targets.append(
            {
                "id": identifier,
                "entity_type": _event_entity_type(event),
            }
        )
    return targets


def build_alert_sync_input(alert_ids: list[str], fields: list[str], comment: str) -> dict:
    payload = {"alertIds": alert_ids}
    if "Status" in fields:
        payload["status"] = "RESOLVED"
    if "Comments" in fields and comment:
        payload["comment"] = comment
    return payload


def build_incident_sync_input(incident_ids: list[str], fields: list[str], comment: str) -> dict:
    payload = {"incidentIds": incident_ids}
    if "Status" in fields:
        payload["status"] = "RESOLVED"
    if "Comments" in fields and comment:
        payload["comment"] = comment
    return payload


class SoarRemediator:
    """Push closed Vega-sourced SOAR cases to Vega when sync is enabled."""

    def __init__(self, manager, siemplify, fields_raw: str, logger_instance=None) -> None:
        self.manager = manager
        self.siemplify = siemplify
        self.fields = resolve_outgoing_fields(fields_raw)
        self.logger = logger_instance

    def run_once(self, state: dict) -> dict:
        state = dict(state or {})
        processed = set(state.get("processed_ids") or [])
        method = getattr(
            self.siemplify,
            "get_alerts_ticket_ids_from_cases_closed_since_timestamp",
            None,
        )
        if not callable(method):
            safe_log(
                self.logger,
                "info",
                "Outbound Vega sync skipped: closed-case SDK method is not available.",
            )
            return {"state": state, "message": "Sync skipped (SDK method missing)."}
        try:
            ticket_ids = method(int(state.get("last_check_ms") or 0)) or []
        except Exception as exc:
            safe_log(self.logger, "warning", "Closed-case lookup failed: %s", exc)
            return {"state": state, "message": "Sync lookup failed."}

        synced = 0
        for ticket_id in ticket_ids:
            if not str(ticket_id).startswith(f"{VENDOR_NAME}:"):
                continue
            identifier = str(ticket_id).split(":", 1)[-1]
            if identifier in processed:
                continue
            entity_type = ENTITY_TYPE_ALERT
            # ticket_id is Vega:<id>; entity type is recovered from case events when possible.
            getter = getattr(self.siemplify, "get_cases_by_ticket_id", None)
            comment = ""
            if callable(getter):
                try:
                    payload = getter(ticket_id) or {}
                    targets = extract_sync_targets(payload)
                    if targets:
                        entity_type = targets[0]["entity_type"]
                        identifier = targets[0]["id"]
                    wall = payload.get("wall") or payload.get("comments") or []
                    if wall and isinstance(wall, list):
                        last = wall[-1]
                        if isinstance(last, dict):
                            comment = str(last.get("text") or last.get("comment") or "")
                        else:
                            comment = str(last)
                except Exception as exc:
                    safe_log(self.logger, "warning", "Case fetch failed for %s: %s", ticket_id, exc)
            try:
                if entity_type == ENTITY_TYPE_INCIDENT:
                    payload = build_incident_sync_input([identifier], self.fields, comment)
                    if len(payload) > 1:
                        self.manager.update_incidents(payload)
                        synced += 1
                else:
                    payload = build_alert_sync_input([identifier], self.fields, comment)
                    if len(payload) > 1:
                        self.manager.update_alerts(payload)
                        synced += 1
                processed.add(identifier)
            except Exception as exc:
                safe_log(
                    self.logger,
                    "warning",
                    "Failed to sync Vega %s %s: %s",
                    entity_type,
                    identifier,
                    exc,
                )
        from utils import utc_now

        state["processed_ids"] = list(processed)[-5000:]
        state["last_check_ms"] = int(utc_now().timestamp() * 1000)
        return {
            "state": state,
            "message": f"Synced {synced} closed Vega case(s).",
        }
