"""
Auto-remediation sync: closed SOAR Flare cases → Flare remediate.

Uses SOAR SDK only (no Google service account):
  - Prefer high-level SiemplifyAction methods when present
  - On connectors (SiemplifyBase), call the same SDK HTTP endpoints via session
  - First run: fetch closed cases since epoch (ALL_CLOSED_CASES)
  - Later runs: fetch closed since last_successful_check_timestamp
  - Flare remediate API uses a fixed batch size of 10
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote, unquote

from .constants import (
    DEFAULT_FLARE_ACTION_BATCH_SIZE,
    DEFAULT_SDK_HTTP_TIMEOUT,
    VENDOR_NAME,
)
from .utils import (
    flare_url_for_uid,
    parse_iso_timestamp,
    safe_log,
    utc_now_iso,
)

logger = logging.getLogger(__name__)

# Epoch used when no remediation checkpoint exists yet ("get all closed cases").
_EPOCH_MS = 0

# Fields that carry Flare event UIDs (example.json metadata.uid + connector packing).
# (Explicit key checks live in _extract_uids_from_event.)

_FLARE_URL_UID_RE = re.compile(
    r"(?:app\.flare\.io/#/|firework/events/)([^\s\"'<>]+)",
    re.IGNORECASE,
)


def _normalize_uid(value: Any) -> Optional[str]:
    """Return a non-empty uid string, or None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in ("null", "none"):
        return None
    return text


def _add_uid_string(value: Any, found: set) -> None:
    """Add uid value(s). Supports CSV lists from extensions.flare_uids."""
    text = _normalize_uid(value)
    if not text:
        return
    if "," in text and not text.startswith("{") and not text.startswith("["):
        for part in text.split(","):
            uid = _normalize_uid(part)
            if uid:
                found.add(uid)
        return
    found.add(text)


def _uid_from_flare_url(url: Any, found: set) -> None:
    text = _normalize_uid(url)
    if not text:
        return
    for match in _FLARE_URL_UID_RE.finditer(text):
        uid = _normalize_uid(unquote(match.group(1)).rstrip("/"))
        if uid:
            found.add(uid)


def _extract_uids_from_event(event: Any, found: set) -> None:
    """Extract UIDs from a single SOAR/Flare event object only."""
    if event is None:
        return
    if not isinstance(event, dict):
        try:
            attrs = getattr(event, "__dict__", None)
            if isinstance(attrs, dict):
                event = attrs
            else:
                return
        except Exception:
            return

    meta = event.get("metadata")
    if isinstance(meta, dict):
        if "uid" in meta:
            _add_uid_string(meta.get("uid"), found)
        if meta.get("flare_url"):
            _uid_from_flare_url(meta.get("flare_url"), found)

    # CaseFullDetails keeps the Flare uid in event_class_id.
    # DeviceEventClassID is the event category (event_type), not the uid.
    for key in (
        "product_log_id",
        "productLogId",
        "flare_uid",
        "flareUid",
        "event_class_id",
        "EventClassId",
    ):
        if key in event:
            _add_uid_string(event.get(key), found)
    if event.get("flare_url"):
        _uid_from_flare_url(event.get("flare_url"), found)

    # Nested bags sometimes hold the original connector fields.
    for nest_key in ("additional_properties", "AdditionalProperties", "fields", "Fields"):
        nested = event.get(nest_key)
        if isinstance(nested, dict):
            _extract_uids_from_event(nested, found)

    # Connector packs the original Flare event JSON into details.
    details = event.get("details")
    if isinstance(details, str):
        stripped = details.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                _extract_uids_from_event(parsed, found)
            elif isinstance(parsed, list):
                for item in parsed:
                    _extract_uids_from_event(item, found)
    elif isinstance(details, dict):
        _extract_uids_from_event(details, found)


def _iter_case_alerts(case_obj: Any) -> list:
    """Return alert objects from a CaseFullDetails-style payload."""
    if case_obj is None:
        return []
    if isinstance(case_obj, dict):
        for key in ("alerts", "Alarms", "cyber_alerts", "Alerts"):
            alerts = case_obj.get(key)
            if isinstance(alerts, list) and alerts:
                return alerts
        # Enriched connector payload
        nested = case_obj.get("alerts_full_details")
        if nested is not None:
            return _iter_case_alerts(nested)
        # Ticket stub / already an alert-shaped object
        if any(k in case_obj for k in ("events", "Events", "ticket_id", "TicketId")):
            return [case_obj]
        return []
    try:
        attrs = getattr(case_obj, "__dict__", None)
        if isinstance(attrs, dict):
            return _iter_case_alerts(attrs)
    except Exception:
        pass
    return []


def _iter_alert_events(alert_obj: Any) -> list:
    if alert_obj is None:
        return []
    if isinstance(alert_obj, dict):
        for key in ("events", "Events", "security_events", "SecurityEvents"):
            events = alert_obj.get(key)
            if isinstance(events, list):
                return events
        return []
    try:
        events = getattr(alert_obj, "events", None)
        if isinstance(events, list):
            return events
        attrs = getattr(alert_obj, "__dict__", None)
        if isinstance(attrs, dict):
            return _iter_alert_events(attrs)
    except Exception:
        pass
    return []


def extract_flare_uids_from_obj(obj: Any, found: Optional[set] = None) -> set:
    """
    Extract Flare UIDs only from events belonging to the fetched case/alert.

    Does not scrape the whole case blob (wall/comments/related) — only alert
    events (and their details / product_log_id / metadata.uid).
    """
    if found is None:
        found = set()

    if obj is None:
        return found

    # Prefer case → cyber_alerts/alerts → security_events/events scoping.
    alerts = _iter_case_alerts(obj)
    if alerts:
        for alert in alerts:
            events = _iter_alert_events(alert)
            if events:
                for event in events:
                    _extract_uids_from_event(event, found)
            else:
                # Alert with no nested events: allow explicit uid fields only.
                if isinstance(alert, dict):
                    for key in (
                        "product_log_id",
                        "flare_uid",
                        "event_class_id",
                        "EventClassId",
                    ):
                        if key in alert:
                            _add_uid_string(alert.get(key), found)
                    # Do NOT use alert.extensions.flare_uids — older merged
                    # cases can carry oversized CSV lists from prior runs.

        # If cyber_alerts events were thin, also try alerts_full_details.
        if not found and isinstance(obj, dict) and obj.get("alerts_full_details") is not None:
            extract_flare_uids_from_obj(obj.get("alerts_full_details"), found)
        return found

    # Fallback: treat payload as a single event/alert.
    if isinstance(obj, dict):
        events = _iter_alert_events(obj)
        if events:
            for event in events:
                _extract_uids_from_event(event, found)
            return found
        _extract_uids_from_event(obj, found)
        return found

    if isinstance(obj, list):
        for item in obj:
            extract_flare_uids_from_obj(item, found)
        return found

    try:
        attrs = getattr(obj, "__dict__", None)
        if isinstance(attrs, dict) and attrs:
            extract_flare_uids_from_obj(attrs, found)
    except Exception:
        pass

    return found


def _to_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _case_is_flare(case_obj: Any, vendor_name: str = VENDOR_NAME) -> bool:
    """Heuristic: Flare connector cases are tagged / vendored with VENDOR_NAME."""
    markers = {vendor_name, VENDOR_NAME, "Flare", "Flare-Verify", "Flare Verify"}
    markers = {m for m in markers if m}

    def _matches(value: Any) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        return any(m == text or m in text for m in markers)

    # Structured fields only (avoid stringifying the whole case blob).
    field_keys = (
        "device_vendor",
        "device_product",
        "rule_generator",
        "vendor",
        "product",
        "Vendor",
        "Product",
        "RuleGenerator",
    )
    if isinstance(case_obj, dict):
        for key in field_keys:
            if _matches(case_obj.get(key)):
                return True
    for key in field_keys:
        if _matches(getattr(case_obj, key, None)):
            return True

    tags = []
    for attr in ("tags", "case_tags", "Tags"):
        raw = getattr(case_obj, attr, None)
        if raw:
            tags.extend([str(t) for t in _to_list(raw)])
    if isinstance(case_obj, dict):
        for key in ("tags", "case_tags", "Tags"):
            if case_obj.get(key):
                tags.extend([str(t) for t in _to_list(case_obj.get(key))])
    if any(_matches(t) for t in tags):
        return True

    # Nested alert/event vendor fields (CaseFullDetails).
    for alert in _iter_case_alerts(case_obj):
        if isinstance(alert, dict):
            for key in field_keys:
                if _matches(alert.get(key)):
                    return True
        for event in _iter_alert_events(alert):
            if isinstance(event, dict):
                for key in field_keys:
                    if _matches(event.get(key)):
                        return True
    return False


class SoarRemediator:
    """Sync closed SOAR Flare cases → Flare remediate (no Google SA)."""

    def __init__(
        self,
        flare_manager,
        siemplify,
        rule_generator: str = VENDOR_NAME+"Flare-test-2",
        state: Optional[dict] = None,
        logger_instance=None,
    ) -> None:
        self.flare = flare_manager
        self.siemplify = siemplify
        self.action_batch_size = DEFAULT_FLARE_ACTION_BATCH_SIZE
        self.rule_generator = (rule_generator or VENDOR_NAME).strip() or VENDOR_NAME
        self.state = state if isinstance(state, dict) else {
            "last_successful_check_timestamp": None,
            "processed_alerts": {},
        }
        self.state.setdefault("processed_alerts", {})
        self.logger = logger_instance or logger

    def _log(self, level: str, msg: str, *args) -> None:
        safe_log(self.logger, level, msg, *args)

    def get_query_start_time(self) -> Optional[datetime]:
        """
        Return the last successful remediation timestamp, or None to mean
        "fetch all closed cases" on the first run.
        """
        return parse_iso_timestamp(self.state.get("last_successful_check_timestamp"))

    def _query_start_ms(self, start_time: Optional[datetime]) -> int:
        if start_time is None:
            return _EPOCH_MS
        return int(start_time.timestamp() * 1000)

    # ------------------------------------------------------------------
    # SDK / HTTP helpers (works on SiemplifyAction and connector SiemplifyBase)
    # ------------------------------------------------------------------

    def _sdk_address(
        self,
        provider_method: str,
        *args,
        fallback_path: str = "",
    ) -> Optional[str]:
        provider = getattr(self.siemplify, "address_provider", None)
        method = (
            getattr(provider, provider_method, None)
            if provider is not None
            else None
        )
        if callable(method):
            try:
                return method(*args)
            except Exception as exc:
                self._log("warning", "%s failed: %s", provider_method, exc)

        api_root = getattr(self.siemplify, "API_ROOT", None)
        if not api_root or not fallback_path:
            return None
        base = (
            f"{str(api_root).rstrip('/')}/external/v1/sdk/{fallback_path}"
        )
        return (
            f"{base}&format=snake"
            if "?" in base
            else f"{base}?format=snake"
        )

    def _sdk_request(
        self,
        method: str,
        address: str,
        payload: Optional[dict] = None,
    ) -> Any:
        session = getattr(self.siemplify, "session", None)
        if session is None or not address:
            return None
        timeout = DEFAULT_SDK_HTTP_TIMEOUT
        try:
            if method.upper() == "GET":
                response = session.get(address, timeout=timeout)
            else:
                response = session.post(
                    address, json=payload or {}, timeout=timeout
                )
        except TypeError:
            # Some SOAR session wrappers do not accept timeout=.
            if method.upper() == "GET":
                response = session.get(address)
            else:
                response = session.post(address, json=payload or {})
        validate = getattr(self.siemplify, "validate_siemplify_error", None)
        if callable(validate):
            validate(response)
        else:
            response.raise_for_status()
        if not response.content:
            return None
        return response.json()

    def _load_case(self, case_id: Any) -> Any:
        if case_id is None or case_id == "":
            return None

        for method_name in ("get_case_by_id", "_get_case_by_id"):
            method = getattr(self.siemplify, method_name, None)
            if not callable(method):
                continue
            try:
                return method(case_id)
            except Exception as exc:
                self._log("warning", "%s(%s) failed: %s", method_name, case_id, exc)

        # Connector / SiemplifyBase fallback: CaseFullDetails HTTP API
        address = self._sdk_address(
            "provide_get_case_full_details_address",
            case_id,
            False,
            fallback_path=f"CaseFullDetails/{quote(str(case_id), safe='')}/false",
        )
        if not address:
            return None
        try:
            return self._sdk_request("GET", address)
        except Exception as exc:
            self._log("warning", "CaseFullDetails(%s) failed: %s", case_id, exc)
            return None

    def _case_ids_for_ticket(self, ticket_id: str) -> list:
        method = getattr(self.siemplify, "get_cases_by_ticket_id", None)
        if callable(method):
            try:
                return _to_list(method(ticket_id))
            except Exception as exc:
                self._log("warning", "get_cases_by_ticket_id(%s) failed: %s", ticket_id, exc)

        # Connector fallback: GetCasesByFilter with ticked_ids_free_search
        address = self._sdk_address(
            "provide_get_cases_by_filter_address",
            fallback_path="GetCasesByFilter",
        )
        if not address:
            return []
        payload = {
            "ticked_ids_free_search": ticket_id,
            "environments": [],
            "case_ids_free_search": "",
            "products": [],
            "analysts": [],
            "status": [],
            "tags": [],
            "start_time_unix_time_in_ms": -1,
            "end_time_unix_time_in_ms": -1,
            "case_names": [],
            "priorities": [],
            "wall_data_free_search": "",
            "stages": [],
            "networks": [],
            "case_types": [],
            "entities_free_search": "",
        }
        try:
            return _to_list(self._sdk_request("POST", address, payload))
        except Exception as exc:
            self._log(
                "warning",
                "GetCasesByFilter(ticket=%s) failed: %s",
                ticket_id,
                exc,
            )
            return []

    def _alerts_for_case(self, case_id: Any) -> Any:
        """Load alert payloads for a case when CaseFullDetails is thin."""
        address = self._sdk_address(
            "provide_get_alerts_full_details_address",
            case_id,
            False,
            fallback_path=(
                f"AlertsFullDetails/{quote(str(case_id), safe='')}/false"
            ),
        )
        if not address:
            return None
        try:
            return self._sdk_request("GET", address)
        except Exception:
            # Classic path is GET; some tenants expose POST AlertFullDetails only.
            return None

    def _enrich_case_payload(self, case_id: Any, case_obj: Any) -> Any:
        """Ensure case payload includes events/UIDs when possible."""
        if case_obj is None:
            return None
        if extract_flare_uids_from_obj(case_obj):
            return case_obj
        alerts = self._alerts_for_case(case_id)
        if alerts is None:
            return case_obj
        if isinstance(case_obj, dict):
            merged = dict(case_obj)
            merged["alerts_full_details"] = alerts
            return merged
        return {"case": case_obj, "alerts_full_details": alerts}

    def _cases_from_ticket_id(self, ticket_id: str) -> list:
        cases = []
        for case_id in self._case_ids_for_ticket(ticket_id):
            case_obj = self._enrich_case_payload(case_id, self._load_case(case_id))
            if case_obj is not None:
                cases.append((str(case_id), case_obj))
        return cases

    def _ticket_ids_closed_since(self, ts_ms: int) -> list:
        method = getattr(
            self.siemplify,
            "get_alerts_ticket_ids_from_cases_closed_since_timestamp",
            None,
        )
        if callable(method):
            try:
                return _to_list(method(ts_ms, self.rule_generator))
            except Exception as exc:
                self._log("warning", "Closed-case ticket lookup failed: %s", exc)

        address = self._sdk_address(
            "provide_close_case_alerts_ticket_ids_address",
            fallback_path="GetAlertsTicketIdsFromCasesClosedSinceTimestamp",
        )
        if not address:
            return []
        payload = {
            "time_stamp_unix_ms": str(ts_ms),
            "rule_generator": self.rule_generator,
            "include_dismissed_alerts": False,
        }
        try:
            return _to_list(self._sdk_request("POST", address, payload))
        except Exception as exc:
            self._log("warning", "Closed-case ticket HTTP lookup failed: %s", exc)
            return []

    def _closed_case_ids(self, start_time: Optional[datetime]) -> list:
        ts_ms = self._query_start_ms(start_time)
        # Always pass start_time_from explicitly — SDK defaults to last 30 days and
        # can silently drop older cases even when filtering by close_time.
        # Do not filter by tags server-side — Flare matching is done after load
        # via vendor/tags/UID heuristics (case_tags can vary by platform).
        kwargs = {
            "status": "CLOSE",
            "start_time_from_unix_time_in_ms": _EPOCH_MS,
            "close_time_from_unix_time_in_ms": ts_ms,
            "sort_by": "CLOSE_TIME",
            "sort_order": "DESC",
            "max_results": 1000,
        }

        method = getattr(self.siemplify, "get_cases_ids_by_filter", None)
        if callable(method):
            try:
                return _to_list(
                    method(
                        kwargs["status"],
                        start_time_from_unix_time_in_ms=kwargs[
                            "start_time_from_unix_time_in_ms"
                        ],
                        close_time_from_unix_time_in_ms=kwargs[
                            "close_time_from_unix_time_in_ms"
                        ],
                        sort_by=kwargs["sort_by"],
                        sort_order=kwargs["sort_order"],
                        max_results=kwargs["max_results"],
                    )
                )
            except TypeError:
                try:
                    return _to_list(method("CLOSE"))
                except Exception as exc:
                    self._log("warning", "get_cases_ids_by_filter failed: %s", exc)
            except Exception as exc:
                self._log("warning", "get_cases_ids_by_filter failed: %s", exc)

        address = self._sdk_address(
            "provide_get_cases_ids_by_filter_address",
            fallback_path="GetCasesIdByFilter",
        )
        if not address:
            return []
        try:
            return _to_list(self._sdk_request("POST", address, kwargs))
        except Exception as exc:
            self._log("warning", "GetCasesIdByFilter HTTP lookup failed: %s", exc)
            return []

    def fetch_closed_flare_cases(self, start_time: Optional[datetime]) -> list:
        """Return list of (case_key, case_payload) for closed Flare cases."""
        results: list = []
        seen_keys: set = set()
        ts_ms = self._query_start_ms(start_time)

        ticket_ids = self._ticket_ids_closed_since(ts_ms)
        if ticket_ids:
            self._log(
                "info",
                "Closed-case ticket lookup returned %d id(s): %s",
                len(ticket_ids),
                ticket_ids[:10],
            )

        for ticket_id in ticket_ids:
            ticket_key = str(ticket_id)
            if not ticket_key or ticket_key in seen_keys:
                continue
            cases = self._cases_from_ticket_id(ticket_key)
            if cases:
                for case_id, case_obj in cases:
                    key = f"case:{case_id}"
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    results.append((key, case_obj))
            else:
                case_obj = self._enrich_case_payload(
                    ticket_key, self._load_case(ticket_key)
                )
                if case_obj is not None:
                    key = f"case:{ticket_key}"
                    seen_keys.add(key)
                    results.append((key, case_obj))
                else:
                    # Ticket-only stub — keep for debug; UID extract may still
                    # succeed if the ticket itself embeds a Flare uid.
                    key = f"ticket:{ticket_key}"
                    seen_keys.add(key)
                    results.append((key, {"ticket_id": ticket_key}))

        for case_id in self._closed_case_ids(start_time):
            key = f"case:{case_id}"
            if key in seen_keys:
                continue
            case_obj = self._enrich_case_payload(case_id, self._load_case(case_id))
            if case_obj is None:
                continue
            if (
                not _case_is_flare(case_obj, self.rule_generator)
                and not extract_flare_uids_from_obj(case_obj)
            ):
                continue
            seen_keys.add(key)
            results.append((key, case_obj))

        return results

    def resolve_targets(self, closed_items: list) -> tuple:
        processed = self.state.get("processed_alerts") or {}
        pending: list = []
        seen: set = set()
        skipped = 0
        per_item: dict = {}

        for key, payload in closed_items:
            if key in processed:
                skipped += 1
                prev = processed.get(key) or {}
                prev_uids = prev.get("flare_uids") or []
                for uid in prev_uids:
                    self._log(
                        "info",
                        "Already remediated Flare event uid=%s flare_url=%s",
                        uid,
                        flare_url_for_uid(uid),
                    )
                continue

            uids = sorted(extract_flare_uids_from_obj(payload))
            if not uids:
                self._log(
                    "info",
                    "Closed item %s had no extractable Flare UID.",
                    key,
                )
                continue

            self._log(
                "info",
                "Closed item %s: extracted %d uid(s) from case alert events.",
                key,
                len(uids),
            )

            new_uids = [uid for uid in uids if uid not in seen]
            for uid in new_uids:
                seen.add(uid)
                pending.append(uid)
                self._log(
                    "info",
                    "Found closed Flare case — will remediate uid=%s flare_url=%s",
                    uid,
                    flare_url_for_uid(uid),
                )
            per_item[key] = new_uids

        return pending, skipped, per_item

    def run_once(self) -> dict:
        start_time = self.get_query_start_time()
        current_run = utc_now_iso()
        checkpoint_label = (
            start_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if start_time
            else "ALL_CLOSED_CASES"
        )

        closed_items = self.fetch_closed_flare_cases(start_time)
        pending, skipped, per_item = self.resolve_targets(closed_items)

        result = {"applied": 0, "applied_uids": [], "errors": []}
        if pending:
            result = self.flare.remediate_events(
                pending, batch_size=self.action_batch_size
            )
            applied_uids = result.get("applied_uids") or pending[
                : int(result.get("applied") or 0)
            ]
            for uid in applied_uids:
                self._log(
                    "info",
                    "Remediated Flare event uid=%s flare_url=%s",
                    uid,
                    flare_url_for_uid(uid),
                )

        # Advance when we found closed items and either remediated or only saw
        # already-processed ones. Do not advance on an empty lookup window.
        has_work = bool(closed_items)
        can_advance = has_work and not result["errors"] and (
            result["applied"] > 0 or (skipped > 0 and not pending)
        )

        new_checkpoint = None
        if can_advance:
            self.state["last_successful_check_timestamp"] = current_run
            new_checkpoint = current_run
            processed = self.state.setdefault("processed_alerts", {})
            for key, uids in per_item.items():
                processed[key] = {
                    "flare_uids": uids,
                    "action": "remediate",
                    "processed_at": current_run,
                    "status": "closed",
                }
            if len(processed) > 5000:
                items = sorted(
                    processed.items(),
                    key=lambda kv: kv[1].get("processed_at") or "",
                    reverse=True,
                )
                self.state["processed_alerts"] = dict(items[:4000])

        if result["errors"]:
            msg = (
                f"Remediation sync completed with errors: "
                f"{result['applied']} remediated, "
                f"{len(result['errors'])} batch error(s). Checkpoint not advanced."
            )
        elif not closed_items:
            msg = (
                "No closed Flare SOAR cases/alerts since "
                f"{checkpoint_label}."
            )
        elif not pending and skipped:
            msg = (
                f"All {skipped} closed item(s) already processed. "
                f"Checkpoint advanced to {new_checkpoint}."
            )
        elif not pending:
            msg = (
                f"No Flare UIDs extracted from {len(closed_items)} closed item(s). "
                f"Checkpoint {'advanced' if new_checkpoint else 'not advanced'}."
            )
        else:
            msg = (
                f"Remediation sync completed: {result['applied']} Flare event(s) "
                f"remediated from {len(closed_items)} closed SOAR item(s)."
            )

        self._log("info", msg)
        return {
            "message": msg,
            "remediated_count": result["applied"],
            "remediated_uids": pending[: result["applied"]] if result["applied"] else [],
            "alerts_checked": len(closed_items),
            "already_processed_skipped": skipped,
            "pending_remediation_count": len(pending),
            "checkpoint_used": checkpoint_label,
            "new_checkpoint_saved": new_checkpoint,
            "errors": result["errors"],
            "state": self.state,
        }


# Backwards-compatible alias
SecOpsRemediator = SoarRemediator
