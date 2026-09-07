"""Map closed SecOps Vega cases back to Vega update mutations."""
from __future__ import annotations

from .constants import ENTITY_TYPE_ALERT, ENTITY_TYPE_INCIDENT, VENDOR_NAME
from .utils import safe_log


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


def extract_sync_targets(case_payload: dict) -> dict:
    events = case_payload.get("events") or case_payload.get("security_events") or []
    incident_ids: list[str] = []
    alert_ids: list[str] = []
    seen_incidents: set[str] = set()
    seen_alerts: set[str] = set()
    for event in events:
        payload = event if isinstance(event, dict) else {}
        entity_type = _event_entity_type(payload)
        if str(payload.get("vega_entity_type") or "").strip().lower() == "alert event":
            incident_id = str(payload.get("vega_incident_id") or "").strip()
            if incident_id and incident_id not in seen_incidents:
                seen_incidents.add(incident_id)
                incident_ids.append(incident_id)
            continue
        identifier = _event_vega_id(payload)
        if not identifier or _is_child_event_id(identifier):
            incident_id = str(payload.get("vega_incident_id") or "").strip()
            if incident_id and incident_id not in seen_incidents:
                seen_incidents.add(incident_id)
                incident_ids.append(incident_id)
            continue
        incident_id = str(payload.get("vega_incident_id") or "").strip()
        if incident_id and incident_id not in seen_incidents:
            seen_incidents.add(incident_id)
            incident_ids.append(incident_id)
        if entity_type == ENTITY_TYPE_INCIDENT:
            if identifier not in seen_incidents:
                seen_incidents.add(identifier)
                incident_ids.append(identifier)
            continue
        if identifier not in seen_alerts:
            seen_alerts.add(identifier)
            alert_ids.append(identifier)
    return {"incidents": incident_ids, "alerts": alert_ids}


def build_alert_sync_input(alert_ids: list[str]) -> dict:
    return {"alertIds": alert_ids, "status": "RESOLVED"}


def build_incident_sync_input(incident_ids: list[str]) -> dict:
    return {"incidentIds": incident_ids, "status": "RESOLVED"}


class SoarRemediator:
    """Close matching Vega alerts or incidents when SOAR cases close."""

    def __init__(self, manager, siemplify, logger_instance=None) -> None:
        self.manager = manager
        self.siemplify = siemplify
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
            incident_ids: list[str] = []
            alert_ids: list[str] = []
            getter = getattr(self.siemplify, "get_cases_by_ticket_id", None)
            if callable(getter):
                try:
                    payload = getter(ticket_id) or {}
                    targets = extract_sync_targets(payload)
                    incident_ids = list(targets.get("incidents") or [])
                    alert_ids = list(targets.get("alerts") or [])
                except Exception as exc:
                    safe_log(self.logger, "warning", "Case fetch failed for %s: %s", ticket_id, exc)
            if not incident_ids and not alert_ids:
                alert_ids = [identifier]
            try:
                if incident_ids:
                    pending_incidents = [item for item in incident_ids if item not in processed]
                    if pending_incidents:
                        self.manager.update_incidents(
                            build_incident_sync_input(pending_incidents)
                        )
                        processed.update(pending_incidents)
                        synced += 1
                pending_alerts = [item for item in alert_ids if item not in processed]
                if pending_alerts:
                    self.manager.update_alerts(build_alert_sync_input(pending_alerts))
                    processed.update(pending_alerts)
                    if not incident_ids:
                        synced += 1
                if identifier not in processed:
                    processed.add(identifier)
            except Exception as exc:
                entity_type = ENTITY_TYPE_INCIDENT if incident_ids else ENTITY_TYPE_ALERT
                safe_log(
                    self.logger,
                    "warning",
                    "Failed to sync Vega %s %s: %s",
                    entity_type,
                    identifier,
                    exc,
                )
        from .utils import utc_now

        state["processed_ids"] = list(processed)[-5000:]
        state["last_check_ms"] = int(utc_now().timestamp() * 1000)
        return {
            "state": state,
            "message": f"Synced {synced} closed Vega case(s).",
        }
