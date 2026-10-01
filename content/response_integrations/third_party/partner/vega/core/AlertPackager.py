"""Build SOAR AlertInfo packages from Vega alerts and incidents."""
from __future__ import annotations

from .constants import (
    DEVICE_PRODUCT,
    ENTITY_TYPE_ALERT,
    ENTITY_TYPE_INCIDENT,
    MAX_EVENTS_PER_ALERT,
    VENDOR_NAME,
)
from .mapping import (
    alert_grouping_id,
    alert_priority,
    build_event_dict,
    build_vega_alert_event_dict,
    case_display_name,
    normalize_alert_event,
    record_id,
    record_severity,
    soar_meta,
)
from .utils import parse_iso_timestamp, safe_log


# Reject epoch-0 / 1970 timestamps and values that are not real event times.
_MIN_VALID_EVENT_MS = 946684800000  # 2000-01-01
_MAX_VALID_EVENT_MS = 4102444800000  # 2100-01-01


def _coerce_unix_ms(raw) -> int | None:
    if raw in (None, "", 0, "0"):
        return None
    value = None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
    else:
        text = str(raw).strip()
        if not text or text in {"0", "0.0"}:
            return None
        if text.isdigit() or (text.replace(".", "", 1).isdigit() and text.count(".") < 2):
            value = float(text)
        else:
            parsed = parse_iso_timestamp(text)
            if parsed is None:
                return None
            millis = int(parsed.timestamp() * 1000)
            if millis < _MIN_VALID_EVENT_MS or millis > _MAX_VALID_EVENT_MS:
                return None
            return millis
    if value is None or value <= 0:
        return None
    if value < 1e12:
        value *= 1000
    millis = int(value)
    if millis < _MIN_VALID_EVENT_MS or millis > _MAX_VALID_EVENT_MS:
        return None
    return millis


def _field_ms(record: dict, *keys: str) -> int | None:
    if not isinstance(record, dict):
        return None
    for key in keys:
        coerced = _coerce_unix_ms(record.get(key))
        if coerced is not None:
            return coerced
    return None


def record_start_end(record: dict, fallback: int) -> tuple[int, int]:
    """Incident and alert window: start is createdAt, end is last update.

    Incidents send lastUpdated. Alerts send updatedAt for the same moment.
    A missing end uses the start so SecOps does not get an empty end time.
    """
    start = _field_ms(record, "createdAt")
    end = _field_ms(record, "lastUpdated", "updatedAt")
    if start is None:
        start = fallback
    if end is None:
        end = start
    return start, end


def _time_values(payload: dict) -> list[int]:
    """Valid timestamps from keys whose name contains 'time'."""
    found: list[int] = []
    if not isinstance(payload, dict):
        return found
    for key, value in payload.items():
        if isinstance(value, dict):
            found.extend(_time_values(value))
            continue
        if "time" not in str(key).lower():
            continue
        coerced = _coerce_unix_ms(value)
        if coerced is not None:
            found.append(coerced)
    return found


def event_start_end(payload: dict, parent_start: int, parent_end: int) -> tuple[int, int]:
    """Alert-event window from any time field, otherwise the parent alert."""
    times = _time_values(payload if isinstance(payload, dict) else {})
    if not times:
        return parent_start, parent_end
    return min(times), max(times)


_PINNED_TIME_KEYS = {
    "createdat",
    "updatedat",
    "lastupdated",
    "created_at",
    "updated_at",
    "last_updated",
}


def _pin_related_event(event: dict, start_time: int, end_time: int) -> None:
    """Force one window so SecOps does not split a batch on event time.

    Grouping by source identifier ignores the 24-hour setting only when every
    alert in the batch carries that same identifier. Per-alert createdAt and
    child-event times make the platform fall back to entity grouping, which
    does use the 24-hour window and opens a new case per alert.
    """
    if not isinstance(event, dict):
        return
    original_created = event.get("created_at") or event.get("createdAt")
    original_updated = (
        event.get("updated_at") or event.get("updatedAt") or event.get("lastUpdated")
    )
    event["StartTime"] = start_time
    event["EndTime"] = end_time
    for key in list(event.keys()):
        folded = str(key).lower()
        compact = folded.replace("_", "")
        if compact in {"starttime", "endtime"}:
            continue
        if "time" in folded or compact in _PINNED_TIME_KEYS or folded in _PINNED_TIME_KEYS:
            event.pop(key, None)
    if original_created not in (None, ""):
        event["vega_alert_created_at"] = str(original_created)
    if original_updated not in (None, ""):
        event["vega_alert_updated_at"] = str(original_updated)


def _attach_child_events(
    alert,
    record: dict,
    parent_start: int,
    parent_end: int,
    logger_instance=None,
    pin_to_parent: bool = False,
) -> None:
    identifier = record_id(record, ENTITY_TYPE_ALERT)
    child_events = list(record.get("alert_events") or [])
    if len(child_events) > MAX_EVENTS_PER_ALERT:
        safe_log(
            logger_instance,
            "info",
            "Vega alert %s has %s events; attaching the first %s (SOAR per-alert cap).",
            identifier,
            len(child_events),
            MAX_EVENTS_PER_ALERT,
        )
        child_events = child_events[:MAX_EVENTS_PER_ALERT]
    for index, vega_event in enumerate(child_events):
        payload = vega_event if isinstance(vega_event, dict) else {}
        normalized = normalize_alert_event(payload) if payload else {}
        if pin_to_parent:
            child_start, child_end = parent_start, parent_end
        else:
            child_start, child_end = event_start_end(
                normalized, parent_start, parent_end
            )
        child = build_vega_alert_event_dict(
            record, vega_event, child_start, child_end, index
        )
        if pin_to_parent:
            _pin_related_event(child, parent_start, parent_end)
        alert.events.append(child)


def create_alerts(records: list[tuple[str, dict]], siemplify, logger_instance=None) -> list:
    """Turn pipeline records into SOAR AlertInfo packages.

    Incident case: one AlertInfo for the Vega incident. Related Vega alerts
    are separate AlertInfo objects with a batch grouping id so they form their
    own cases. Each alert keeps its own Name (Vega Incident vs Vega Alert).
    Related batches share Product, Rule Generator (the incident title plus
    batch N), and the incident createdAt/lastUpdated window. SecOps groups on
    that shared window, so a batch stays one case up to the 90-alert cap.
    The incident case and standalone alerts use their own createdAt and last
    update.
    """
    from soar_sdk.SiemplifyConnectorsDataModel import AlertInfo
    from soar_sdk.SiemplifyUtils import unix_now

    if not records:
        return []
    current_time = unix_now()
    environment = ""
    try:
        environment = siemplify.context.connector_info.environment
    except Exception:
        environment = ""
    packages = []
    for entity_type, record in records:
        identifier = record_id(record, entity_type)
        if not identifier:
            continue
        meta = soar_meta(record)
        if meta.get("is_related_batch"):
            # One window for the whole batch. Per-alert createdAt values are
            # often days apart, and SecOps then opens a new case for each.
            start_time, end_time = record_start_end(
                {
                    "createdAt": meta.get("grouping_start") or meta.get("grouping_time"),
                    "lastUpdated": meta.get("grouping_end") or meta.get("grouping_time"),
                },
                current_time,
            )
        else:
            start_time, end_time = record_start_end(record, current_time)
        severity = record_severity(record)
        ticket_suffix = str(meta.get("ticket_suffix") or "").strip()
        ticket_key = f"{identifier}:{ticket_suffix}" if ticket_suffix else identifier
        ticket_id = f"{VENDOR_NAME}:{ticket_key}"
        display_name = case_display_name(record, entity_type)
        grouping_id = str(
            meta.get("grouping_id")
            or (
                alert_grouping_id(identifier)
                if entity_type == ENTITY_TYPE_ALERT
                else f"{VENDOR_NAME}:incident:{identifier}"
            )
        )
        case_title = str(meta.get("case_title") or display_name)
        # Name is what the analyst sees on the alert tab. Related alerts must
        # keep "Vega Alert - <id> - <name>", not the incident case title.
        # Rule Generator stays the case title so Case Name = Rule Generator
        # names the case after the Vega incident.
        alert_name = display_name
        rule_generator = case_title if meta.get("is_incident_case") else display_name
        alert = AlertInfo()
        alert.display_id = ticket_id
        alert.ticket_id = ticket_id
        alert.rule_generator = rule_generator
        alert.device_event_class_id = ticket_key
        alert.name = alert_name
        alert.device_vendor = VENDOR_NAME
        # Product must be the stable value "Vega" so an Alerts Grouping rule
        # (Product = Vega → Source Grouping Identifier) can match. Case title
        # stays on rule_generator; each alert keeps its own name.
        alert.device_product = DEVICE_PRODUCT
        alert.source_grouping_identifier = grouping_id
        alert.environment = environment
        alert.description = str(
            record.get("description")
            or record.get("incidentSummary")
            or record.get("incidentFindings")
            or alert.name
        )
        alert.start_time = start_time
        alert.end_time = end_time
        alert.Severity = severity
        alert.priority = alert_priority(severity)
        incident_id = str(meta.get("incident_id") or "").strip()
        alert.extensions = {
            "vega_entity_type": entity_type,
            "vega_id": identifier,
            "vega_incident_id": incident_id,
            "source_grouping_identifier": grouping_id,
        }
        parent_event = build_event_dict(record, entity_type, start_time, end_time)
        if meta.get("is_related_batch"):
            _pin_related_event(parent_event, start_time, end_time)
        alert.events.append(parent_event)
        if entity_type == ENTITY_TYPE_ALERT:
            _attach_child_events(
                alert,
                record,
                start_time,
                end_time,
                logger_instance,
                pin_to_parent=bool(meta.get("is_related_batch")),
            )
        # Do not set AlertInfo.case_tags here. SecOps treats each ingest
        # write plus playbook add_tag as a new catalog tag, which duplicates
        # names. Events still carry labels for Apply Vega Labels as Tags.
        packages.append(alert)
        safe_log(
            logger_instance,
            "info",
            "Packaged Vega %s %s with %s event(s) (grouping=%s title=%s).",
            entity_type,
            identifier,
            len(alert.events),
            grouping_id,
            alert_name,
        )
    return packages
