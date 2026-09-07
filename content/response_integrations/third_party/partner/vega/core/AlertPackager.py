"""Build SOAR AlertInfo packages from Vega alerts and incidents."""
from __future__ import annotations

from .constants import (
    DEVICE_PRODUCT,
    ENTITY_TYPE_ALERT,
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


_TIME_KEYS = (
    "updatedAt",
    "lastUpdated",
    "createdAt",
    "timestamp",
    "eventTime",
    "event_time",
    "origin_time",
    "occurredAt",
    "occurred_at",
    "datetime",
    "_time",
    "time",
    "Time",
)
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


def _unix_ms(record: dict, fallback: int) -> int:
    if not isinstance(record, dict):
        return fallback
    for key in _TIME_KEYS:
        coerced = _coerce_unix_ms(record.get(key))
        if coerced is not None:
            return coerced
    fields = record.get("fields")
    if isinstance(fields, dict):
        for key in _TIME_KEYS:
            coerced = _coerce_unix_ms(fields.get(key))
            if coerced is not None:
                return coerced
    return fallback


def _attach_child_events(alert, record: dict, event_time: int, logger_instance=None) -> None:
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
        child_time = _unix_ms(
            normalize_alert_event(payload) if payload else {},
            event_time,
        )
        alert.events.append(
            build_vega_alert_event_dict(
                record, vega_event, child_time, child_time, index
            )
        )


def create_alerts(records: list[tuple[str, dict]], siemplify, logger_instance=None) -> list:
    """Turn pipeline records into SOAR AlertInfo packages.

    Incident case: one AlertInfo for the Vega incident plus one AlertInfo per
    related Vega alert. Each alert keeps its own Name (Vega Incident vs Vega
    Alert). They share Product, grouping id, grouping time, and Rule Generator
    (the incident case title) so SOAR can group them when a Product=Vega rule
    uses Source Grouping Identifier. Standalone Vega alerts keep their own
    title and grouping id.
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
        record_time = _unix_ms(record, current_time)
        grouping_time = _unix_ms(
            {"createdAt": meta.get("grouping_time")}, record_time
        )
        alert_time = grouping_time if meta.get("is_incident_case") else record_time
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
        alert.start_time = alert_time
        alert.end_time = alert_time
        alert.Severity = severity
        alert.priority = alert_priority(severity)
        case_tags = [str(tag).strip() for tag in (meta.get("case_tags") or []) if str(tag).strip()]
        if case_tags:
            alert.case_tags = case_tags
        incident_id = str(meta.get("incident_id") or "").strip()
        alert.extensions = {
            "vega_entity_type": entity_type,
            "vega_incident_id": incident_id,
            "source_grouping_identifier": grouping_id,
        }
        alert.events.append(
            build_event_dict(record, entity_type, record_time, record_time)
        )
        if entity_type == ENTITY_TYPE_ALERT:
            _attach_child_events(alert, record, record_time, logger_instance)
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
