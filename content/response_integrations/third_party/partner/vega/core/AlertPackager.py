"""Build SOAR AlertInfo packages from Vega alerts and incidents."""
from __future__ import annotations

from .constants import ENTITY_TYPE_ALERT, VENDOR_NAME
from .mapping import (
    alert_priority,
    build_event_dict,
    build_vega_alert_event_dict,
    case_display_name,
    record_id,
    record_severity,
)
from .utils import parse_iso_timestamp, safe_log


def _unix_ms(record: dict, fallback: int) -> int:
    if not isinstance(record, dict):
        return fallback
    for key in ("updatedAt", "lastUpdated", "createdAt", "timestamp", "eventTime", "time"):
        parsed = parse_iso_timestamp(str(record.get(key) or ""))
        if parsed is not None:
            return int(parsed.timestamp() * 1000)
    return fallback


def create_alerts(records: list[tuple[str, dict]], siemplify, logger_instance=None) -> list:
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
        event_time = _unix_ms(record, current_time)
        severity = record_severity(record)
        ticket_id = f"{VENDOR_NAME}:{identifier}"
        display_name = case_display_name(record, entity_type)
        alert = AlertInfo()
        alert.display_id = ticket_id
        alert.ticket_id = ticket_id
        # Case Name settings typically use Rule Generator and/or Device Product,
        # not only alert.name. Keep all three aligned so the case title is
        # "Vega Alert - <name>" / "Vega Incident - <name>".
        alert.rule_generator = display_name
        alert.device_event_class_id = identifier
        alert.name = display_name
        alert.device_vendor = VENDOR_NAME
        alert.device_product = display_name
        alert.environment = environment
        alert.description = str(
            record.get("description")
            or record.get("incidentSummary")
            or record.get("incidentFindings")
            or alert.name
        )
        alert.start_time = event_time
        alert.end_time = event_time
        alert.Severity = severity
        alert.priority = alert_priority(severity)
        alert.events.append(
            build_event_dict(record, entity_type, event_time, event_time)
        )
        if entity_type == ENTITY_TYPE_ALERT:
            for index, vega_event in enumerate(record.get("alert_events") or []):
                child_time = _unix_ms(vega_event, event_time) if isinstance(vega_event, dict) else event_time
                alert.events.append(
                    build_vega_alert_event_dict(
                        record, vega_event, child_time, child_time, index
                    )
                )
        packages.append(alert)
        safe_log(
            logger_instance,
            "info",
            "Packaged Vega %s %s.",
            entity_type,
            identifier,
        )
    return packages
