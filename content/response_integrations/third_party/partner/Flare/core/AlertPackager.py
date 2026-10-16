"""Build SOAR AlertInfo packages from Flare findings."""
from __future__ import annotations

import datetime
import json
import uuid
from typing import Any

from soar_sdk.SiemplifyUtils import unix_now

from .constants import (
    DEVICE_PRODUCT,
    PRODUCT_NAME,
    SEVERITY_TO_ALERT_PRIORITY,
    TYPE_DISPLAY_NAME,
    VENDOR_NAME,
)
from .utils import flare_url_for_uid, safe_log


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _metadata(event: dict) -> dict:
    return _as_dict(event.get("metadata"))


def _data(event: dict) -> dict:
    return _as_dict(event.get("data"))


def _severity(event: dict) -> str:
    meta = _metadata(event)
    tenant = _as_dict(meta.get("tenant"))
    data = _data(event)
    raw = (
        tenant.get("severity")
        or data.get("severity")
        or meta.get("severity")
        or "info"
    )
    return str(raw).strip().lower() or "info"


def _source_type(event: dict) -> str:
    meta = _metadata(event)
    data = _data(event)
    return str(
        meta.get("type")
        or data.get("type")
        or event.get("event_type")
        or "unknown"
    ).strip() or "unknown"


def _uid(event: dict) -> str:
    return str(_metadata(event).get("uid") or event.get("uid") or "").strip()


def _title(event: dict) -> str:
    meta = _metadata(event)
    data = _data(event)
    for candidate in (
        meta.get("title"),
        data.get("title"),
        data.get("name"),
        meta.get("name"),
    ):
        if candidate:
            return str(candidate).strip()
    source_type = _source_type(event)
    return TYPE_DISPLAY_NAME.get(source_type, "Flare Threat Exposure Finding")


def _flare_url(event: dict) -> str:
    meta = _metadata(event)
    url = meta.get("flare_url")
    if url:
        return str(url)
    return flare_url_for_uid(_uid(event))


def _timestamp(event: dict) -> str:
    meta = _metadata(event)
    return str(
        meta.get("matched_at")
        or meta.get("estimated_created_at")
        or meta.get("created_at")
        or ""
    )


def _unix_timestamp(event: dict, fallback_time: int) -> int:
    """Parse the event timestamp into a UNIX timestamp in milliseconds."""
    ts_str = _timestamp(event)
    if not ts_str:
        return fallback_time
    try:
        ts_str = ts_str.replace("Z", "+00:00")
        if "." in ts_str:
            dt = datetime.datetime.fromisoformat(ts_str)
        else:
            dt = datetime.datetime.fromisoformat(ts_str)
        return int(dt.timestamp() * 1000)
    except Exception:
        try:
            clean_str = ts_str.split("+")[0].replace("Z", "")
            if "." in clean_str:
                dt = datetime.datetime.strptime(clean_str, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                dt = datetime.datetime.strptime(clean_str, "%Y-%m-%dT%H:%M:%S")
            return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
        except Exception:
            return fallback_time


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def build_event_dict(event: dict, start_time: int, end_time: int) -> dict:
    """Flat SOAR event payload for AlertInfo.events."""
    meta = _metadata(event)
    uid = _uid(event)
    source_type = _source_type(event)
    severity = _severity(event)
    return {
        "StartTime": start_time,
        "EndTime": end_time,
        "name": _title(event),
        "device_vendor": VENDOR_NAME,
        "device_product": DEVICE_PRODUCT,
        # product_log_id / event_class_id: CaseFullDetails exposes the Flare
        # uid on security_events.event_class_id after ingestion.
        "product_log_id": uid,
        "flare_uid": uid,
        "event_class_id": uid,
        "DeviceEventClassID": uid,
        "Severity": severity,
        "source_type": source_type,
        "source_type_display": TYPE_DISPLAY_NAME.get(
            source_type, source_type.replace("_", " ").title()
        ),
        "flare_url": _flare_url(event),
        "estimated_created_at": _timestamp(event),
        "tenant_id": str(meta.get("tenant_id") or ""),
        "details": _safe_json(event),
    }


def create_alerts(
    events: list,
    siemplify,
    tenant_id: int,
    logger_instance=None,
) -> list:
    """Build one AlertInfo per Flare finding, with exactly one event.

    Case grouping is left to the connector's Alert Grouping rule in Google
    SecOps, which runs after return_package().
    """
    # Import here so managers stay importable outside the SecOps runtime.
    from soar_sdk.SiemplifyConnectorsDataModel import AlertInfo

    if not events:
        return []

    alerts = []
    current_time = unix_now()
    tenant_key = str(tenant_id or "flare")
    safe_log(
        logger_instance,
        "info",
        "Packaging %d Flare finding(s) for tenant_id=%s into individual alerts.",
        len(events),
        tenant_key,
    )

    for event in events:
        source_type = _source_type(event)
        display_type = TYPE_DISPLAY_NAME.get(
            source_type, source_type.replace("_", " ").title()
        )
        finding_key = _uid(event) or str(uuid.uuid4())
        alert_id = f"{tenant_key}:{finding_key}"
        severity = _severity(event)
        event_time = _unix_timestamp(event, current_time)

        alert = AlertInfo()
        alert.display_id = f"{VENDOR_NAME}:{finding_key}"
        alert.ticket_id = alert_id
        # Stable rule_generator so closed-case ticket lookup finds Flare alerts.
        alert.rule_generator = VENDOR_NAME
        alert.device_event_class_id = alert_id
        alert.name = _title(event)
        alert.source_grouping_identifier = source_type
        alert.sourceGroupIdentifier = source_type
        alert.start_time = event_time
        alert.end_time = event_time
        alert.priority = SEVERITY_TO_ALERT_PRIORITY.get(severity, 40)
        alert.device_vendor = VENDOR_NAME
        alert.device_product = PRODUCT_NAME
        alert.environment = siemplify.context.connector_info.environment
        alert.description = (
            f"1 Flare threat exposure finding of type {source_type}."
        )
        alert.case_tags = [VENDOR_NAME, source_type, display_type]
        alert.events = [build_event_dict(event, event_time, event_time)]
        alert.extensions = {
            "SourceType": source_type,
            "SourceTypeDisplay": display_type,
            "FindingCount": 1,
            "TenantId": tenant_key,
            "FlareUid": finding_key,
            "CaseId": alert_id,
        }
        alerts.append(alert)

    return alerts
