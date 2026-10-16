"""Build SOAR AlertInfo packages from Flare findings."""
from __future__ import annotations

import datetime
import json
import uuid
from typing import Any

from SiemplifyUtils import unix_now

from constants import (
    DEVICE_PRODUCT,
    MAX_EVENTS_PER_ALERT,
    PRODUCT_NAME,
    SEVERITY_TO_ALERT_PRIORITY,
    TYPE_DISPLAY_NAME,
    VENDOR_NAME,
)
from utils import flare_url_for_uid, safe_log


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
    """
    Group Flare findings by source type, build AlertInfo objects, batch at
    MAX_EVENTS_PER_ALERT.
    """
    # Import here so managers stay importable outside the SecOps runtime.
    from SiemplifyConnectorsDataModel import AlertInfo

    if not events:
        return []

    log = logger_instance
    groups: dict[str, list] = {}
    for event in events:
        source_type = _source_type(event)
        groups.setdefault(source_type, []).append(event)

    alerts = []
    current_time = unix_now()
    tenant_key = str(tenant_id or "flare")
    safe_log(
        log,
        "info",
        "Packaging %d Flare finding(s) for tenant_id=%s into alert groups.",
        len(events),
        tenant_key,
    )

    for source_type, group_events in groups.items():
        display_type = TYPE_DISPLAY_NAME.get(
            source_type, source_type.replace("_", " ").title()
        )
        total = len(group_events)
        num_batches = (total + MAX_EVENTS_PER_ALERT - 1) // MAX_EVENTS_PER_ALERT

        for batch_num in range(num_batches):
            start_idx = batch_num * MAX_EVENTS_PER_ALERT
            end_idx = min((batch_num + 1) * MAX_EVENTS_PER_ALERT, total)
            batch = group_events[start_idx:end_idx]

            # Unique ticket_id per alert package so SOAR does not merge every
            # "listing"/"paste"/… run into one mega-case. Closing a case must
            # only remediate events that belong to that case.
            alert_key = f"{tenant_key}:{source_type}"
            ticket_id = f"{VENDOR_NAME}:{uuid.uuid4()}"
            alert = AlertInfo()
            alert.display_id = ticket_id
            alert.ticket_id = ticket_id
            # Stable rule_generator so closed-case ticket lookup finds Flare alerts.
            alert.rule_generator = VENDOR_NAME
            alert.device_event_class_id = alert_key
            alert.name = (
                f"{display_type}"
                if num_batches == 1
                else f"{display_type} (Part {batch_num + 1}/{num_batches})"
            )
            alert.sourceGroupIdentifier = source_type
            alert.device_vendor = VENDOR_NAME
            alert.device_product = PRODUCT_NAME
            alert.environment = siemplify.context.connector_info.environment
            alert.description = (
                f"{len(batch)} Flare threat exposure finding(s) of type {source_type}."
            )
            alert.case_tags = [VENDOR_NAME, source_type, display_type]
            if num_batches > 1:
                alert.case_tags.append(f"Batch {batch_num + 1}/{num_batches}")

            highest = "info"
            batch_start_time = None
            batch_end_time = None
            batch_uids = []
            for item in batch:
                severity = _severity(item)
                highest_priority = SEVERITY_TO_ALERT_PRIORITY.get(highest, 0)
                item_priority = SEVERITY_TO_ALERT_PRIORITY.get(severity, 0)
                if item_priority >= highest_priority:
                    highest = severity
                
                event_time = _unix_timestamp(item, current_time)
                if batch_start_time is None or event_time < batch_start_time:
                    batch_start_time = event_time
                if batch_end_time is None or event_time > batch_end_time:
                    batch_end_time = event_time

                uid = _uid(item)
                if uid:
                    batch_uids.append(uid)

                alert.events.append(
                    build_event_dict(item, event_time, event_time)
                )

            alert.start_time = batch_start_time or current_time
            alert.end_time = batch_end_time or current_time
            alert.Severity = highest
            alert.priority = SEVERITY_TO_ALERT_PRIORITY.get(highest, 40)
            alert.extensions = {
                "SourceType": source_type,
                "SourceTypeDisplay": display_type,
                "FindingCount": len(batch),
                "TotalFindingCount": total,
                "TenantId": tenant_key,
                "CaseId": alert_key,
                "flare_uids": ",".join(batch_uids),
            }
            if num_batches > 1:
                alert.extensions["BatchNumber"] = batch_num + 1
                alert.extensions["TotalBatches"] = num_batches

            alerts.append(alert)

    return alerts
