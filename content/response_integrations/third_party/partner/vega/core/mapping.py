"""Map Vega alert/incident records to SOAR event dictionaries."""
from __future__ import annotations

import json
import re
from typing import Any

from .constants import (
    DEVICE_PRODUCT,
    ENTITY_TYPE_ALERT,
    ENTITY_TYPE_INCIDENT,
    SEVERITY_TO_ALERT_PRIORITY,
    VENDOR_NAME,
)

_SAFE_KEY_RE = re.compile(r"[^A-Za-z0-9_]")
_MAX_EVENT_FIELD_CHARS = 10000
_MAX_DETAILS_CHARS = 100000
_MAX_EXTRA_FIELDS = 80
_SKIP_PAYLOAD_KEYS = {
    "fields",
    "_raw",
    "raw",
    "details",
    "StartTime",
    "EndTime",
    "name",
    "device_vendor",
    "device_product",
    "product",
    "event_type",
    "product_log_id",
    "vega_id",
    "event_class_id",
    "DeviceEventClassID",
    "Severity",
}
_ENTITY_ALIASES = {
    "src_ip": "ip",
    "srcip": "ip",
    "source_ip": "ip",
    "sourceip": "ip",
    "dest_ip": "ip",
    "dst_ip": "ip",
    "dstip": "ip",
    "destination_ip": "ip",
    "client_ip": "ip",
    "ip_address": "ip",
    "src_host": "hostname",
    "dest_host": "hostname",
    "computer": "hostname",
    "computer_name": "hostname",
    "src_user": "user",
    "dest_user": "user",
    "user_name": "user",
    "username": "user",
    "account": "user",
    "filehash": "hash",
    "file_hash": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "request_url": "url",
    "http_url": "url",
    "fqdn": "hostname",
    "domain_name": "domain",
}


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def record_id(record: dict, entity_type: str) -> str:
    if entity_type == ENTITY_TYPE_INCIDENT:
        return str(
            record.get("id")
            or record.get("incidentId")
            or ""
        ).strip()
    return str(record.get("id") or record.get("vegaAlertId") or "").strip()


def record_alert_ids(record: dict) -> list[str]:
    """IDs to try with getAlertsEvents: UUID first, then human vegaAlertId."""
    ids: list[str] = []
    for key in ("id", "vegaAlertId", "alertId"):
        value = str(record.get(key) or "").strip()
        if value and value not in ids:
            ids.append(value)
    return ids


def record_display_id(record: dict, entity_type: str) -> str:
    """Human-facing Vega ID used in the SOAR case title."""
    if entity_type == ENTITY_TYPE_INCIDENT:
        return str(
            record.get("vegaUniqueIncidentId")
            or record.get("id")
            or record.get("incidentId")
            or ""
        ).strip()
    return str(record.get("vegaAlertId") or record.get("id") or "").strip()


def record_name(record: dict) -> str:
    return str(record.get("name") or record.get("incidentName") or "Vega record").strip()

# TODO: Need to remove the manually change of the case display name
def case_display_name(record: dict, entity_type: str) -> str:
    """SOAR case title: Vega Alert - <vegaAlertId> - <name>."""
    display_id = record_display_id(record, entity_type)
    name = record_name(record)
    if display_id:
        return f"Vega {entity_type} - {display_id} - {name} - TEST-13"
    return f"Vega {entity_type} - {name} - TEST-13"


def record_severity(record: dict) -> str:
    raw = str(record.get("severity") or "MEDIUM").strip().upper()
    if raw not in SEVERITY_TO_ALERT_PRIORITY:
        return "MEDIUM"
    return raw


def record_timestamp(record: dict) -> str:
    return str(
        record.get("updatedAt")
        or record.get("lastUpdated")
        or record.get("createdAt")
        or ""
    )


def _flatten_entities(record: dict) -> dict[str, str]:
    buckets = {
        "ip": [],
        "domain": [],
        "user": [],
        "hash": [],
        "url": [],
        "hostname": [],
    }
    type_map = {
        "ip": "ip",
        "ipv4": "ip",
        "ipv6": "ip",
        "domain": "domain",
        "user": "user",
        "username": "user",
        "email": "user",
        "hash": "hash",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "url": "url",
        "uri": "url",
        "hostname": "hostname",
        "host": "hostname",
        "fqdn": "hostname",
    }
    blobs: list = []
    for key in ("entities", "observables", "assets"):
        value = record.get(key)
        if value:
            blobs.append(value)
    for blob in blobs:
        items = blob if isinstance(blob, list) else [blob]
        for item in items:
            if isinstance(item, str):
                continue
            if not isinstance(item, dict):
                continue
            kind = str(item.get("type") or item.get("category") or "").strip().lower()
            value = item.get("value") or item.get("name")
            bucket = type_map.get(kind)
            if bucket and value:
                text = str(value).strip()
                if text and text not in buckets[bucket]:
                    buckets[bucket].append(text)
    return {key: ",".join(values) for key, values in buckets.items() if values}


def _soar_key(key: Any) -> str:
    text = _SAFE_KEY_RE.sub("_", str(key or "").strip()).strip("_")
    if text and text[0].isdigit():
        text = f"f_{text}"
    return text[:80]


def _soar_value(value: Any, *, limit: int = _MAX_EVENT_FIELD_CHARS) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        text = _safe_json(value)
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _apply_entity_aliases(event: dict, payload: dict) -> None:
    for key, value in payload.items():
        bucket = _ENTITY_ALIASES.get(str(key).strip().lower())
        if not bucket or bucket in event or value in (None, ""):
            continue
        if isinstance(value, (dict, list)):
            continue
        event[bucket] = _soar_value(value)


def _details_payload(record: dict) -> str:
    """JSON snapshot of the Vega record without duplicating child events."""
    if not isinstance(record, dict):
        return _safe_json(record)
    trimmed = {key: value for key, value in record.items() if key != "alert_events"}
    return _soar_value(trimmed, limit=_MAX_DETAILS_CHARS)


def build_event_dict(record: dict, entity_type: str, start_time: int, end_time: int) -> dict:
    identifier = record_id(record, entity_type)
    severity = record_severity(record)
    event = {
        "StartTime": start_time,
        "EndTime": end_time,
        "name": case_display_name(record, entity_type),
        "device_vendor": VENDOR_NAME,
        "device_product": DEVICE_PRODUCT,
        "product": DEVICE_PRODUCT,
        "event_type": entity_type,
        "product_log_id": identifier,
        "vega_id": identifier,
        "event_class_id": identifier,
        "DeviceEventClassID": identifier,
        "Severity": severity,
        "status": str(record.get("status") or ""),
        "verdict": str(record.get("verdict") or ""),
        "verdict_reasoning": str(record.get("verdictReasoning") or ""),
        "description": str(record.get("description") or record.get("incidentSummary") or ""),
        "source_url": str(record.get("href") or record.get("link") or ""),
        "created_at": str(record.get("createdAt") or ""),
        "updated_at": record_timestamp(record),
        "vega_entity_type": entity_type,
        "vega_alert_id": str(record.get("vegaAlertId") or ""),
        "vega_unique_incident_id": str(record.get("vegaUniqueIncidentId") or ""),
        "vega_comments": _safe_json(record.get("comments") or []),
        "vega_recommended_actions": _safe_json(record.get("recommendedActions") or []),
        "vega_investigation_plan": _safe_json(record.get("investigationPlan") or []),
        "vega_labels": _safe_json(record.get("labels") or []),
        "vega_skills": _safe_json(record.get("skills") or []),
        "vega_timeline": _safe_json(record.get("timeline") or []),
        "vega_alert_events_count": str(len(record.get("alert_events") or [])),
        "vega_observables": _safe_json(record.get("observables") or []),
        "vega_assets": _safe_json(record.get("assets") or []),
        "vega_entities": _safe_json(record.get("entities") or []),
        "details": _details_payload(record),
    }
    event.update(_flatten_entities(record))
    return event


def _try_parse_json(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "{[":
        return value
    try:
        return json.loads(text)
    except Exception:
        return value


def normalize_alert_event(vega_event: Any) -> dict:
    """Parse getAlertsEvents rows, including JSON `fields` / `fields._raw` payloads."""
    payload = dict(vega_event) if isinstance(vega_event, dict) else {"value": vega_event}
    fields = _try_parse_json(payload.get("fields"))
    if not isinstance(fields, dict):
        return payload
    merged = dict(payload)
    raw = _try_parse_json(fields.get("_raw"))
    if isinstance(raw, dict):
        for key, value in raw.items():
            if key not in merged or merged[key] in (None, ""):
                merged[key] = value
    for key, value in fields.items():
        if key == "_raw":
            continue
        if key not in merged or merged[key] in (None, ""):
            merged[key] = value
    merged["fields"] = fields
    return merged


def build_vega_alert_event_dict(
    parent: dict,
    vega_event: Any,
    start_time: int,
    end_time: int,
    index: int,
) -> dict:
    """Map one Vega getAlertsEvents result onto a SOAR event for a Vega Alert case.

    Child events must use a unique product_log_id and only string field values.
    Shared IDs or nested/Splunk-style keys cause SecOps to drop them from the case.
    """
    identifier = record_id(parent, ENTITY_TYPE_ALERT)
    payload = normalize_alert_event(vega_event)
    event_key = f"{identifier}:event:{index}"
    name = str(
        payload.get("name")
        or payload.get("summary")
        or payload.get("message")
        or payload.get("eventName")
        or payload.get("event_name")
        or payload.get("sourcetype")
        or f"Vega Alert Event {index + 1}"
    ).strip()
    event = {
        "StartTime": start_time,
        "EndTime": end_time,
        "name": name,
        "device_vendor": VENDOR_NAME,
        "device_product": DEVICE_PRODUCT,
        "product": DEVICE_PRODUCT,
        "event_type": "Alert Event",
        "product_log_id": event_key,
        "vega_id": identifier,
        "vega_alert_id": str(parent.get("vegaAlertId") or ""),
        "event_class_id": event_key,
        "DeviceEventClassID": event_key,
        "Severity": record_severity(parent),
        "vega_entity_type": "Alert Event",
        "details": _soar_value(payload, limit=_MAX_DETAILS_CHARS),
    }
    extra = 0
    for key, value in payload.items():
        if extra >= _MAX_EXTRA_FIELDS or value in (None, ""):
            continue
        if str(key) in _SKIP_PAYLOAD_KEYS:
            continue
        safe_key = _soar_key(key)
        if not safe_key or safe_key in event:
            continue
        event[safe_key] = _soar_value(value)
        extra += 1
    event.update(_flatten_entities(payload))
    _apply_entity_aliases(event, payload)
    return event


def alert_priority(severity: str) -> int:
    return SEVERITY_TO_ALERT_PRIORITY.get(str(severity).upper(), 60)
