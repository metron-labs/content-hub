"""Map Vega alert/incident records to SOAR event dictionaries."""
from __future__ import annotations

import json
from typing import Any

from .constants import (
    DEVICE_PRODUCT,
    ENTITY_TYPE_ALERT,
    ENTITY_TYPE_INCIDENT,
    SEVERITY_TO_ALERT_PRIORITY,
    VENDOR_NAME,
)


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


def case_display_name(record: dict, entity_type: str) -> str:
    """SOAR case title: Vega Alert - <vegaAlertId> - <name>."""
    display_id = record_display_id(record, entity_type)
    name = record_name(record)
    if display_id:
        return f"Vega {entity_type} - {display_id} - {name}"
    return f"Vega {entity_type} - {name}"


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
        "vega_alert_events": _safe_json(record.get("alert_events") or []),
        "vega_observables": _safe_json(record.get("observables") or []),
        "vega_assets": _safe_json(record.get("assets") or []),
        "vega_entities": _safe_json(record.get("entities") or []),
        "details": _safe_json(record),
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
    """Map one Vega getAlertsEvents result onto a SOAR event for a Vega Alert case."""
    identifier = record_id(parent, ENTITY_TYPE_ALERT)
    payload = normalize_alert_event(vega_event)
    name = str(
        payload.get("name")
        or payload.get("summary")
        or payload.get("message")
        or payload.get("eventName")
        or payload.get("event_name")
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
        "product_log_id": identifier,
        "vega_id": identifier,
        "event_class_id": f"{identifier}:event:{index}",
        "DeviceEventClassID": f"{identifier}:event:{index}",
        "Severity": record_severity(parent),
        "vega_entity_type": ENTITY_TYPE_ALERT,
        "details": _safe_json(payload),
    }
    for key, value in payload.items():
        if key in event or value in (None, ""):
            continue
        event[str(key)] = value if not isinstance(value, (dict, list)) else _safe_json(value)
    event.update(_flatten_entities(payload))
    return event


def alert_priority(severity: str) -> int:
    return SEVERITY_TO_ALERT_PRIORITY.get(str(severity).upper(), 60)
