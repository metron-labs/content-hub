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
    SOAR_ALERT_TYPE_ALERT,
    SOAR_ALERT_TYPE_INCIDENT,
    SOAR_META_KEY,
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
    "time",
    "Time",
    "_time",
    "timestamp",
    "eventTime",
    "event_time",
    "datetime",
    "date",
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


def soar_meta(record: dict) -> dict:
    meta = record.get(SOAR_META_KEY) if isinstance(record, dict) else None
    return dict(meta) if isinstance(meta, dict) else {}


def set_soar_meta(record: dict, **fields: Any) -> dict:
    updated = dict(record or {})
    meta = soar_meta(updated)
    meta.update({key: value for key, value in fields.items() if value is not None})
    updated[SOAR_META_KEY] = meta
    return updated


def record_id(record: dict, entity_type: str) -> str:
    if entity_type == ENTITY_TYPE_INCIDENT:
        return str(
            record.get("id")
            or record.get("incidentId")
            or ""
        ).strip()
    return str(
        record.get("id")
        or record.get("vegaAlertId")
        or record.get("alertId")
        or ""
    ).strip()


def record_alert_ids(record: dict) -> list[str]:
    """IDs to try with getAlertsEvents: UUID first, then human vegaAlertId."""
    ids: list[str] = []
    for key in ("id", "vegaAlertId", "alertId"):
        value = str(record.get(key) or "").strip()
        if value and value not in ids:
            ids.append(value)
    return ids


def record_display_id(record: dict, entity_type: str) -> str:
    """Human-facing Vega ID used in the SOAR alert/case title.

    Vega Alert names use vegaAlertId only (never the UUID id/alertId).
    """
    if entity_type == ENTITY_TYPE_INCIDENT:
        return str(
            record.get("vegaUniqueIncidentId")
            or record.get("incidentId")
            or ""
        ).strip()
    return str(record.get("vegaAlertId") or "").strip()


def record_name(record: dict) -> str:
    return str(record.get("name") or record.get("incidentName") or "Vega record").strip()

def case_display_name(record: dict, entity_type: str) -> str:
    """Human-readable SOAR alert/case title: Vega {entity} - {display_id} - {name}.

    Alert Type in SOAR search is rule_generator. For incident-case members the
    packager sets Rule Generator to the incident case title and Name to this
    per-record title (Vega Incident vs Vega Alert).
    """
    display_id = record_display_id(record, entity_type)
    name = record_name(record)
    if display_id:
        return f"Vega {entity_type} - {display_id} - {name} TEST 28"
    return f"Vega {entity_type} - {name} TEST 28"


def incident_case_title(record: dict, case_part: int = 1) -> str:
    """Shared SOAR case title for an incident and its nested related alerts."""
    title = case_display_name(record, ENTITY_TYPE_INCIDENT)
    if case_part and case_part > 1:
        return f"{title} (part {case_part})"
    return title


def incident_grouping_id(incident_id: str, case_part: int = 1) -> str:
    """SOAR source grouping key. Overflow cases use :part:N so they stay separate."""
    base = f"{VENDOR_NAME}:incident:{incident_id}"
    if case_part and case_part > 1:
        return f"{base}:part:{case_part}"
    return base


def alert_grouping_id(alert_id: str) -> str:
    return f"{VENDOR_NAME}:alert:{alert_id}"


def record_label_tags(record: dict) -> list[str]:
    """SOAR case tags from Vega incident labels. Reuses existing tag names."""
    tags: list[str] = []
    seen: set[str] = set()
    labels = record.get("labels") if isinstance(record, dict) else None
    if isinstance(labels, str) and labels.strip():
        labels = [labels]
    if not isinstance(labels, list):
        return tags
    for item in labels:
        name = ""
        if isinstance(item, str):
            name = item.strip()
        elif isinstance(item, dict):
            name = str(item.get("name") or item.get("label") or "").strip()
        if not name:
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        tags.append(name)
    return tags


def incident_alert_stubs(incident: dict) -> list[dict]:
    raw = incident.get("alerts") if isinstance(incident, dict) else None
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    stubs: list[dict] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            stubs.append({"alertId": item.strip(), "id": item.strip()})
        elif isinstance(item, dict):
            stubs.append(item)
    return stubs


def incident_alert_ids(incident: dict) -> list[str]:
    """Unique alert IDs from getIncidents `alerts { alertId name createdAt }`."""
    ids: list[str] = []
    seen: set[str] = set()
    for stub in incident_alert_stubs(incident):
        for key in record_alert_ids(stub):
            if key not in seen:
                seen.add(key)
                ids.append(key)
    return ids


def chunk_case_alerts(related_alerts: list, max_alerts_per_case: int) -> list[list]:
    """Split related alerts so each SOAR case stays within the 90-alert cap.

    First case reserves 1 slot for the Vega incident alert, so it holds
    (max - 1) related alerts. Overflow cases are related alerts only and
    hold `max` alerts each. Zero related alerts still yields one empty
    chunk (incident-only case).
    """
    limit = max(1, int(max_alerts_per_case))
    first_cap = max(1, limit - 1)
    if not related_alerts:
        return [[]]
    first = list(related_alerts[:first_cap])
    rest = list(related_alerts[first_cap:])
    chunks = [first]
    for index in range(0, len(rest), limit):
        chunks.append(list(rest[index : index + limit]))
    return chunks


def stub_to_alert(stub: dict) -> dict:
    alert_id = str(
        stub.get("alertId") or stub.get("id") or stub.get("vegaAlertId") or ""
    ).strip()
    return {
        "id": alert_id,
        "alertId": alert_id,
        "vegaAlertId": str(stub.get("vegaAlertId") or "").strip(),
        "name": stub.get("name") or "Vega alert",
        "createdAt": stub.get("createdAt") or "",
        "updatedAt": stub.get("updatedAt") or stub.get("createdAt") or "",
        "severity": stub.get("severity") or "MEDIUM",
        "status": stub.get("status") or "",
        "description": stub.get("description") or "",
    }


def related_incident_ref(alert: dict) -> tuple[str, str]:
    related = alert.get("relatedIncidents") if isinstance(alert, dict) else None
    if isinstance(related, dict):
        related = [related]
    if not isinstance(related, list):
        return "", ""
    for item in related:
        if not isinstance(item, dict):
            continue
        identifier = str(item.get("incidentId") or item.get("id") or "").strip()
        if identifier:
            return identifier, str(item.get("name") or "").strip()
    return "", ""


def index_alert_records(alerts: list[dict]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        for key in record_alert_ids(alert):
            index[key] = alert
    return index


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
    trimmed = {
        key: value
        for key, value in record.items()
        if key not in (SOAR_META_KEY, "alert_events", "nested_related_alerts")
    }
    return _soar_value(trimmed, limit=_MAX_DETAILS_CHARS)


def build_event_dict(record: dict, entity_type: str, start_time: int, end_time: int) -> dict:
    identifier = record_id(record, entity_type)
    severity = record_severity(record)
    meta = soar_meta(record)
    incident_id = str(
        meta.get("incident_id")
        or record.get("vega_incident_id")
        or ""
    ).strip()
    incident_display_id = str(
        meta.get("incident_display_id")
        or record.get("vegaUniqueIncidentId")
        or ""
    ).strip()
    soar_alert_type = str(
        meta.get("soar_alert_type")
        or (
            SOAR_ALERT_TYPE_INCIDENT
            if entity_type == ENTITY_TYPE_INCIDENT
            else SOAR_ALERT_TYPE_ALERT
        )
    )
    grouping_id = str(meta.get("grouping_id") or "")
    event = {
        "StartTime": start_time,
        "EndTime": end_time,
        "start_time": start_time,
        "end_time": end_time,
        "name": case_display_name(record, entity_type),
        "device_vendor": VENDOR_NAME,
        "device_product": DEVICE_PRODUCT,
        "product": DEVICE_PRODUCT,
        "source_grouping_identifier": grouping_id,
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
        "vega_soar_alert_type": soar_alert_type,
        "vega_alert_id": str(record.get("vegaAlertId") or ""),
        "vega_incident_id": incident_id,
        "vega_unique_incident_id": incident_display_id,
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
    meta = soar_meta(parent)
    incident_id = str(meta.get("incident_id") or parent.get("vega_incident_id") or "").strip()
    grouping_id = str(meta.get("grouping_id") or "")
    event = {
        "StartTime": start_time,
        "EndTime": end_time,
        "start_time": start_time,
        "end_time": end_time,
        "name": name,
        "device_vendor": VENDOR_NAME,
        "device_product": DEVICE_PRODUCT,
        "product": DEVICE_PRODUCT,
        "source_grouping_identifier": grouping_id,
        "event_type": "Alert Event",
        "product_log_id": event_key,
        "vega_id": identifier,
        "vega_alert_id": str(parent.get("vegaAlertId") or ""),
        "vega_incident_id": incident_id,
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
