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
_GRAPHQL_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
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
    "labels",
    "vega_label_names",
    "vega_labels",
    "vega_incident_label_names",
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


def is_graphql_alert_id(value: str) -> bool:
    """True for UUID alertIds safe in getAlerts(alertIds: [ID!])."""
    return bool(_GRAPHQL_ID_RE.match(str(value or "").strip()))


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
        return f"Vega {entity_type} - {display_id} - {name} TEST 70"
    return f"Vega {entity_type} - {name} TEST 70"


def incident_case_title(record: dict, related_batch: int = 0) -> str:
    """SOAR case title for an incident-only case or a related-alert batch.

    related_batch 0 is the Vega incident case. related_batch >= 1 is a
    related-alert case named after the incident with ``(batch N)``.
    """
    title = case_display_name(record, ENTITY_TYPE_INCIDENT)
    if related_batch and related_batch > 0:
        return f"{title} (batch {related_batch})"
    return title


def incident_grouping_id(incident_id: str, related_batch: int = 0) -> str:
    """SOAR source grouping key. Incident and related-alert batches stay separate.

    related_batch 0 is ``Vega:incident:<id>``. related_batch >= 1 is
    ``Vega:incident:<id>:batch:N`` so the grouping rule does not merge them.
    """
    base = f"{VENDOR_NAME}:incident:{incident_id}"
    if related_batch and related_batch > 0:
        return f"{base}:batch:{related_batch}"
    return base


def alert_grouping_id(alert_id: str) -> str:
    return f"{VENDOR_NAME}:alert:{alert_id}"


def _label_items(value: Any) -> list:
    labels = value
    if isinstance(labels, str) and labels.strip():
        parsed = _try_parse_json(labels)
        labels = parsed if parsed is not labels else [labels]
    if isinstance(labels, dict):
        labels = (
            labels.get("items")
            or labels.get("nodes")
            or labels.get("labels")
            or list(labels.values())
        )
    if not isinstance(labels, list):
        return []
    return labels


def _display_labels(value: Any) -> list[dict]:
    """Keep only Vega label name and color on SOAR events."""
    displayed: list[dict] = []
    for item in _label_items(value):
        if isinstance(item, str):
            name = item.strip()
            if name:
                displayed.append({"name": name})
            continue
        if not isinstance(item, dict):
            continue
        name = str(
            item.get("name")
            or item.get("label")
            or item.get("labelName")
            or item.get("displayName")
            or ""
        ).strip()
        color = str(item.get("color") or "").strip()
        if not name and not color:
            continue
        entry: dict[str, str] = {}
        if name:
            entry["name"] = name
        if color:
            entry["color"] = color
        displayed.append(entry)
    return displayed


def record_label_tags(record: dict) -> list[str]:
    """SOAR case tags from Vega incident or alert `labels` names.

    SecOps creates a tag on first use when AlertInfo.case_tags is set, so
    names do not need to exist in Settings first. Names shorter than 2
    characters are skipped (SOAR rejects them).
    """
    tags: list[str] = []
    seen: set[str] = set()
    labels = record.get("labels") if isinstance(record, dict) else None
    for item in _label_items(labels):
        name = ""
        if isinstance(item, str):
            name = item.strip()
        elif isinstance(item, dict):
            name = str(
                item.get("name")
                or item.get("label")
                or item.get("labelName")
                or item.get("displayName")
                or ""
            ).strip()
        if len(name) < 2:
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        tags.append(name)
    return tags


def collect_label_tags(*records: dict) -> list[str]:
    """Unique case tags from an incident and every related alert in the case."""
    tags: list[str] = []
    seen: set[str] = set()
    for record in records:
        for name in record_label_tags(record or {}):
            key = name.casefold()
            if key in seen:
                continue
            seen.add(key)
            tags.append(name)
    return tags


_LABEL_TAG_KEYS = (
    "labels",
    "vega_label_names",
    "vega_labels",
    "vega_incident_label_names",
)


def flatten_event_for_tags(event: Any) -> dict:
    """SOAR events store Vega fields on the object, in additional_properties, or in details JSON."""
    payload: dict = {}
    if isinstance(event, dict):
        payload.update(event)
    elif event is not None:
        extra = getattr(event, "additional_properties", None)
        if isinstance(extra, dict):
            payload.update(extra)
        raw = getattr(event, "__dict__", None)
        if isinstance(raw, dict):
            for key, value in raw.items():
                if str(key).startswith("_"):
                    continue
                payload.setdefault(key, value)
        fields = getattr(event, "fields", None)
        if isinstance(fields, list):
            payload.setdefault("fields", fields)
    nested = payload.get("additional_properties") or payload.get("AdditionalProperties")
    merged: dict = {}
    if isinstance(nested, dict):
        merged.update(nested)
    for key, value in payload.items():
        if key in ("additional_properties", "AdditionalProperties"):
            continue
        merged[key] = value
    fields = merged.get("fields")
    if isinstance(fields, list):
        for item in fields:
            if not isinstance(item, dict):
                continue
            key = item.get("key") or item.get("name") or item.get("field")
            if key and "value" in item:
                merged.setdefault(str(key), item.get("value"))
    details = _try_parse_json(merged.get("details"))
    if isinstance(details, dict):
        for key in _LABEL_TAG_KEYS:
            if key in details and merged.get(key) in (None, "", [], {}):
                merged[key] = details.get(key)
    return merged


def tags_from_event_fields(event: Any) -> list[str]:
    """Vega label names stored on a SOAR event (JSON labels or comma-separated names)."""
    event = flatten_event_for_tags(event)
    blobs: list = []
    for key in _LABEL_TAG_KEYS:
        value = event.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str):
            parsed = _try_parse_json(value)
            blobs.append(
                parsed
                if parsed is not value
                else [part.strip() for part in value.split(",") if part.strip()]
            )
        else:
            blobs.append(value)
    return collect_label_tags(*[{"labels": blob} for blob in blobs])


def pending_case_tags(names: list[str], existing: list[str] | set[str] | None = None) -> list[str]:
    """Drop blank, short, and already-assigned tag names (case-insensitive)."""
    seen = {
        str(name).strip().casefold()
        for name in (existing or [])
        if str(name).strip()
    }
    pending: list[str] = []
    for name in names or []:
        text = str(name).strip()
        key = text.casefold()
        if len(text) < 2 or key in seen:
            continue
        seen.add(key)
        pending.append(text)
    return pending


def tags_from_events(events: list) -> list[str]:
    return collect_label_tags(
        *[{"labels": tags_from_event_fields(event)} for event in (events or [])]
    )


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
    """Split related alerts into SOAR cases of at most ``max`` alerts each.

    The Vega incident is a separate case, so every chunk can hold the full
    cap (90). Zero related alerts yields no chunks.
    """
    limit = max(1, int(max_alerts_per_case))
    if not related_alerts:
        return []
    chunks: list[list] = []
    items = list(related_alerts)
    for index in range(0, len(items), limit):
        chunks.append(items[index : index + limit])
    return chunks


def stub_to_alert(stub: dict) -> dict:
    stub = stub if isinstance(stub, dict) else {}
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
        "labels": stub.get("labels") if stub.get("labels") not in (None,) else [],
    }


def merge_related_alert(stub: dict, full: dict | None) -> dict:
    """Prefer the full getAlerts record; keep nested incident stub labels if needed.

    getIncidents `alerts { ... }` is often what we package when getAlerts(id)
    misses a related alert. Those stubs used to drop labels, so SecOps showed [].
    """
    stub = stub if isinstance(stub, dict) else {}
    if not isinstance(full, dict):
        return stub_to_alert(stub)
    merged = dict(full)
    if not record_label_tags(merged) and stub.get("labels") not in (None, "", [], {}):
        merged["labels"] = stub.get("labels")
    if not str(merged.get("vegaAlertId") or "").strip():
        vega_id = str(stub.get("vegaAlertId") or "").strip()
        if vega_id:
            merged["vegaAlertId"] = vega_id
    return merged


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


def _has_mapped_value(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (list, dict)) and not value:
        return False
    return True


def _set_mapped(event: dict, key: str, value: Any) -> None:
    if not key or key in event or not _has_mapped_value(value):
        return
    event[key] = _soar_value(value)


def _map_api_fields(event: dict, record: dict, fields: tuple[tuple[str, str], ...]) -> None:
    if not isinstance(record, dict):
        return
    for api_key, event_key in fields:
        if api_key not in record:
            continue
        value = record.get(api_key)
        if api_key == "labels":
            value = _display_labels(value)
        _set_mapped(event, event_key, value)


def _apply_entity_aliases(event: dict, payload: dict) -> None:
    for key, value in payload.items():
        bucket = _ENTITY_ALIASES.get(str(key).strip().lower())
        if not bucket or bucket in event or not _has_mapped_value(value):
            continue
        if isinstance(value, (dict, list)):
            continue
        event[bucket] = _soar_value(value)


def _details_payload(record: dict) -> str:
    """JSON snapshot of the Vega record without duplicating child events."""
    if not isinstance(record, dict):
        return _safe_json(record)
    trimmed = {}
    for key, value in record.items():
        if key in (SOAR_META_KEY, "alert_events", "nested_related_alerts"):
            continue
        if key == "labels":
            trimmed[key] = _display_labels(value)
            continue
        if not _has_mapped_value(value):
            continue
        trimmed[key] = value
    if "labels" not in trimmed:
        trimmed["labels"] = []
    return _soar_value(trimmed, limit=_MAX_DETAILS_CHARS)


# Selection set from GET_ALERTS_QUERY `alerts { ... }`.
_ALERT_API_FIELDS = (
    ("vegaAlertId", "vega_alert_id"),
    ("detectionId", "detection_id"),
    ("description", "description"),
    ("status", "status"),
    ("assignee", "assignee"),
    ("assignees", "assignees"),
    ("dataSources", "data_sources"),
    ("createdAt", "created_at"),
    ("updatedAt", "updated_at"),
    ("mitre", "mitre"),
    ("relatedIncidents", "related_incidents"),
    ("detectionSource", "detection_source"),
    ("detectionDescription", "detection_description"),
    ("detectionQuery", "detection_query"),
    ("eventCount", "event_count"),
    ("isTestMode", "is_test_mode"),
    ("verdict", "verdict"),
    ("verdictReasoning", "verdict_reasoning"),
    ("escalation", "escalation"),
    ("dedupCount", "dedup_count"),
    ("comments", "comments"),
    ("labels", "labels"),
    ("skills", "skills"),
    ("actors", "actors"),
    ("targets", "targets"),
    ("href", "source_url"),
)

# Selection set from GET_INCIDENTS_QUERY `incidents { ... }`, plus timeline
# enrichment from getIncidentTimeline.
_INCIDENT_API_FIELDS = (
    ("vegaUniqueIncidentId", "vega_unique_incident_id"),
    ("createdBy", "created_by"),
    ("createdAt", "created_at"),
    ("lastUpdated", "updated_at"),
    ("status", "status"),
    ("dataSources", "data_sources"),
    ("verdict", "verdict"),
    ("verdictReasoning", "verdict_reasoning"),
    ("assignee", "assignee"),
    ("assignees", "assignees"),
    ("comments", "comments"),
    ("incidentSummary", "description"),
    ("incidentFindings", "incident_findings"),
    ("assets", "assets"),
    ("observables", "observables"),
    ("alertsCount", "alerts_count"),
    ("alerts", "alerts"),
    ("recommendedActions", "recommended_actions"),
    ("investigationPlan", "investigation_plan"),
    ("labels", "labels"),
    ("skills", "skills"),
    ("href", "source_url"),
    ("link", "source_url"),
    ("timeline", "timeline"),
)


def _apply_label_fields(
    event: dict, record: dict, *, copy_incident_names: bool
) -> None:
    """Put this Vega record's labels on a SOAR event.

    Incident names stay on `vega_incident_label_names` for related alerts;
    they are not copied onto `labels`.
    """
    event["labels"] = _soar_value(
        _display_labels(record.get("labels") if isinstance(record, dict) else None)
    )
    label_names = record_label_tags(record)
    if label_names:
        event["vega_label_names"] = ",".join(label_names)
    if not copy_incident_names:
        return
    meta = soar_meta(record)
    incident_label_names = [
        str(name).strip()
        for name in (meta.get("incident_label_tags") or [])
        if str(name).strip()
    ]
    if incident_label_names:
        event["vega_incident_label_names"] = ",".join(incident_label_names)


def build_event_dict(record: dict, entity_type: str, start_time: int, end_time: int) -> dict:
    """Map a Vega alert or incident onto a SOAR event using API fields only.

    Empty or missing Vega values are omitted so the Default event section does
    not show null fields that were never returned by getAlerts/getIncidents.
    `labels` is always present: Vega names/colors, or `[]` when there are none.
    """
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
        "event_type": entity_type,
        "product_log_id": identifier,
        "vega_id": identifier,
        "event_class_id": identifier,
        "DeviceEventClassID": identifier,
        "Severity": severity,
        "vega_entity_type": entity_type,
        "vega_soar_alert_type": soar_alert_type,
    }
    _set_mapped(event, "source_grouping_identifier", grouping_id)
    _set_mapped(event, "vega_incident_id", incident_id)
    if entity_type == ENTITY_TYPE_INCIDENT:
        _map_api_fields(event, record, _INCIDENT_API_FIELDS)
    else:
        _map_api_fields(event, record, _ALERT_API_FIELDS)
    _set_mapped(event, "vega_unique_incident_id", incident_display_id)
    _apply_label_fields(
        event, record, copy_incident_names=entity_type == ENTITY_TYPE_ALERT
    )
    details = _details_payload(record)
    if details:
        event["details"] = details
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


def _is_flat_dict(value: dict) -> bool:
    return all(not isinstance(item, (dict, list)) for item in value.values())


def _iter_dynamic_fields(payload: dict):
    """Yield API keys/values from getAlertsEvents, flattening one-level dicts."""
    for key, value in payload.items():
        if str(key) in _SKIP_PAYLOAD_KEYS:
            continue
        if not _has_mapped_value(value):
            continue
        if isinstance(value, dict) and _is_flat_dict(value):
            for nested_key, nested_value in value.items():
                if str(nested_key) in _SKIP_PAYLOAD_KEYS:
                    continue
                if not _has_mapped_value(nested_value):
                    continue
                yield nested_key, nested_value
            continue
        yield key, value


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
    Fields are taken from the API payload as-is; empty values are omitted.
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
        "event_type": "Alert Event",
        "product_log_id": event_key,
        "vega_id": identifier,
        "event_class_id": event_key,
        "DeviceEventClassID": event_key,
        "Severity": record_severity(parent),
        "vega_entity_type": "Alert Event",
    }
    _set_mapped(event, "source_grouping_identifier", grouping_id)
    _set_mapped(event, "vega_alert_id", parent.get("vegaAlertId"))
    _set_mapped(event, "vega_incident_id", incident_id)
    extra = 0
    for key, value in _iter_dynamic_fields(payload):
        if extra >= _MAX_EXTRA_FIELDS:
            break
        safe_key = _soar_key(key)
        if not safe_key or safe_key in event:
            continue
        event[safe_key] = _soar_value(value)
        extra += 1
    # Related-alert cases are mostly these child events. Copy the parent
    # Vega Alert labels so Default/Events is not an empty `labels` list.
    _apply_label_fields(event, parent, copy_incident_names=True)
    details_payload = {
        key: value for key, value in payload.items() if _has_mapped_value(value)
    }
    if details_payload:
        event["details"] = _soar_value(details_payload, limit=_MAX_DETAILS_CHARS)
    event.update(_flatten_entities(payload))
    _apply_entity_aliases(event, payload)
    return event


def alert_priority(severity: str) -> int:
    return SEVERITY_TO_ALERT_PRIORITY.get(str(severity).upper(), 60)
