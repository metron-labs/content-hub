"""Shared helpers for timestamps, filters, and historical backfill."""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .constants import (
    DEFAULT_FLARE_APP_URL,
    DEFAULT_MAX_RECORDS,
    HARD_MAX_RECORDS,
    MAX_BACKFILL_RANGE_DAYS,
    MSG_BAD_REQUEST,
    MSG_FORBIDDEN,
    MSG_NOT_FOUND,
    MSG_RATE_LIMIT,
    MSG_SERVER_ERROR,
    MSG_UNAUTHORIZED,
)
from .exceptions import (
    FlareBadRequestException,
    FlareException,
    FlareForbiddenException,
    FlareNotFoundException,
    FlareRateLimitException,
    FlareUnauthorizedException,
    FlareValidationException,
)

logger = logging.getLogger(__name__)

# India Standard Time (IST, UTC+05:30) — backfill windows start at local midnight.
IST = timezone(timedelta(hours=5, minutes=30))

_JSONISH_RE = re.compile(r"\{[^{}]{0,500}\}")
_HTTP_STATUS_RE = re.compile(r"HTTP\s+(\d{3})", re.IGNORECASE)


def parse_tenant_id(value: Any) -> int:
    """Parse and validate a single Flare Tenant ID as a positive integer."""
    tenant_ids = parse_tenant_ids(value)
    if len(tenant_ids) != 1:
        raise FlareValidationException(
            "Flare Tenant ID must be a single number when used here. "
            "For multiple tenants, use a comma-separated list in the connector."
        )
    return tenant_ids[0]


def parse_tenant_ids(value: Any) -> list:
    """
    Parse one or more Flare Tenant IDs.

    Accepts a single number or a comma/semicolon/pipe-separated list
    (e.g. \"123\" or \"123,456\"). Duplicates are removed, order preserved.
    """
    if isinstance(value, (list, tuple, set)):
        raw_parts = [str(v).strip() for v in value if str(v).strip()]
    else:
        text = str(value if value is not None else "").strip()
        if not text:
            raise FlareValidationException(
                "Flare Tenant ID is required. Enter the numeric tenant ID from Flare "
                "(or a comma-separated list for multiple tenants)."
            )
        # Split on comma / semicolon / pipe so "123,456" and "123;456" both work.
        raw_parts = re.split(r"[,;|]+", text)
        raw_parts = [p.strip() for p in raw_parts if p.strip()]

    if not raw_parts:
        raise FlareValidationException(
            "Flare Tenant ID is required. Enter the numeric tenant ID from Flare "
            "(or a comma-separated list for multiple tenants)."
        )

    tenant_ids: list = []
    seen: set = set()
    for part in raw_parts:
        token = str(part).strip()
        if not token.isdigit():
            raise FlareValidationException(
                f"Flare Tenant ID must be a number (or a comma-separated list of numbers). Invalid value: {token}."
            )
        tenant_id = int(token)
        if tenant_id <= 0:
            raise FlareValidationException(f"Flare Tenant ID must be a positive number. Invalid value: {tenant_id}.")
        if tenant_id in seen:
            continue
        seen.add(tenant_id)
        tenant_ids.append(tenant_id)
    return tenant_ids


def format_user_facing_error(exc: BaseException) -> str:
    """
    Convert raw exceptions / API payloads into short, human-readable messages
    for Configure Instance Test, connector Testing, Run once, and Logs.
    """
    if isinstance(exc, FlareValidationException):
        return str(exc)
    if isinstance(exc, FlareUnauthorizedException):
        return MSG_UNAUTHORIZED
    if isinstance(exc, FlareForbiddenException):
        return MSG_FORBIDDEN
    if isinstance(exc, FlareBadRequestException):
        return MSG_BAD_REQUEST
    if isinstance(exc, FlareNotFoundException):
        return MSG_NOT_FOUND
    if isinstance(exc, FlareRateLimitException):
        return MSG_RATE_LIMIT
    if isinstance(exc, FlareException):
        cleaned = _strip_raw_payload(str(exc))
        return cleaned or "Flare request failed. Please try again."

    raw = str(exc or "").strip()
    lower = raw.lower()

    if "invalid literal for int" in lower or ("tenant id" in lower and "number" in lower):
        return "Flare Tenant ID must be a number. Please enter a valid tenant ID."
    if any(token in lower for token in ("invalid_key", "invalid api key", "unauthorized")):
        return MSG_UNAUTHORIZED
    if "forbidden" in lower:
        return MSG_FORBIDDEN
    if "429" in lower or "ratelimit" in lower or "rate limit" in lower:
        return MSG_RATE_LIMIT
    if "timeout" in lower or "timed out" in lower:
        return "Connection to Flare timed out. Check network access and try again."
    if any(token in lower for token in ("connection", "name or service not known", "nodename")):
        return "Unable to reach the Flare API. Check network access and try again."

    status_match = _HTTP_STATUS_RE.search(raw)
    if status_match:
        status = status_match.group(1)
        if status == "401":
            return MSG_UNAUTHORIZED
        if status == "403":
            return MSG_FORBIDDEN
        if status == "404":
            return "Requested Flare resource was not found."
        if status == "429":
            return MSG_RATE_LIMIT
        if status.startswith("5"):
            return MSG_SERVER_ERROR

    cleaned = _strip_raw_payload(raw)
    if cleaned:
        return cleaned
    return "Unexpected error while talking to Flare. Check configuration and try again."


def _strip_raw_payload(message: str) -> str:
    """Drop embedded JSON / HTML dumps so operators see a short sentence."""
    text = (message or "").strip()
    if not text:
        return ""
    text = _JSONISH_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip(" :-")
    # Prefer the first sentence-like chunk when the platform appends a traceback hint.
    for sep in ("Traceback", 'File "', "\n"):
        if sep in text:
            text = text.split(sep, 1)[0].strip(" :-")
    return text[:300]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or raw.lower() in ("null", "none"):
        return None
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_flare_timestamp(value: Optional[str]) -> Optional[str]:
    """Normalize UI/checkpoint timestamps to Flare-friendly ISO-8601 UTC.

    Fractional seconds are kept. The ingestion watermark is a Flare
    matched_at value, and trimming it would move the next search window.
    """
    parsed = parse_iso_timestamp(value)
    if parsed is None:
        return value.strip() if isinstance(value, str) and value.strip() else None
    parsed = parsed.astimezone(timezone.utc)
    if parsed.microsecond:
        return parsed.strftime("%Y-%m-%dT%H:%M:%S.") + f"{parsed.microsecond:06d}Z"
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_backfill_range_days(val: Any) -> int:
    """
    Validate a backfill range from 0 through MAX_BACKFILL_RANGE_DAYS.

    Zero disables historical backfill. Invalid or out-of-range values fail
    explicitly instead of silently requesting an unexpected date range.
    """
    try:
        days = int(val)
    except (TypeError, ValueError):
        raise ValueError(f"Backfill Range (Days) must be an integer from 0 to {MAX_BACKFILL_RANGE_DAYS}.")

    if days < 0 or days > MAX_BACKFILL_RANGE_DAYS:
        raise ValueError(f"Backfill Range (Days) must be between 0 and {MAX_BACKFILL_RANGE_DAYS}; received {days}.")

    return days


def default_backfill_start(backfill_days: Any) -> str:
    """
    Start of the historical backfill window.

    For N > 0 days: N calendar days ago at 12:00 AM IST (Asia/Kolkata),
    returned as UTC for the Flare API (e.g. 5 days → today-5 @ 00:00 IST).
    For 0 days: current UTC time (no historical backfill).
    """
    days = validate_backfill_range_days(backfill_days)
    if days == 0:
        return utc_now_iso()

    now_ist = datetime.now(IST)
    start_ist = (now_ist - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    return start_ist.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_csv_list(raw: Optional[str]) -> list:
    """Parse comma/semicolon/pipe-separated values (or a JSON list) into a list."""
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        return [str(s).strip() for s in raw if str(s).strip()]
    text = str(raw).strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(s).strip() for s in parsed if str(s).strip()]
        except Exception:
            pass
    for sep in (",", ";", "|"):
        if sep in text:
            return [s.strip() for s in text.split(sep) if s.strip()]
    return [text]


def safe_log(logger_obj, level: str, msg: str, *args) -> None:
    """
    Log through the Siemplify logger, which does not accept %-style args.

    Interpolating here keeps messages readable instead of emitting raw "%s".
    """
    text = msg
    if args:
        try:
            text = msg % args
        except Exception:
            text = " ".join([msg] + [str(arg) for arg in args])

    log_fn = getattr(logger_obj, level, None) if logger_obj else None
    if callable(log_fn):
        log_fn(text)
    else:
        getattr(logger, level)(text)


def flare_url_for_uid(uid: Any) -> str:
    """Build Flare UI URL for an event UID (matches metadata.flare_url style)."""
    text = str(uid or "").strip()
    if not text:
        return ""
    # UI path: https://app.flare.io/#/<uid>
    encoded = urllib.parse.quote(text, safe="/")
    return f"{DEFAULT_FLARE_APP_URL.rstrip('#/')}/#/{encoded}"


def _normalize_filter_token(value: Any) -> str:
    """Case-insensitive token: lower-case and collapse spaces/hyphens to underscores."""
    text = str(value or "").strip().lower()
    text = re.sub(r"[\s\-]+", "_", text)
    return text


def _option_key_and_labels(item: Any, extra_label_map: Optional[dict] = None) -> Optional[dict]:
    """
    Normalize one Flare filter catalog entry to
    {"key": <api value>, "label": <display>, "labels": set()}.

    Accepts strings or dicts with common key/label fields (value/name/label/...).
    Preferred display label is the API label when present.
    """
    labels: set = set()
    key = None
    preferred_label = None

    if isinstance(item, str):
        key = item.strip()
    elif isinstance(item, dict):
        for field in ("value", "id", "key", "uid", "type", "code"):
            candidate = item.get(field)
            if candidate is not None and str(candidate).strip():
                key = str(candidate).strip()
                break
        for field in (
            "label",
            "name",
            "display_name",
            "displayName",
            "title",
            "description",
        ):
            candidate = item.get(field)
            if candidate is not None and str(candidate).strip():
                text = str(candidate).strip()
                labels.add(text)
                if preferred_label is None:
                    preferred_label = text
        if key is None and labels:
            key = next(iter(labels))
    else:
        key = str(item).strip() if item is not None else ""

    if not key:
        return None

    labels.add(key)
    if extra_label_map:
        mapped = extra_label_map.get(key) or extra_label_map.get(key.lower())
        if mapped:
            mapped_text = str(mapped)
            labels.add(mapped_text)
            if preferred_label is None:
                preferred_label = mapped_text
    return {
        "key": key,
        "label": preferred_label or key,
        "labels": labels,
    }


def _extract_categorized_filter_options(
    categories: list,
    extra_label_map: Optional[dict] = None,
) -> list:
    """
    Build options from Flare /events/filters/types categories payload.

    Each sub-type is a leaf option. Each parent category is also selectable and
    carries expand_to=[all sub-type keys] so "Open Web" → all open_web types.
    """
    options: list = []
    seen_types: set = set()

    for category in categories:
        if not isinstance(category, dict):
            continue

        types = category.get("types") or category.get("items") or []
        type_keys: list = []
        if isinstance(types, list):
            for item in types:
                option = _option_key_and_labels(item, extra_label_map=extra_label_map)
                if not option:
                    continue
                type_keys.append(option["key"])
                dedupe = _normalize_filter_token(option["key"])
                if dedupe in seen_types:
                    continue
                seen_types.add(dedupe)
                options.append(option)

        if not type_keys:
            continue

        cat_option = _option_key_and_labels(category, extra_label_map=extra_label_map)
        if not cat_option:
            continue
        # Parent category → expand to every nested type (API type filter values).
        cat_option["expand_to"] = list(dict.fromkeys(type_keys))
        options.append(cat_option)

    return options


def extract_filter_options(
    raw: Any,
    extra_label_map: Optional[dict] = None,
) -> list:
    """
    Flatten Flare severity/type filter payloads into option dicts.

    Handles:
      - ["critical", ...]
      - [{"value": "paste", "name": "..."}, ...]
      - {"severities"|"items"|"data"|"types": [...]}
      - {"categories": [{"value", "label", "types": [...]}]}
        → leaf types plus parent categories with expand_to=[...]
    """
    if isinstance(raw, dict) and isinstance(raw.get("categories"), list):
        return _extract_categorized_filter_options(raw["categories"], extra_label_map=extra_label_map)

    items: list = []
    if raw is None:
        items = []
    elif isinstance(raw, list):
        items = list(raw)
    elif isinstance(raw, dict):
        for field in ("severities", "types", "items", "data", "results"):
            candidate = raw.get(field)
            if isinstance(candidate, list):
                items = list(candidate)
                break
        if not items and raw.get("value") is not None:
            items = [raw]
    else:
        items = [raw]

    options: list = []
    seen: set = set()
    for item in items:
        option = _option_key_and_labels(item, extra_label_map=extra_label_map)
        if not option:
            continue
        dedupe = _normalize_filter_token(option["key"])
        if dedupe in seen:
            continue
        seen.add(dedupe)
        options.append(option)
    return options


def _leaf_filter_keys(options: list) -> list:
    """API type/severity keys only (exclude parent categories with expand_to)."""
    keys: list = []
    seen: set = set()
    for opt in options:
        if opt.get("expand_to"):
            continue
        key = opt.get("key")
        if not key:
            continue
        token = _normalize_filter_token(key)
        if token in seen:
            continue
        seen.add(token)
        keys.append(key)
    return keys


def _option_display_label(opt: dict) -> str:
    key = str(opt.get("key") or "").strip()
    return str(opt.get("label") or key).strip() or key


def _format_valid_filter_options(options: list) -> str:
    """
    Format catalog options for operator-facing errors.

    Categorized source types → hierarchical tree (category + nested labels).
    Flat catalogs (e.g. severities) → comma-separated labels.
    """
    if not options:
        return "(none returned by Flare)"

    label_by_key: dict = {}
    for opt in options:
        key = opt.get("key")
        if not key or opt.get("expand_to"):
            continue
        label_by_key[_normalize_filter_token(key)] = _option_display_label(opt)

    categories = [opt for opt in options if opt.get("expand_to")]
    if categories:
        blocks: list = []
        for cat in categories:
            cat_label = _option_display_label(cat)
            child_labels: list = []
            for child_key in cat.get("expand_to") or []:
                token = _normalize_filter_token(child_key)
                child_labels.append(label_by_key.get(token) or str(child_key))
            children = ", ".join(child_labels) if child_labels else "(none)"
            blocks.append(f"• {cat_label} (Category)\n  └── {children}")
        return "Valid structural options are:\n\n" + "\n\n".join(blocks)

    labels = [_option_display_label(opt) for opt in options if opt.get("key")]
    return "Valid values: " + (", ".join(labels) if labels else "(none returned by Flare)")


def resolve_selected_filters(
    user_input: Any,
    options: list,
    filter_name: str,
    *,
    allow_empty_as_all: bool = True,
) -> list:
    """
    Resolve connector filter input against Flare catalog values.

    - Case-insensitive match on API key and display labels
      (e.g. open_web / Open Web / OPEN_WEB).
    - Parent category match expands to all nested sub-type keys.
    - Empty input → all leaf catalog keys (API defaults), when allow_empty_as_all.
    - Unknown values → FlareValidationException with a human-readable message.
    """
    selected = parse_csv_list(user_input)
    leaf_keys = _leaf_filter_keys(options)

    if not selected:
        if allow_empty_as_all:
            return list(leaf_keys)
        return []

    # token → option; leaf types win over parent categories on exact key collisions.
    lookup: dict = {}
    for opt in options:
        key = opt.get("key")
        if not key:
            continue
        tokens = {_normalize_filter_token(key)}
        for label in opt.get("labels") or set():
            tokens.add(_normalize_filter_token(label))
        for token in tokens:
            existing = lookup.get(token)
            if existing is None:
                lookup[token] = opt
            elif not opt.get("expand_to") and existing.get("expand_to"):
                lookup[token] = opt

    resolved: list = []
    unknown: list = []
    seen: set = set()
    for value in selected:
        opt = lookup.get(_normalize_filter_token(value))
        if not opt:
            unknown.append(value)
            continue
        keys_to_add = opt.get("expand_to") or [opt["key"]]
        for match in keys_to_add:
            token = _normalize_filter_token(match)
            if token in seen:
                continue
            seen.add(token)
            resolved.append(match)

    if unknown:
        raise FlareValidationException(
            f"Invalid {filter_name} value(s): {', '.join(unknown)}.\n{_format_valid_filter_options(options)}"
        )

    return resolved


def extract_event_timestamp(event: dict) -> str:
    """matched_at is the checkpoint and the _search filter. Fall back only if missing."""
    meta = event.get("metadata") or {}
    tenant_meta = event.get("tenant_metadata") or {}
    for obj in (meta, tenant_meta, event):
        if not isinstance(obj, dict):
            continue
        for key in ("matched_at", "estimated_created_at", "created_at"):
            val = obj.get(key)
            if val:
                return str(val)
    return ""


def max_event_timestamp(events: list) -> Optional[str]:
    best_ts: Optional[str] = None
    best_dt: Optional[datetime] = None
    for event in events:
        if not isinstance(event, dict):
            continue
        ts = extract_event_timestamp(event)
        parsed = parse_iso_timestamp(ts)
        if parsed is None:
            continue
        if best_dt is None or parsed > best_dt:
            best_dt = parsed
            best_ts = ts
    return best_ts


def cap_page_size(size: int, maximum: int = 10) -> int:
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = maximum
    return max(1, min(size, maximum))


# --- Action input helpers ---


def parse_bool(value: Any, default: bool = False) -> bool:
    """Parse a SOAR checkbox / string value into a bool."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if not text:
        return default
    if text in ("true", "1", "yes", "y", "on"):
        return True
    if text in ("false", "0", "no", "n", "off"):
        return False
    raise FlareValidationException(f"Invalid boolean value: {value}. Use true or false.")


def require_non_empty(value: Any, name: str) -> str:
    """Return the stripped string value or raise a validation error."""
    text = str(value if value is not None else "").strip()
    if not text:
        raise FlareValidationException(f"{name} is required and cannot be empty.")
    return text


def parse_max_records(
    value: Any,
    name: str = "Max Records To Return",
    default: int = DEFAULT_MAX_RECORDS,
    maximum: int = HARD_MAX_RECORDS,
) -> int:
    """Validate a record-limit input (integer between 1 and ``maximum``)."""
    if value is None or str(value).strip() == "":
        return default
    try:
        number = int(str(value).strip())
    except ValueError as exc:
        raise FlareValidationException(f"{name} must be a whole number.") from exc
    if number < 1 or number > maximum:
        raise FlareValidationException(f"{name} must be between 1 and {maximum}.")
    return number


def parse_optional_iso_date(value: Any, name: str) -> Optional[str]:
    """Validate an ISO 8601 date/time input; return it normalised to UTC (or None)."""
    text = str(value if value is not None else "").strip()
    if not text:
        return None
    parsed = parse_iso_timestamp(text)
    if parsed is None:
        raise FlareValidationException(f"{name} must be a valid ISO 8601 date/time, e.g. 2026-01-31T00:00:00Z.")
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_action_tenant(config_value: Any, override: Any = None) -> int:
    """
    Pick the single tenant an action runs against.

    The integration config accepts several tenants, but an action works on
    one. An explicit ``Tenant ID`` action parameter wins (and must be one of
    the configured tenants). Without it the config must hold exactly one.
    """
    configured = parse_tenant_ids(config_value)
    override_text = str(override if override is not None else "").strip()
    if override_text:
        chosen = parse_tenant_id(override_text)
        if chosen not in configured:
            allowed = ", ".join(str(t) for t in configured)
            raise FlareValidationException(
                f"Tenant ID {chosen} is not configured for this integration. Configured tenant ID(s): {allowed}."
            )
        return chosen
    if len(configured) == 1:
        return configured[0]
    allowed = ", ".join(str(t) for t in configured)
    raise FlareValidationException(
        f"The integration is configured with several tenants. Set the Tenant ID action parameter to one of: {allowed}."
    )


def split_csv_param(value: Any) -> list:
    """Parse a CSV action parameter into a de-duplicated list (order kept)."""
    return list(dict.fromkeys(parse_csv_list(value)))
