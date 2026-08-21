"""Validation, filter mapping, timestamps, and log redaction."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from constants import (
    ALERT_STATUS_OPTIONS,
    BACKFILL_MAX,
    BACKFILL_MIN,
    ENTITY_OPTIONS,
    INCIDENT_STATUS_OPTIONS,
    LOOKBACK_MAX,
    LOOKBACK_MIN,
    MSG_BAD_REQUEST,
    MSG_FORBIDDEN,
    MSG_NOT_FOUND,
    MSG_RATE_LIMIT,
    MSG_SERVER_ERROR,
    MSG_TIMEOUT,
    MSG_UNAUTHORIZED,
    MSG_UNREACHABLE,
    OUTGOING_FIELD_OPTIONS,
    RELATED_OPTIONS,
    SEVERITY_OPTIONS,
    VERDICT_OPTIONS,
)
from exceptions import (
    VegaBadRequestException,
    VegaException,
    VegaForbiddenException,
    VegaNotFoundException,
    VegaRateLimitException,
    VegaTimeoutException,
    VegaUnauthorizedException,
    VegaValidationException,
)

logger = logging.getLogger(__name__)

_SECRET_KEYS = (
    "access_key",
    "access_key_id",
    "session_jwt",
    "jwtsessiontoken",
    "x-vega-key-id",
    "authorization",
)
_JSONISH_RE = re.compile(r"\{[^{}]{0,500}\}")


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


def to_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_csv_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        return [str(item).strip() for item in raw if str(item).strip()]
    text = str(raw).strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except Exception:
            pass
    for sep in (",", ";", "|"):
        if sep in text:
            return [part.strip() for part in text.split(sep) if part.strip()]
    return [text]


def truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in ("true", "1", "yes")


def normalize_api_root(value: Any) -> str:
    text = str(value or "").strip().rstrip("/")
    if not text:
        raise VegaValidationException(
            "API Root is required. Enter the Vega HTTPS base URL."
        )
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc:
        raise VegaValidationException(
            "API Root must be an HTTPS URL, for example https://api.vega.io."
        )
    return text


def require_secret(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise VegaValidationException(f"{name} is required.")
    return text


def parse_int_in_range(
    value: Any,
    name: str,
    minimum: int,
    maximum: int,
    default: Optional[int] = None,
    clamp_default: Optional[int] = None,
) -> int:
    """Parse an integer. Out-of-range uses clamp_default when set."""
    if value is None or str(value).strip() == "":
        if default is not None:
            return default
        raise VegaValidationException(f"{name} is required.")
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        if clamp_default is not None:
            return clamp_default
        raise VegaValidationException(f"{name} must be an integer.") from exc
    if number < minimum or number > maximum:
        if clamp_default is not None:
            return clamp_default
        raise VegaValidationException(
            f"{name} must be between {minimum} and {maximum}."
        )
    return number


def parse_lookback_minutes(value: Any) -> int:
    return parse_int_in_range(
        value,
        "Fetch Lookback (Minutes)",
        LOOKBACK_MIN,
        LOOKBACK_MAX,
        default=5,
    )


def parse_backfill_days(value: Any) -> int:
    return parse_int_in_range(
        value,
        "Max Days Backwards",
        BACKFILL_MIN,
        BACKFILL_MAX,
        default=30,
    )


def to_graphql_enum(value: str) -> str:
    """Map operator labels with spaces to GraphQL enum names."""
    return " ".join(str(value).split()).replace(" ", "_")


def _filter_known(selected: list[str], allowed: Iterable[str]) -> list[str]:
    allowed_map = {item.upper(): to_graphql_enum(item) for item in allowed}
    allowed_tokens = {to_graphql_enum(item).upper(): to_graphql_enum(item) for item in allowed}
    result: list[str] = []
    seen: set[str] = set()
    for raw in selected:
        token = to_graphql_enum(raw)
        key = token.upper()
        mapped = allowed_map.get(raw.strip().upper()) or allowed_tokens.get(key)
        if not mapped:
            continue
        if mapped in seen:
            continue
        seen.add(mapped)
        result.append(mapped)
    return result


def resolve_multi_filter(
    raw: Any,
    allowed: Iterable[str],
    *,
    empty_means_all: bool = True,
) -> Optional[list[str]]:
    """Return GraphQL enum values. Unknown values are ignored. Empty = all/omit."""
    selected = parse_csv_list(raw)
    if not selected:
        return None if empty_means_all else []
    resolved = _filter_known(selected, allowed)
    if not resolved:
        return None if empty_means_all else []
    allowed_list = [to_graphql_enum(item) for item in allowed]
    if empty_means_all and set(resolved) == set(allowed_list):
        return None
    return resolved


def resolve_entities(raw: Any) -> list[str]:
    selected = parse_csv_list(raw) or list(ENTITY_OPTIONS)
    known = {item.lower(): item for item in ENTITY_OPTIONS}
    resolved = []
    for item in selected:
        match = known.get(item.lower())
        if match and match not in resolved:
            resolved.append(match)
    if not resolved:
        raise VegaValidationException(
            "Vega Entities to Fetch must include Alerts and/or Incidents."
        )
    return resolved


def resolve_has_related(raw: Any) -> Optional[bool]:
    selected = parse_csv_list(raw) or list(RELATED_OPTIONS)
    known = {item.lower(): item for item in RELATED_OPTIONS}
    resolved = []
    for item in selected:
        match = known.get(item.lower())
        if match and match not in resolved:
            resolved.append(match)
    if not resolved:
        raise VegaValidationException(
            "Has Related Incidents must include Yes and/or No."
        )
    if set(resolved) == set(RELATED_OPTIONS):
        return None
    return resolved[0] == "Yes"


def resolve_outgoing_fields(raw: Any) -> list[str]:
    selected = parse_csv_list(raw)
    if not selected:
        return list(OUTGOING_FIELD_OPTIONS)
    known = {item.lower(): item for item in OUTGOING_FIELD_OPTIONS}
    resolved = []
    for item in selected:
        match = known.get(item.lower())
        if match and match not in resolved:
            resolved.append(match)
    return resolved or list(OUTGOING_FIELD_OPTIONS)


def resolve_alert_filters(config: dict) -> dict:
    return {
        "severities": resolve_multi_filter(
            config.get("alert_severities"), SEVERITY_OPTIONS
        ),
        "statuses": resolve_multi_filter(
            config.get("alert_statuses"), ALERT_STATUS_OPTIONS
        ),
        "verdicts": resolve_multi_filter(
            config.get("alert_verdicts"), VERDICT_OPTIONS
        ),
        "has_related": resolve_has_related(config.get("has_related")),
    }


def resolve_incident_filters(config: dict) -> dict:
    return {
        "severities": resolve_multi_filter(
            config.get("incident_severities"), SEVERITY_OPTIONS
        ),
        "statuses": resolve_multi_filter(
            config.get("incident_statuses"), INCIDENT_STATUS_OPTIONS
        ),
        "verdicts": resolve_multi_filter(
            config.get("incident_verdicts"), VERDICT_OPTIONS
        ),
    }


def redact(value: Any) -> Any:
    """Return a copy with secret-looking keys and JWT-like strings removed."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if str(key).strip().lower() in _SECRET_KEYS:
                redacted[key] = "<redacted>"
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    text = str(value) if value is not None else ""
    if len(text) > 20 and text.count(".") == 2:
        return "<redacted>"
    return value


def format_user_facing_error(exc: BaseException) -> str:
    if isinstance(exc, VegaValidationException):
        return str(exc)
    if isinstance(exc, VegaUnauthorizedException):
        return MSG_UNAUTHORIZED
    if isinstance(exc, VegaForbiddenException):
        return MSG_FORBIDDEN
    if isinstance(exc, VegaBadRequestException):
        return MSG_BAD_REQUEST
    if isinstance(exc, VegaNotFoundException):
        return MSG_NOT_FOUND
    if isinstance(exc, VegaRateLimitException):
        return MSG_RATE_LIMIT
    if isinstance(exc, VegaTimeoutException):
        return MSG_TIMEOUT
    if isinstance(exc, VegaException):
        return str(exc)[:300] or "Vega request failed. Please try again."
    raw = str(exc or "").strip().lower()
    if "timeout" in raw or "timed out" in raw:
        return MSG_TIMEOUT
    if any(token in raw for token in ("connection", "name or service not known")):
        return MSG_UNREACHABLE
    if "429" in raw:
        return MSG_RATE_LIMIT
    if "401" in raw:
        return MSG_UNAUTHORIZED
    cleaned = _JSONISH_RE.sub("", str(exc or ""))
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" :-")[:300]
    return cleaned or "Unexpected error while talking to Vega. Check configuration."


def safe_log(logger_obj, level: str, msg: str, *args) -> None:
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


def compute_time_window(
    checkpoint: dict,
    backfill_days: int,
    lookback_minutes: int,
    now: Optional[datetime] = None,
) -> dict:
    current = now or utc_now()
    lookback = timedelta(minutes=lookback_minutes)
    watermark = parse_iso_timestamp((checkpoint or {}).get("watermark"))
    if watermark is None:
        start = current - timedelta(days=backfill_days) - lookback
        return {
            "first_run": True,
            "from": to_iso(start),
            "to": to_iso(current),
            "updated_from": None,
            "updated_to": None,
            "end": to_iso(current),
        }
    start = watermark - lookback
    return {
        "first_run": False,
        "from": None,
        "to": None,
        "updated_from": to_iso(start),
        "updated_to": to_iso(current),
        "end": to_iso(current),
    }
