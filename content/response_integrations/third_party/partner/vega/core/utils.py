"""Validation, filter mapping, timestamps, and log redaction."""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from .constants import (
    ALERT_STATUS_OPTIONS,
    BACKFILL_MAX,
    BACKFILL_MIN,
    ENTITY_OPTIONS,
    INCIDENT_STATUS_OPTIONS,
    LOOKBACK_MAX,
    LOOKBACK_MIN,
    MSG_BAD_REQUEST,
    MSG_FORBIDDEN,
    MSG_INVALID_ACCESS_KEY,
    MSG_INVALID_ACCESS_KEY_ID,
    MSG_NOT_FOUND,
    MSG_RATE_LIMIT,
    MSG_SERVER_ERROR,
    MSG_TIMEOUT,
    MSG_UNAUTHORIZED,
    MSG_UNREACHABLE,
    PARAM_ALERT_SEVERITIES,
    PARAM_ALERT_STATUSES,
    PARAM_ALERT_VERDICTS,
    PARAM_BACKFILL,
    PARAM_ENTITIES,
    PARAM_HAS_RELATED,
    PARAM_INCIDENT_SEVERITIES,
    PARAM_INCIDENT_STATUSES,
    PARAM_INCIDENT_VERDICTS,
    PARAM_LOOKBACK,
    RELATED_OPTIONS,
    SEVERITY_OPTIONS,
    VERDICT_OPTIONS,
)
from .exceptions import (
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
            "API Root is required. Enter the Vega HTTPS base URL, for example https://api.vega.io."
        )
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise VegaValidationException(
            "API Root must be an HTTPS URL, for example https://api.vega.io."
        )
    return text


def require_secret(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise VegaValidationException(f"{name} is required. Enter a valid {name}.")
    return text


def parse_int_in_range(
    value: Any,
    name: str,
    minimum: int,
    maximum: int,
    default: Optional[int] = None,
) -> int:
    """Parse a required integer in [minimum, maximum]. Invalid values raise."""
    text = "" if value is None else str(value).strip()
    if text == "":
        if default is not None:
            return default
        raise VegaValidationException(
            f"{name} is required. Enter an integer from {minimum} to {maximum}."
        )
    if not re.fullmatch(r"-?\d+", text):
        raise VegaValidationException(
            f'"{text}" is not a valid value for {name}. '
            f"Enter an integer from {minimum} to {maximum}."
        )
    number = int(text)
    if number < minimum or number > maximum:
        raise VegaValidationException(
            f'"{text}" is not a valid value for {name}. '
            f"Use a number from {minimum} to {maximum}."
        )
    return number


def parse_lookback_minutes(value: Any) -> int:
    return parse_int_in_range(
        value,
        PARAM_LOOKBACK,
        LOOKBACK_MIN,
        LOOKBACK_MAX,
    )


def parse_backfill_days(value: Any) -> int:
    return parse_int_in_range(
        value,
        PARAM_BACKFILL,
        BACKFILL_MIN,
        BACKFILL_MAX,
    )


def to_graphql_enum(value: str) -> str:
    """Map operator labels with spaces to GraphQL enum names."""
    return " ".join(str(value).split()).replace(" ", "_")


def _raise_unsupported(param_name: str, unknown: list[str], allowed: Iterable[str]) -> None:
    quoted = ", ".join(f'"{item}"' for item in unknown)
    possible = ", ".join(allowed)
    if len(unknown) == 1:
        raise VegaValidationException(
            f"{quoted} is not a valid value for {param_name}. Use one of: {possible}."
        )
    raise VegaValidationException(
        f"{quoted} are not valid values for {param_name}. Use only: {possible}."
    )


def _filter_known(selected: list[str], allowed: Iterable[str]) -> tuple[list[str], list[str]]:
    allowed_map = {item.upper(): to_graphql_enum(item) for item in allowed}
    allowed_tokens = {to_graphql_enum(item).upper(): to_graphql_enum(item) for item in allowed}
    result: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    seen_unknown: set[str] = set()
    for raw in selected:
        token = to_graphql_enum(raw)
        key = token.upper()
        mapped = allowed_map.get(raw.strip().upper()) or allowed_tokens.get(key)
        if not mapped:
            label = " ".join(str(raw).split())
            if label and label not in seen_unknown:
                seen_unknown.add(label)
                unknown.append(label)
            continue
        if mapped in seen:
            continue
        seen.add(mapped)
        result.append(mapped)
    return result, unknown


def resolve_multi_filter(
    raw: Any,
    allowed: Iterable[str],
    *,
    param_name: str,
    empty_means_all: bool = True,
) -> Optional[list[str]]:
    """Return GraphQL enum values. Empty = all/omit. Unsupported values raise."""
    selected = parse_csv_list(raw)
    if not selected:
        return None if empty_means_all else []
    resolved, unknown = _filter_known(selected, allowed)
    if unknown:
        _raise_unsupported(param_name, unknown, allowed)
    if not resolved:
        return None if empty_means_all else []
    allowed_list = [to_graphql_enum(item) for item in allowed]
    if empty_means_all and set(resolved) == set(allowed_list):
        return None
    return resolved


def resolve_entities(raw: Any) -> list[str]:
    selected = parse_csv_list(raw)
    if not selected:
        raise VegaValidationException(
            f"{PARAM_ENTITIES} is required. Use one or both of: {', '.join(ENTITY_OPTIONS)}."
        )
    known = {item.lower(): item for item in ENTITY_OPTIONS}
    resolved = []
    unknown = []
    for item in selected:
        match = known.get(item.lower())
        if match:
            if match not in resolved:
                resolved.append(match)
            continue
        if item not in unknown:
            unknown.append(item)
    if unknown:
        _raise_unsupported(PARAM_ENTITIES, unknown, ENTITY_OPTIONS)
    if not resolved:
        raise VegaValidationException(
            f"{PARAM_ENTITIES} is required. Use one or both of: {', '.join(ENTITY_OPTIONS)}."
        )
    return resolved


def resolve_has_related(raw: Any) -> Optional[bool]:
    selected = parse_csv_list(raw)
    if not selected:
        raise VegaValidationException(
            f"{PARAM_HAS_RELATED} is required. Use one or both of: {', '.join(RELATED_OPTIONS)}."
        )
    known = {item.lower(): item for item in RELATED_OPTIONS}
    resolved = []
    unknown = []
    for item in selected:
        match = known.get(item.lower())
        if match:
            if match not in resolved:
                resolved.append(match)
            continue
        if item not in unknown:
            unknown.append(item)
    if unknown:
        _raise_unsupported(PARAM_HAS_RELATED, unknown, RELATED_OPTIONS)
    if not resolved:
        raise VegaValidationException(
            f"{PARAM_HAS_RELATED} is required. Use one or both of: {', '.join(RELATED_OPTIONS)}."
        )
    if set(resolved) == set(RELATED_OPTIONS):
        return None
    return resolved[0] == "Yes"


def resolve_alert_filters(config: dict) -> dict:
    return {
        "severities": resolve_multi_filter(
            config.get("alert_severities"),
            SEVERITY_OPTIONS,
            param_name=PARAM_ALERT_SEVERITIES,
        ),
        "statuses": resolve_multi_filter(
            config.get("alert_statuses"),
            ALERT_STATUS_OPTIONS,
            param_name=PARAM_ALERT_STATUSES,
        ),
        "verdicts": resolve_multi_filter(
            config.get("alert_verdicts"),
            VERDICT_OPTIONS,
            param_name=PARAM_ALERT_VERDICTS,
        ),
        "has_related": resolve_has_related(config.get("has_related")),
    }


def resolve_incident_filters(config: dict) -> dict:
    return {
        "severities": resolve_multi_filter(
            config.get("incident_severities"),
            SEVERITY_OPTIONS,
            param_name=PARAM_INCIDENT_SEVERITIES,
        ),
        "statuses": resolve_multi_filter(
            config.get("incident_statuses"),
            INCIDENT_STATUS_OPTIONS,
            param_name=PARAM_INCIDENT_STATUSES,
        ),
        "verdicts": resolve_multi_filter(
            config.get("incident_verdicts"),
            VERDICT_OPTIONS,
            param_name=PARAM_INCIDENT_VERDICTS,
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


_KEY_ID_HINTS = (
    "key-id",
    "key_id",
    "keyid",
    "x-vega-key-id",
    "access key id",
    "access_key_id",
)
_ACCESS_KEY_ONLY_RE = re.compile(r"access[_\s]?key(?![_\s]?id)")


def classify_credential_error(text: str) -> Optional[str]:
    """Return a specific credential message when the API text names the field."""
    raw = (text or "").lower()
    mentions_key_id = any(hint in raw for hint in _KEY_ID_HINTS)
    mentions_key = bool(_ACCESS_KEY_ONLY_RE.search(raw))
    if mentions_key_id and not mentions_key:
        return MSG_INVALID_ACCESS_KEY_ID
    if mentions_key and not mentions_key_id:
        return MSG_INVALID_ACCESS_KEY
    return None


def format_user_facing_error(exc: BaseException) -> str:
    if isinstance(exc, VegaValidationException):
        return str(exc)
    if isinstance(exc, VegaUnauthorizedException):
        return str(exc).strip() or MSG_UNAUTHORIZED
    if isinstance(exc, VegaForbiddenException):
        return MSG_FORBIDDEN
    if isinstance(exc, VegaBadRequestException):
        return str(exc).strip() or MSG_BAD_REQUEST
    if isinstance(exc, VegaNotFoundException):
        return MSG_NOT_FOUND
    if isinstance(exc, VegaRateLimitException):
        return MSG_RATE_LIMIT
    if isinstance(exc, VegaTimeoutException):
        return str(exc).strip() or MSG_TIMEOUT
    if isinstance(exc, VegaException):
        classified = classify_credential_error(str(exc))
        if classified:
            return classified
        return str(exc)[:300] or "Vega request failed. Please try again."
    raw = str(exc or "").strip().lower()
    if "timeout" in raw or "timed out" in raw:
        return MSG_TIMEOUT
    if any(token in raw for token in ("connection", "name or service not known")):
        return MSG_UNREACHABLE
    if "429" in raw:
        return MSG_RATE_LIMIT
    if "401" in raw:
        return classify_credential_error(raw) or MSG_UNAUTHORIZED
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
