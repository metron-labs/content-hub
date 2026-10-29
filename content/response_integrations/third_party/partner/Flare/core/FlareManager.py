"""
Flare API manager for the Flare - Google SecOps integration.

Uses the official flareio SDK (FlareApiClient) which handles JWT generation
and auto-refresh. Paces calls to Flare's per-organization limits (basic 4/s,
search 1/s) and retries HTTP 429 after the 10 seconds Flare recommends.
Also retries 5xx and refreshes the token once on HTTP 401.
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.parse
from typing import Optional

import requests
from flareio import FlareApiClient
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from .constants import (
    BAD_REQUEST,
    DEFAULT_FLARE_API_URL,
    DEFAULT_HTTP_TIMEOUT,
    ENDPOINT_ALERT_CHANNELS,
    ENDPOINT_ALERTS,
    ENDPOINT_ENTITIES,
    ENDPOINT_ENTITIES_LIST,
    ENDPOINT_ENTITIES_RELATIONS,
    ENDPOINT_EVENT_ACTIONS,
    ENDPOINT_EVENTS_AI_ASSISTANCE,
    ENDPOINT_EVENTS_CREDENTIAL_ACTIONS,
    ENDPOINT_EVENTS_DETAIL,
    ENDPOINT_EVENTS_EXPAND,
    ENDPOINT_EVENTS_EXPLAIN_IDENTIFIER,
    ENDPOINT_EVENTS_SEARCH,
    ENDPOINT_EVENTS_TENANT_METADATA,
    ENDPOINT_FILTER_SEVERITIES,
    ENDPOINT_FILTER_TYPES,
    ENDPOINT_GLOBAL_SEARCH,
    ENDPOINT_GLOBAL_SEARCH_QUOTA,
    ENDPOINT_IDENTIFIERS,
    ENDPOINT_TENANTS,
    EVENT_ACTION_TYPES,
    FLARE_BASIC_REQUESTS_PER_SECOND,
    FLARE_HTTP_RETRIES,
    FLARE_RATE_LIMIT_RETRY_WAIT_SECONDS,
    FLARE_SEARCH_REQUESTS_PER_SECOND,
    FORBIDDEN,
    MAX_EVENT_ACTION_TARGETS,
    MAX_FLARE_PAGE_SIZE,
    MSG_BAD_REQUEST,
    MSG_FORBIDDEN,
    MSG_NOT_FOUND,
    MSG_RATE_LIMIT,
    MSG_SERVER_ERROR,
    MSG_UNAUTHORIZED,
    NOT_FOUND,
    OFFSET_PAGE_SIZE,
    SERVER_ERROR,
    SEVERITY_OPTIONS,
    TOO_MANY_REQUESTS,
    TYPE_DISPLAY_NAME,
    UNAUTHORIZED,
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
from .utils import (
    cap_page_size,
    extract_filter_options,
    format_user_facing_error,
    safe_log,
)

logger = logging.getLogger(__name__)

# One pair of buckets per API key. Limits are per organization, and a connector
# run builds a new FlareManager for each tenant on the same key.
_ORG_LIMITERS: dict[str, tuple["_RequestPace", "_RequestPace"]] = {}
_ORG_LIMITERS_LOCK = threading.Lock()


class _RequestPace:
    """Space calls so a bucket stays at or under its requests-per-second cap."""

    def __init__(self, requests_per_second: float) -> None:
        self._interval = 1.0 / requests_per_second
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            if delay > 0:
                time.sleep(delay)
                now = time.monotonic()
            self._next = now + self._interval


class _FlareRetry(Retry):
    """Retry 429 only after Flare's recommended 10 second wait."""

    def sleep(self, response=None):
        status = getattr(response, "status", None)
        if status == TOO_MANY_REQUESTS:
            wait = float(FLARE_RATE_LIMIT_RETRY_WAIT_SECONDS)
            headers = getattr(response, "headers", None)
            header = headers.get("Retry-After") if headers is not None else None
            if header:
                try:
                    parsed = self.parse_retry_after(header)
                except Exception:
                    parsed = None
                if parsed is not None:
                    wait = max(wait, float(parsed))
            logger.warning(
                "Flare rate limit reached (HTTP 429). Waiting %.0f seconds before retry.",
                wait,
            )
            time.sleep(wait)
            return
        super().sleep(response)


def _is_search_url(url: str) -> bool:
    path = urllib.parse.urlsplit(url or "").path.lower()
    return "/_search" in path


def _is_rate_limit_error(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "429" in text or "ratelimit" in text or "rate limit" in text


def _limiters_for(api_key: str) -> tuple[_RequestPace, _RequestPace]:
    with _ORG_LIMITERS_LOCK:
        existing = _ORG_LIMITERS.get(api_key)
        if existing is None:
            existing = (
                _RequestPace(FLARE_BASIC_REQUESTS_PER_SECOND),
                _RequestPace(FLARE_SEARCH_REQUESTS_PER_SECOND),
            )
            _ORG_LIMITERS[api_key] = existing
        return existing


class _TimeoutHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that paces Flare calls and applies a default timeout."""

    def __init__(
        self,
        *args,
        timeout=DEFAULT_HTTP_TIMEOUT,
        basic_pace: Optional[_RequestPace] = None,
        search_pace: Optional[_RequestPace] = None,
        **kwargs,
    ):
        self._default_timeout = timeout
        self._basic_pace = basic_pace
        self._search_pace = search_pace
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        pace = self._search_pace if _is_search_url(getattr(request, "url", "")) else self._basic_pace
        if pace is not None:
            pace.wait()
        kwargs.setdefault("timeout", self._default_timeout)
        return super().send(request, **kwargs)


def _build_session(api_key: str, ssl_verify: bool = True) -> requests.Session:
    session = requests.Session()
    session.verify = ssl_verify
    basic_pace, search_pace = _limiters_for(api_key)
    retry = _FlareRetry(
        total=FLARE_HTTP_RETRIES,
        backoff_factor=2,
        status_forcelist=[
            TOO_MANY_REQUESTS,
            SERVER_ERROR,
            502,
            503,
            504,
        ],
        allowed_methods={"GET", "POST", "PATCH"},
    )
    if hasattr(retry, "backoff_max"):
        retry.backoff_max = 60  # type: ignore[attr-defined]
    adapter = _TimeoutHTTPAdapter(
        max_retries=retry,
        timeout=DEFAULT_HTTP_TIMEOUT,
        basic_pace=basic_pace,
        search_pace=search_pace,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class FlareManager:
    """Client for Flare Firework APIs (search, enrich, remediate)."""

    def __init__(
        self,
        api_key: str,
        tenant_id: int,
        api_url: str = DEFAULT_FLARE_API_URL,
        logger_instance=None,
    ) -> None:
        if not api_key:
            raise FlareException("Flare API Key is required.")
        self.api_key = api_key
        self.tenant_id = int(tenant_id or 0)
        self.api_url = (api_url or DEFAULT_FLARE_API_URL).rstrip("/")
        self.logger = logger_instance or logger
        self._session = _build_session(self.api_key, ssl_verify=True)
        # tenant_id scopes Firework API calls to the selected Flare tenant.
        self.client = FlareApiClient(
            api_key=self.api_key,
            tenant_id=self.tenant_id,
            session=self._session,
        )

    def _log(self, level: str, msg: str, *args) -> None:
        safe_log(self.logger, level, msg, *args)

    def _raise_for_status(self, response, context: str = "Flare API request") -> None:
        """Raise a short operator-facing error (no raw payload logging)."""
        status = response.status_code
        if 200 <= status < 300:
            return
        if status == BAD_REQUEST:
            raise FlareBadRequestException(MSG_BAD_REQUEST)
        if status == UNAUTHORIZED:
            raise FlareUnauthorizedException(MSG_UNAUTHORIZED)
        if status == FORBIDDEN:
            raise FlareForbiddenException(MSG_FORBIDDEN)
        if status == NOT_FOUND:
            raise FlareNotFoundException(MSG_NOT_FOUND)
        if status == TOO_MANY_REQUESTS:
            raise FlareRateLimitException(MSG_RATE_LIMIT)
        if status >= SERVER_ERROR:
            raise FlareException(MSG_SERVER_ERROR)
        raise FlareException(f"{context} failed. Please try again.")

    def _refresh_token(self) -> None:
        self.client.generate_token()

    def _invoke(self, method: str, path: str, **kwargs):
        """Call the SDK verb, or its generic request for methods it does not wrap."""
        fn = getattr(self.client, method.lower(), None)
        if callable(fn):
            return fn(path, **kwargs)
        return self.client._request(method=method.upper(), url=path, **kwargs)

    def _request_with_auth_retry(self, method: str, path: str, **kwargs):
        """Execute SDK request; on 401 refresh token and retry once."""
        try:
            resp = self._invoke(method, path, **kwargs)
        except Exception as exc:
            if _is_rate_limit_error(exc):
                raise FlareRateLimitException(MSG_RATE_LIMIT) from exc
            raise
        if resp.status_code == UNAUTHORIZED:
            try:
                self._refresh_token()
            except FlareException:
                raise
            except Exception as exc:
                if _is_rate_limit_error(exc):
                    raise FlareRateLimitException(MSG_RATE_LIMIT) from exc
                raise FlareUnauthorizedException(MSG_UNAUTHORIZED) from exc
            try:
                resp = self._invoke(method, path, **kwargs)
            except Exception as exc:
                if _is_rate_limit_error(exc):
                    raise FlareRateLimitException(MSG_RATE_LIMIT) from exc
                raise
        return resp

    # --- Discovery ---

    def fetch_available_severities(self) -> list:
        try:
            resp = self._request_with_auth_retry("get", ENDPOINT_FILTER_SEVERITIES)
            self._raise_for_status(resp, "Fetch severities")
            return resp.json()
        except Exception as exc:
            self._log(
                "warning",
                "Unable to fetch Flare severity filters: %s",
                format_user_facing_error(exc),
            )
            return []

    def fetch_available_source_types(self) -> list:
        try:
            resp = self._request_with_auth_retry("get", ENDPOINT_FILTER_TYPES)
            self._raise_for_status(resp, "Fetch source types")
            return resp.json()
        except Exception as exc:
            self._log(
                "warning",
                "Unable to fetch Flare source-type filters: %s",
                format_user_facing_error(exc),
            )
            return []

    def list_severity_options(self) -> list:
        """Return [{key, labels}] for severities; falls back to built-in defaults."""
        options = extract_filter_options(self.fetch_available_severities())
        if options:
            return options
        return [{"key": value, "labels": {value}} for value in SEVERITY_OPTIONS]

    def list_source_type_options(self) -> list:
        """Return source-type options from /events/filters/types.

        Leaf types are {key, labels}. Parent categories also appear with
        expand_to=[nested type keys] so category names resolve to all subtypes.
        """
        options = extract_filter_options(
            self.fetch_available_source_types(),
            extra_label_map=TYPE_DISPLAY_NAME,
        )
        if options:
            return options
        return [{"key": key, "labels": {key, display}} for key, display in TYPE_DISPLAY_NAME.items()]

    def fetch_tenants(self) -> list:
        """Tenants this API key can access. Raises on auth/API failure."""
        resp = self._request_with_auth_retry("get", ENDPOINT_TENANTS)
        self._raise_for_status(resp, "Fetch tenants")
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for field in ("tenants", "items", "data", "results"):
                candidate = data.get(field)
                if isinstance(candidate, list):
                    return candidate
            return [data]
        return []

    def validate_tenant(self) -> dict:
        """
        Confirm the configured Tenant ID exists for this API key.

        Flare API keys can reach several tenants, so a syntactically valid ID
        is not enough — it must be one of the accessible tenants.
        """
        tenants = self.fetch_tenants()

        available: list = []
        for tenant in tenants:
            if isinstance(tenant, dict):
                raw_id = tenant.get("id", tenant.get("tenant_id"))
                name = tenant.get("name") or tenant.get("display_name") or ""
            else:
                raw_id, name = tenant, ""
            try:
                tenant_id = int(str(raw_id).strip())
            except (TypeError, ValueError):
                continue
            available.append({"id": tenant_id, "name": str(name)})

        if not available:
            raise FlareValidationException(
                "No Flare tenants are accessible with this API key. Check the API key permissions in Flare."
            )

        for tenant in available:
            if tenant["id"] == self.tenant_id:
                return tenant

        allowed = ", ".join(f"{t['id']}" + (f" ({t['name']})" if t["name"] else "") for t in available)
        raise FlareValidationException(
            f"Flare Tenant ID {self.tenant_id} is not available for this API key. Available tenant ID(s): {allowed}."
        )

    # --- Events ---

    def fetch_events_page(
        self,
        from_token: Optional[str] = None,
        size: int = 10,
        severities: Optional[list] = None,
        source_types: Optional[list] = None,
        start_date: Optional[str] = None,
        start_date_op: str = "gt",
    ) -> dict:
        page_size = cap_page_size(size, MAX_FLARE_PAGE_SIZE)
        search_body: dict = {"size": page_size, "order": "asc"}
        if from_token:
            search_body["from"] = from_token

        filters: dict = {}
        # start_date is the previous run's last event matched_at, not "now".
        if start_date:
            filters["matched_at"] = {start_date_op: start_date}
        if severities:
            filters["severity"] = severities
        if source_types:
            filters["type"] = source_types
        if filters:
            search_body["filters"] = filters

        resp = self._request_with_auth_retry("post", ENDPOINT_EVENTS_SEARCH, json=search_body)
        self._raise_for_status(resp, "Event search")
        return resp.json()

    def enrich_event(self, event: dict) -> dict:
        """Merge full event detail onto the search-result event."""
        uid = (event.get("metadata") or {}).get("uid")
        if not uid:
            return event

        encoded_uid = urllib.parse.quote(uid, safe="")
        try:
            resp = self._request_with_auth_retry("get", f"{ENDPOINT_EVENTS_DETAIL}?uid={encoded_uid}")
            self._raise_for_status(resp, f"Enrich event {uid}")
            full_detail = resp.json()
            if not isinstance(full_detail, dict):
                return event

            if "data" in full_detail:
                event["data"] = full_detail["data"]
            if full_detail.get("event_type"):
                event["event_type"] = full_detail["event_type"]

            detail_meta = full_detail.get("metadata")
            if isinstance(detail_meta, dict):
                merged = dict(event.get("metadata") or {})
                for key, value in detail_meta.items():
                    if value is not None:
                        merged[key] = value
                event["metadata"] = merged
        except (FlareException, requests.exceptions.HTTPError, Exception) as exc:
            # Keep the base search event; one warning (no response body).
            self._log(
                "warning",
                "Unable to enrich Flare event uid=%s: %s",
                uid,
                format_user_facing_error(exc),
            )

        return event

    def apply_event_action(self, action: str, uids: list) -> dict:
        """
        POST /firework/v4/events/actions.

        payload = {
          "action": {"type": "remediate"},
          "targets": [{"uid": "<metadata.uid>"}, ...]
        }
        """
        if not uids:
            return {"status_code": 200, "json": {}}

        payload = {
            "action": {"type": action},
            "targets": [{"uid": uid} for uid in uids],
        }
        self._log(
            "info",
            "Flare event-actions %s targets=%d uids=%s",
            action,
            len(uids),
            uids,
        )
        resp = self._request_with_auth_retry("post", ENDPOINT_EVENT_ACTIONS, json=payload)
        try:
            body = resp.json()
        except Exception:
            body = {}
        self._log(
            "info",
            "Flare event-actions %s status=%s targets=%d",
            action,
            resp.status_code,
            len(uids),
        )
        return {"status_code": resp.status_code, "text": resp.text, "json": body}

    def remediate_events(self, uids: list, batch_size: int = 10) -> dict:
        """Remediate Flare events in batches with 401 retry."""
        applied = 0
        errors: list = []
        size = max(1, int(batch_size))
        applied_uids: list = []

        for i in range(0, len(uids), size):
            batch = uids[i : i + size]
            try:
                result = self.apply_event_action("remediate", batch)
                if result.get("status_code") == UNAUTHORIZED:
                    self._refresh_token()
                    result = self.apply_event_action("remediate", batch)

                status = int(result.get("status_code") or 500)
                if status >= 400:
                    raise FlareException(f"Flare remediate failed (HTTP {status}).")
                applied += len(batch)
                applied_uids.extend(batch)
            except Exception as exc:
                friendly = format_user_facing_error(exc)
                errors.append(friendly)
                self._log("error", friendly)

        return {"applied": applied, "applied_uids": applied_uids, "errors": errors}

    # --- Shared request / pagination helpers for actions ---

    @staticmethod
    def _quote(value: str) -> str:
        return urllib.parse.quote(str(value).strip(), safe="")

    def _call(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
        context: str = "Flare API request",
    ):
        """
        Single request path for actions.

        Goes through pacing, 429/5xx retry and the 401 token refresh, then maps
        HTTP errors to typed exceptions and returns the decoded JSON body
        (``{}`` when the body is empty).
        """
        kwargs: dict = {}
        if params:
            kwargs["params"] = params
        if json is not None:
            kwargs["json"] = json
        resp = self._request_with_auth_retry(method, path, **kwargs)
        self._raise_for_status(resp, context)
        try:
            return resp.json()
        except ValueError:
            return {}

    @staticmethod
    def _extract_items(data) -> list:
        """Return the record list from a list/dict page response."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for field in ("items", "data", "results", "entities", "identifiers", "alerts", "channels"):
                candidate = data.get(field)
                if isinstance(candidate, list):
                    return candidate
        return []

    def _paginate_cursor(
        self,
        method: str,
        path: str,
        *,
        body: dict,
        max_records: int,
        page_size: int = MAX_FLARE_PAGE_SIZE,
        context: str = "Flare API request",
    ) -> list:
        """Cursor pagination: the response ``next`` token is sent back as ``from``."""
        items: list = []
        cursor: Optional[str] = None
        while len(items) < max_records:
            payload = dict(body)
            payload["size"] = min(page_size, max_records - len(items))
            if cursor:
                payload["from"] = cursor
            data = self._call(method, path, json=payload, context=context)
            page = self._extract_items(data)
            items.extend(page)
            cursor = data.get("next") if isinstance(data, dict) else None
            if not cursor or not page:
                break
        return items[:max_records]

    def _paginate_offset(
        self,
        path: str,
        *,
        params: Optional[dict],
        max_records: int,
        page_size: int = OFFSET_PAGE_SIZE,
        context: str = "Flare API request",
    ) -> list:
        """limit/offset pagination; stops on a short or empty page."""
        items: list = []
        offset = 0
        base = {k: v for k, v in (params or {}).items() if v not in (None, "")}
        while len(items) < max_records:
            limit = min(page_size, max_records - len(items))
            data = self._call(
                "get",
                path,
                params={**base, "limit": limit, "offset": offset},
                context=context,
            )
            page = self._extract_items(data)
            items.extend(page)
            if len(page) < limit:
                break
            offset += limit
        return items[:max_records]

    # --- Events (actions) ---

    def get_event_details(self, uid: str) -> dict:
        return self._call(
            "get",
            ENDPOINT_EVENTS_DETAIL,
            params={"uid": str(uid).strip()},
            context="Get event details",
        )

    def get_event_field_details(self, uid: str, field_path: str) -> dict:
        return self._call(
            "get",
            ENDPOINT_EVENTS_EXPAND,
            params={"uid": str(uid).strip(), "field_path": str(field_path).strip()},
            context="Get event field details",
        )

    def get_event_ai_insights(self, uid: str) -> dict:
        return self._call(
            "get",
            ENDPOINT_EVENTS_AI_ASSISTANCE,
            params={"uid": str(uid).strip()},
            context="Get event AI insights",
        )

    def explain_identifier_match(self, uid: str, identifier_id: str) -> dict:
        return self._call(
            "get",
            ENDPOINT_EVENTS_EXPLAIN_IDENTIFIER,
            params={"uid": str(uid).strip(), "identifier_id": str(identifier_id).strip()},
            context="Explain identifier match",
        )

    def execute_event_action(self, action: str, uids: list) -> dict:
        """POST /firework/v4/events/actions for up to MAX_EVENT_ACTION_TARGETS UIDs."""
        action_type = str(action or "").strip().lower()
        if action_type not in EVENT_ACTION_TYPES:
            raise FlareValidationException(
                f"Invalid Action Type: {action}. Valid values: {', '.join(EVENT_ACTION_TYPES)}."
            )
        targets = list(dict.fromkeys(str(u).strip() for u in uids if str(u).strip()))
        if not targets:
            raise FlareValidationException("At least one Event UID is required.")
        if len(targets) > MAX_EVENT_ACTION_TARGETS:
            raise FlareValidationException(
                f"A maximum of {MAX_EVENT_ACTION_TARGETS} Event UIDs can be "
                f"processed per execution. Received {len(targets)}."
            )
        payload = {
            "action": {"type": action_type},
            "targets": [{"uid": uid} for uid in targets],
        }
        self._log("info", "Flare execute event action %s targets=%d", action_type, len(targets))
        return self._call("post", ENDPOINT_EVENT_ACTIONS, json=payload, context="Execute event action")

    def execute_credential_action(self, action: str, credential_ids: list) -> dict:
        """POST /events/credential-actions for leaked credentials inside events."""
        action_type = str(action or "").strip().lower()
        if not action_type:
            raise FlareValidationException("Action Type is required.")
        targets = list(dict.fromkeys(str(item).strip() for item in credential_ids if str(item).strip()))
        if not targets:
            raise FlareValidationException("At least one Credential ID is required.")
        payload = {"action": {"type": action_type}, "credential_ids": targets}
        self._log("info", "Flare credential action %s targets=%d", action_type, len(targets))
        return self._call(
            "post",
            ENDPOINT_EVENTS_CREDENTIAL_ACTIONS,
            json=payload,
            context="Execute credential action",
        )

    def update_tenant_metadata(
        self,
        uid: str,
        severity: Optional[str] = None,
        tags: Optional[list] = None,
        notes: Optional[str] = None,
    ) -> dict:
        """PATCH /events/tenant-metadata for one event. Only supplied fields are sent."""
        body: dict = {}
        if severity and str(severity).strip():
            value = str(severity).strip().lower()
            if value not in SEVERITY_OPTIONS:
                raise FlareValidationException(
                    f"Invalid Severity: {severity}. Valid values: {', '.join(SEVERITY_OPTIONS)}."
                )
            body["severity"] = value
        if tags:
            body["tags"] = list(tags)
        if notes is not None and str(notes).strip():
            body["notes"] = str(notes).strip()
        if not body:
            raise FlareValidationException("Set at least one of Severity, Tags, or Notes.")
        return self._call(
            "patch",
            ENDPOINT_EVENTS_TENANT_METADATA,
            params={"uid": str(uid).strip()},
            json=body,
            context="Update tenant metadata",
        )

    # --- Global search ---

    def search_global(
        self,
        query: str,
        categories: Optional[list] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        max_records: int = 50,
    ) -> list:
        body: dict = {"query": {"type": "query_string", "query": query}}
        filters: dict = {}
        if categories:
            filters["type"] = list(categories)
        date_range: dict = {}
        if from_date:
            date_range["gte"] = from_date
        if to_date:
            date_range["lte"] = to_date
        if date_range:
            filters["estimated_created_at"] = date_range
        if filters:
            body["filters"] = filters
        return self._paginate_cursor(
            "post",
            ENDPOINT_GLOBAL_SEARCH,
            body=body,
            max_records=max_records,
            context="Global search",
        )

    def get_global_search_quota(self) -> dict:
        return self._call("get", ENDPOINT_GLOBAL_SEARCH_QUOTA, context="Get global search quota")

    # --- Identifiers ---

    def list_identifiers(
        self,
        identifier_type: Optional[str] = None,
        status: Optional[str] = None,
        max_records: int = 50,
    ) -> list:
        return self._paginate_offset(
            ENDPOINT_IDENTIFIERS,
            params={"type": identifier_type, "status": status},
            max_records=max_records,
            context="List identifiers",
        )

    def get_identifier(self, identifier_id: str) -> dict:
        return self._call(
            "get",
            f"{ENDPOINT_IDENTIFIERS}{self._quote(identifier_id)}",
            context="Get identifier details",
        )

    def set_identifier_status(self, identifier_id: str, enabled: bool) -> dict:
        return self._call(
            "post",
            f"{ENDPOINT_IDENTIFIERS}{self._quote(identifier_id)}/status",
            json={"enabled": bool(enabled)},
            context="Set identifier status",
        )

    # --- Alerts ---

    def list_alerts(self, max_records: int = 50) -> list:
        return self._paginate_offset(ENDPOINT_ALERTS, params=None, max_records=max_records, context="List alerts")

    def get_alert(self, alert_id: str) -> dict:
        return self._call("get", f"{ENDPOINT_ALERTS}{self._quote(alert_id)}", context="Get alert details")

    def list_alert_channels(self, channel_type: Optional[str] = None) -> list:
        params = {"type": channel_type} if channel_type else None
        data = self._call("get", ENDPOINT_ALERT_CHANNELS, params=params, context="List alert channels")
        return self._extract_items(data)

    # --- Entities ---

    def list_entities(
        self,
        entity_type: Optional[str] = None,
        query: Optional[str] = None,
        max_records: int = 50,
    ) -> list:
        """POST /entities/_list, paged with limit/offset in the request body."""
        items: list = []
        offset = 0
        while len(items) < max_records:
            limit = min(OFFSET_PAGE_SIZE, max_records - len(items))
            body: dict = {"tenant_id": self.tenant_id, "limit": limit, "offset": offset}
            if entity_type:
                body["type"] = entity_type
            if query:
                body["query"] = query
            data = self._call("post", ENDPOINT_ENTITIES_LIST, json=body, context="List entities")
            page = self._extract_items(data)
            items.extend(page)
            if len(page) < limit:
                break
            offset += limit
        return items[:max_records]

    def get_entity(self, entity_id: str) -> dict:
        return self._call("get", f"{ENDPOINT_ENTITIES}{self._quote(entity_id)}", context="Get entity details")

    def list_entity_relations(
        self,
        entity_id: str,
        relation_types: Optional[list] = None,
        max_records: int = 50,
    ) -> list:
        """POST /entities/relations, paged with limit/offset in the request body."""
        items: list = []
        offset = 0
        while len(items) < max_records:
            limit = min(OFFSET_PAGE_SIZE, max_records - len(items))
            body: dict = {
                "entity_id": str(entity_id).strip(),
                "tenant_id": self.tenant_id,
                "limit": limit,
                "offset": offset,
            }
            if relation_types:
                body["relation_types"] = list(relation_types)
            data = self._call("post", ENDPOINT_ENTITIES_RELATIONS, json=body, context="List entity relations")
            page = self._extract_items(data)
            items.extend(page)
            if len(page) < limit:
                break
            offset += limit
        return items[:max_records]

    def test_connection(self, validate_tenant: bool = True) -> bool:
        """Authenticate with the API key, then confirm the tenant is reachable.

        Token generation is probed without a tenant binding first so a bad
        Tenant ID is not reported as an Invalid API Key.
        """
        # 1) Prove the API key works (no tenant scope).
        try:
            auth_client = FlareApiClient(
                api_key=self.api_key,
                session=self._session,
            )
            auth_client.generate_token()
        except FlareException:
            raise
        except Exception as exc:
            if _is_rate_limit_error(exc):
                raise FlareRateLimitException(MSG_RATE_LIMIT) from exc
            raise FlareUnauthorizedException(MSG_UNAUTHORIZED) from exc

        # 2) Bind the configured tenant and confirm it is accessible.
        # After the API key is known-good, treat auth/forbidden failures for the
        # tenant-scoped client as a Tenant ID problem (not a bad API key).
        tenant_error = FlareValidationException(
            f"Flare Tenant ID {self.tenant_id} is not valid for this API key. Check the tenant ID and try again."
        )
        if validate_tenant:
            try:
                self.client.generate_token()
                self.validate_tenant()
            except FlareValidationException:
                raise
            except (FlareUnauthorizedException, FlareForbiddenException) as exc:
                raise tenant_error from exc
            except FlareException:
                raise
            except Exception as exc:
                if _is_rate_limit_error(exc):
                    raise FlareRateLimitException(MSG_RATE_LIMIT) from exc
                raise tenant_error from exc
        else:
            try:
                self.client.generate_token()
            except FlareException:
                raise
            except Exception as exc:
                if _is_rate_limit_error(exc):
                    raise FlareRateLimitException(MSG_RATE_LIMIT) from exc
                raise FlareUnauthorizedException(MSG_UNAUTHORIZED) from exc
        return True
