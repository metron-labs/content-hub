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
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from flareio import FlareApiClient

from .constants import (
    BAD_REQUEST,
    DEFAULT_FLARE_API_URL,
    DEFAULT_HTTP_TIMEOUT,
    ENDPOINT_EVENT_ACTIONS,
    ENDPOINT_EVENTS_DETAIL,
    ENDPOINT_EVENTS_SEARCH,
    ENDPOINT_FILTER_SEVERITIES,
    ENDPOINT_FILTER_TYPES,
    ENDPOINT_TENANTS,
    FLARE_BASIC_REQUESTS_PER_SECOND,
    FLARE_HTTP_RETRIES,
    FLARE_RATE_LIMIT_RETRY_WAIT_SECONDS,
    FLARE_SEARCH_REQUESTS_PER_SECOND,
    FORBIDDEN,
    MAX_FLARE_PAGE_SIZE,
    MSG_BAD_REQUEST,
    MSG_FORBIDDEN,
    MSG_NOT_FOUND,
    MSG_RATE_LIMIT,
    MSG_SERVER_ERROR,
    MSG_UNAUTHORIZED,
    NOT_FOUND,
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
        pace = (
            self._search_pace
            if _is_search_url(getattr(request, "url", ""))
            else self._basic_pace
        )
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
        allowed_methods={"GET", "POST"},
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

    def _request_with_auth_retry(self, method: str, path: str, **kwargs):
        """Execute SDK request; on 401 refresh token and retry once."""
        fn = getattr(self.client, method.lower())
        try:
            resp = fn(path, **kwargs)
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
                resp = fn(path, **kwargs)
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
        return [
            {"key": key, "labels": {key, display}}
            for key, display in TYPE_DISPLAY_NAME.items()
        ]

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
                "No Flare tenants are accessible with this API key. "
                "Check the API key permissions in Flare."
            )

        for tenant in available:
            if tenant["id"] == self.tenant_id:
                return tenant

        allowed = ", ".join(
            f"{t['id']}" + (f" ({t['name']})" if t["name"] else "") for t in available
        )
        raise FlareValidationException(
            f"Flare Tenant ID {self.tenant_id} is not available for this API key. "
            f"Available tenant ID(s): {allowed}."
        )

    # --- Events ---

    def fetch_events_page(
        self,
        from_token: Optional[str] = None,
        size: int = 10,
        severities: Optional[list] = None,
        source_types: Optional[list] = None,
        start_date: Optional[str] = None,
        start_date_op: str = "gte",
    ) -> dict:
        page_size = cap_page_size(size, MAX_FLARE_PAGE_SIZE)
        search_body: dict = {"size": page_size, "order": "asc"}
        if from_token:
            search_body["from"] = from_token

        filters: dict = {}
        if start_date:
            filters["estimated_created_at"] = {start_date_op: start_date}
        if severities:
            filters["severity"] = severities
        if source_types:
            filters["type"] = source_types
        if filters:
            search_body["filters"] = filters

        resp = self._request_with_auth_retry(
            "post", ENDPOINT_EVENTS_SEARCH, json=search_body
        )
        self._raise_for_status(resp, "Event search")
        return resp.json()

    def enrich_event(self, event: dict) -> dict:
        """Merge full event detail onto the search-result event."""
        uid = (event.get("metadata") or {}).get("uid")
        if not uid:
            return event

        encoded_uid = urllib.parse.quote(uid, safe="")
        try:
            resp = self._request_with_auth_retry(
                "get", f"{ENDPOINT_EVENTS_DETAIL}?uid={encoded_uid}"
            )
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
        resp = self._request_with_auth_retry(
            "post", ENDPOINT_EVENT_ACTIONS, json=payload
        )
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
                    raise FlareException(
                        f"Flare remediate failed (HTTP {status})."
                    )
                applied += len(batch)
                applied_uids.extend(batch)
            except Exception as exc:
                friendly = format_user_facing_error(exc)
                errors.append(friendly)
                self._log("error", friendly)

        return {"applied": applied, "applied_uids": applied_uids, "errors": errors}

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
            f"Flare Tenant ID {self.tenant_id} is not valid for this API key. "
            "Check the tenant ID and try again."
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
