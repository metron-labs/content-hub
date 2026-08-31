"""
Vega HTTP manager: login_machine session JWT + GraphQL /api/v1/query.

Does not import the SecOps SDK.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from .constants import (
    ALERT_EVENTS_MAX_FETCH,
    ALERT_EVENTS_PAGE_SIZE,
    DEFAULT_HTTP_TIMEOUT,
    GET_ALERT_EVENTS_QUERY,
    GET_ALERTS_QUERY,
    GET_INCIDENT_TIMELINE_QUERY,
    GET_INCIDENTS_QUERY,
    GRAPHQL_PAGE_SIZE,
    LOGIN_PATH,
    MSG_BAD_REQUEST,
    MSG_FORBIDDEN,
    MSG_INVALID_ACCESS_KEY,
    MSG_INVALID_ACCESS_KEY_ID,
    MSG_INVALID_API_ROOT,
    MSG_NOT_FOUND,
    MSG_RATE_LIMIT,
    MSG_SERVER_ERROR,
    QUERY_PATH,
    SERVER_ERROR_RETRIES,
    SERVER_ERROR_WAIT_SECONDS,
    SET_DETECTIONS_STATE_MUTATION,
    TIMELINE_MAX_FETCH,
    TIMELINE_PAGE_SIZE,
    UPDATE_ALERTS_MUTATION,
    UPDATE_DETECTIONS_MUTATION,
    UPDATE_INCIDENTS_MUTATION,
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
from .rate_limit import RateLimitController
from .utils import classify_credential_error, normalize_api_root, require_secret, safe_log

logger = logging.getLogger(__name__)


def parse_alert_events_results(results: Any) -> list[dict]:
    """Normalize getAlertsEvents `results` (list, dict, or JSON string) into event dicts."""
    if results is None or results == "":
        return []
    if isinstance(results, str):
        text = results.strip()
        if not text:
            return []
        try:
            results = json.loads(text)
        except json.JSONDecodeError:
            return []
    if isinstance(results, dict):
        for key in ("results", "events", "items", "data", "rows"):
            nested = results.get(key)
            if isinstance(nested, list):
                results = nested
                break
        else:
            results = [results]
    if not isinstance(results, list):
        return []
    parsed: list[dict] = []
    for item in results:
        if isinstance(item, str):
            try:
                item = json.loads(item)
            except json.JSONDecodeError:
                continue
        if isinstance(item, dict):
            parsed.append(item)
    return parsed


def _requests():
    import requests

    return requests


class VegaManager:
    """Client for Vega login and GraphQL APIs."""

    def __init__(
        self,
        api_root: str,
        access_key_id: str,
        access_key: str,
        verify_ssl: bool = True,
        timeout=DEFAULT_HTTP_TIMEOUT,
        logger_instance=None,
        session=None,
        rate_limiter: Optional[RateLimitController] = None,
        sleeper=None,
    ) -> None:
        self.api_root = normalize_api_root(api_root)
        self.access_key_id = require_secret(access_key_id, "Access Key ID")
        self.access_key = require_secret(access_key, "Access Key")
        self.verify_ssl = bool(verify_ssl)
        self.timeout = timeout
        self.logger = logger_instance or logger
        self.session = session or _requests().Session()
        self.session.trust_env = False
        self.session.verify = self.verify_ssl
        self.rate_limiter = rate_limiter or RateLimitController(
            sleeper=sleeper or __import__("time").sleep
        )
        self._sleeper = sleeper or __import__("time").sleep
        self._jwt: Optional[str] = None

    def _log(self, level: str, msg: str, *args) -> None:
        safe_log(self.logger, level, msg, *args)

    def _url(self, path: str) -> str:
        return f"{self.api_root}{path}"

    def _response_error_text(self, response) -> str:
        try:
            payload = response.json()
        except Exception:
            return str(getattr(response, "text", "") or "")
        if isinstance(payload, dict):
            error = payload.get("error") or payload.get("errors") or payload.get("message")
            if isinstance(error, dict):
                return str(error.get("message") or error.get("code") or error)
            if isinstance(error, list) and error:
                first = error[0]
                if isinstance(first, dict):
                    return str(first.get("message") or first.get("code") or first)
                return str(first)
            if error:
                return str(error)
            return str(payload)
        return str(payload)

    def _raise_http(self, response, path: str = "") -> None:
        status = response.status_code
        classified = classify_credential_error(self._response_error_text(response))
        if classified:
            raise VegaUnauthorizedException(classified)
        if path == LOGIN_PATH:
            if status == 400:
                raise VegaUnauthorizedException(MSG_INVALID_ACCESS_KEY_ID)
            if status == 404:
                raise VegaValidationException(MSG_INVALID_API_ROOT)
            if status in (401, 403) or status >= 500:
                raise VegaUnauthorizedException(MSG_INVALID_ACCESS_KEY)
        if status == 400:
            raise VegaBadRequestException(MSG_BAD_REQUEST)
        if status == 401:
            raise VegaUnauthorizedException(MSG_INVALID_ACCESS_KEY_ID)
        if status == 403:
            raise VegaForbiddenException(MSG_FORBIDDEN)
        if status == 404:
            raise VegaNotFoundException(MSG_NOT_FOUND)
        if status == 429:
            raise VegaRateLimitException(MSG_RATE_LIMIT)
        if status >= 500:
            raise VegaException(MSG_SERVER_ERROR)
        raise VegaException("Vega request failed. Please try again.")

    def _send(self, method: str, path: str, **kwargs):
        requests = _requests()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        try:
            return self.session.request(method, self._url(path), **kwargs)
        except requests.Timeout as exc:
            raise VegaTimeoutException(MSG_INVALID_API_ROOT) from exc
        except requests.exceptions.SSLError as exc:
            raise VegaValidationException(MSG_INVALID_API_ROOT) from exc
        except requests.ConnectionError as exc:
            raise VegaValidationException(MSG_INVALID_API_ROOT) from exc

    def _request(self, method: str, path: str, allow_relogin: bool = True, **kwargs):
        server_attempts = 0
        while True:
            response = self._send(method, path, **kwargs)
            status = response.status_code
            if status == 429:
                wait = self.rate_limiter.on_429()
                self._log("warning", "Vega HTTP 429; waiting %s seconds.", wait)
                continue
            if status >= 500:
                if path == LOGIN_PATH:
                    self._raise_http(response, path)
                server_attempts += 1
                if server_attempts <= SERVER_ERROR_RETRIES:
                    self._sleeper(SERVER_ERROR_WAIT_SECONDS)
                    continue
                self._raise_http(response, path)
            if status == 401 and allow_relogin and path != LOGIN_PATH:
                self._jwt = None
                self.login()
                headers = dict(kwargs.get("headers") or {})
                headers.update(self._auth_headers())
                kwargs["headers"] = headers
                allow_relogin = False
                continue
            if not (200 <= status < 300):
                self._raise_http(response, path)
            self.rate_limiter.on_success()
            return response

    def _auth_headers(self) -> dict:
        if not self._jwt:
            self.login()
        return {
            "Content-Type": "application/json",
            "JWTSessionToken": self._jwt,
            "X-Vega-Key-Id": self.access_key_id,
        }

    def login(self) -> str:
        response = self._request(
            "POST",
            LOGIN_PATH,
            allow_relogin=False,
            headers={
                "Content-Type": "application/json",
                "X-Vega-Key-Id": self.access_key_id,
            },
            json={"access_key": self.access_key},
        )
        try:
            payload = response.json()
        except Exception as exc:
            raise VegaValidationException(MSG_INVALID_API_ROOT) from exc
        token = (
            payload.get("session_jwt")
            or payload.get("sessionJwt")
            or payload.get("token")
        )
        if not token:
            raise VegaUnauthorizedException(MSG_INVALID_ACCESS_KEY)
        self._jwt = str(token)
        return self._jwt

    def graphql(self, query: str, variables: Optional[dict] = None) -> dict:
        response = self._request(
            "POST",
            QUERY_PATH,
            headers=self._auth_headers(),
            json={"query": query, "variables": variables or {}},
        )
        try:
            payload = response.json()
        except Exception as exc:
            raise VegaException("Vega GraphQL returned a non-JSON body.") from exc
        if payload.get("errors"):
            message = payload["errors"][0].get("message") if payload["errors"] else ""
            classified = classify_credential_error(message)
            if classified:
                raise VegaUnauthorizedException(classified)
            raise VegaException("Vega request failed. Please try again.")
        return payload.get("data") or {}

    def test_connection(self) -> bool:
        """Validate API Root, Access Key, and Access Key ID before ingest."""
        self.login()
        try:
            self.get_alerts({"limit": 1, "offset": 0}, max_records=1)
        except VegaBadRequestException as exc:
            raise VegaUnauthorizedException(MSG_INVALID_ACCESS_KEY_ID) from exc
        return True

    def _paged(
        self,
        query: str,
        envelope_key: str,
        records_key: str,
        variables: dict,
        max_records: Optional[int] = None,
    ) -> list:
        collected: list = []
        offset = 0
        while True:
            if max_records is not None and len(collected) >= max_records:
                break
            page_size = GRAPHQL_PAGE_SIZE
            if max_records is not None:
                page_size = min(GRAPHQL_PAGE_SIZE, max_records - len(collected))
                if page_size <= 0:
                    break
            page_vars = dict(variables)
            page_vars["limit"] = page_size
            page_vars["offset"] = offset
            data = self.graphql(query, page_vars)
            envelope = data.get(envelope_key) or {}
            error = envelope.get("error") or envelope.get("errors") or {}
            if isinstance(error, dict) and (error.get("code") or error.get("message")):
                message = error.get("message") or "Vega query failed."
                classified = classify_credential_error(message)
                if classified:
                    raise VegaUnauthorizedException(classified)
                raise VegaException(message)
            if isinstance(error, list) and error:
                message = error[0].get("message") if isinstance(error[0], dict) else str(error[0])
                classified = classify_credential_error(message)
                if classified:
                    raise VegaUnauthorizedException(classified)
                raise VegaException(message or "Vega query failed.")
            records = envelope.get(records_key) or []
            if not records:
                break
            collected.extend(records)
            offset += len(records)
            total = envelope.get("total")
            if total is not None and offset >= int(total):
                break
            if len(records) < page_vars["limit"]:
                break
        if max_records is not None:
            return collected[:max_records]
        return collected

    def get_alerts(self, variables: dict, max_records: Optional[int] = None) -> list:
        return self._paged(
            GET_ALERTS_QUERY, "getAlerts", "alerts", variables, max_records
        )

    def get_incidents(self, variables: dict, max_records: Optional[int] = None) -> list:
        return self._paged(
            GET_INCIDENTS_QUERY, "getIncidents", "incidents", variables, max_records
        )

    def get_alert_events(
        self, alert_id: str, limit: int = ALERT_EVENTS_PAGE_SIZE, offset: int = 0
    ) -> dict:
        data = self.graphql(
            GET_ALERT_EVENTS_QUERY,
            {"alertId": alert_id, "limit": limit, "offset": offset},
        )
        envelope = data.get("getAlertsEvents") or {}
        if not isinstance(envelope, dict):
            return {}
        envelope = dict(envelope)
        envelope["results"] = parse_alert_events_results(envelope.get("results"))
        return envelope

    def _collect_paged(
        self,
        fetch_page,
        records_key: str,
        page_size: int,
        max_records: int,
        label: str,
    ) -> list:
        collected: list = []
        offset = 0
        total: Optional[int] = None
        while len(collected) < max_records:
            request_size = min(max(int(page_size or 1), 1), max_records - len(collected))
            try:
                envelope = fetch_page(request_size, offset)
            except Exception:
                if collected:
                    break
                raise
            if not isinstance(envelope, dict):
                envelope = {}
            error = envelope.get("error") or {}
            if isinstance(error, dict) and (error.get("code") or error.get("message")):
                if collected:
                    self._log(
                        "warning",
                        "Stopped paging Vega %s after %s row(s): %s",
                        label,
                        len(collected),
                        error.get("message") or error.get("code"),
                    )
                    break
                raise VegaException(
                    error.get("message") or f"{label} fetch failed."
                )
            records = envelope.get(records_key) or []
            if isinstance(records, dict):
                records = [records]
            if not isinstance(records, list) or not records:
                break
            collected.extend(records)
            offset += len(records)
            page_total = envelope.get("total")
            if page_total is not None:
                try:
                    parsed_total = int(page_total)
                    if parsed_total > 0:
                        total = parsed_total
                except (TypeError, ValueError):
                    pass
            if total is not None and offset >= total:
                break
        return collected[:max_records]

    def get_all_alert_events(
        self,
        alert_id: str,
        page_size: int = ALERT_EVENTS_PAGE_SIZE,
    ) -> list:
        return self._collect_paged(
            lambda limit, offset: self.get_alert_events(alert_id, limit, offset),
            "results",
            page_size,
            ALERT_EVENTS_MAX_FETCH,
            f"alert events for {alert_id}",
        )

    def get_incident_timeline(
        self,
        incident_id: str,
        limit: int = TIMELINE_PAGE_SIZE,
        offset: int = 0,
    ) -> dict:
        data = self.graphql(
            GET_INCIDENT_TIMELINE_QUERY,
            {"incidentId": incident_id, "limit": limit, "offset": offset},
        )
        envelope = data.get("getIncidentTimeline") or {}
        if not isinstance(envelope, dict):
            return {}
        envelope = dict(envelope)
        events = envelope.get("events") or []
        if isinstance(events, dict):
            events = [events]
        if not isinstance(events, list):
            events = []
        envelope["events"] = [item for item in events if isinstance(item, dict)]
        return envelope

    def get_all_incident_timeline(
        self,
        incident_id: str,
        page_size: int = TIMELINE_PAGE_SIZE,
    ) -> list:
        return self._collect_paged(
            lambda limit, offset: self.get_incident_timeline(
                incident_id, limit, offset
            ),
            "events",
            page_size,
            TIMELINE_MAX_FETCH,
            f"incident timeline for {incident_id}",
        )

    def get_incident(self, incident_id: str) -> dict:
        lookup = str(incident_id).strip()
        records = self.get_incidents(
            {
                "incidentIds": [lookup],
                "from": None,
                "to": None,
                "updatedFrom": None,
                "updatedTo": None,
            },
            max_records=1,
        )
        if records:
            return records[0]
        records = self.get_incidents(
            {
                "vegaIncidentIds": [lookup],
                "from": None,
                "to": None,
                "updatedFrom": None,
                "updatedTo": None,
            },
            max_records=1,
        )
        return records[0] if records else {}

    def set_detections_state(self, ids: list[str], state: str) -> dict:
        data = self.graphql(
            SET_DETECTIONS_STATE_MUTATION,
            {"input": {"ids": ids, "state": state}},
        )
        return data.get("setDetectionsState") or {}

    def update_detections(self, detections: list[dict]) -> dict:
        data = self.graphql(
            UPDATE_DETECTIONS_MUTATION,
            {"input": {"detections": detections}},
        )
        return data.get("updateDetections") or {}

    def update_alerts(self, payload: dict) -> dict:
        data = self.graphql(UPDATE_ALERTS_MUTATION, {"input": payload})
        envelope = data.get("updateAlerts") or {}
        error = envelope.get("error") or {}
        if error.get("code") or error.get("message"):
            raise VegaException(error.get("message") or "updateAlerts failed.")
        return envelope

    def update_incidents(self, payload: dict) -> dict:
        data = self.graphql(UPDATE_INCIDENTS_MUTATION, {"input": payload})
        envelope = data.get("updateIncidents") or {}
        errors = envelope.get("errors") or []
        if errors:
            message = errors[0].get("message") if isinstance(errors[0], dict) else str(errors[0])
            raise VegaException(message or "updateIncidents failed.")
        return envelope
