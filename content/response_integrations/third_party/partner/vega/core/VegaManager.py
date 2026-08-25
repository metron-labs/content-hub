"""
Vega HTTP manager: login_machine session JWT + GraphQL /api/v1/query.

Does not import the SecOps SDK.
"""
from __future__ import annotations

import logging
from typing import Optional

from .constants import (
    ALERT_EVENTS_PAGE_SIZE,
    DEFAULT_API_ROOT,
    DEFAULT_HTTP_TIMEOUT,
    GET_ALERT_EVENTS_QUERY,
    GET_ALERTS_QUERY,
    GET_INCIDENT_TIMELINE_QUERY,
    GET_INCIDENTS_QUERY,
    GRAPHQL_PAGE_SIZE,
    LOGIN_PATH,
    MSG_BAD_REQUEST,
    MSG_FORBIDDEN,
    MSG_NOT_FOUND,
    MSG_RATE_LIMIT,
    MSG_SERVER_ERROR,
    MSG_UNAUTHORIZED,
    QUERY_PATH,
    SERVER_ERROR_RETRIES,
    SERVER_ERROR_WAIT_SECONDS,
    SET_DETECTIONS_STATE_MUTATION,
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
)
from .rate_limit import RateLimitController
from .utils import normalize_api_root, require_secret, safe_log

logger = logging.getLogger(__name__)


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
        self.api_root = normalize_api_root(api_root or DEFAULT_API_ROOT)
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

    def _raise_http(self, status: int) -> None:
        if status == 400:
            raise VegaBadRequestException(MSG_BAD_REQUEST)
        if status == 401:
            raise VegaUnauthorizedException(MSG_UNAUTHORIZED)
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
            raise VegaTimeoutException("Connection to Vega timed out.") from exc
        except requests.ConnectionError as exc:
            raise VegaException(
                "Unable to reach the Vega API. Check API Root and network access."
            ) from exc

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
                server_attempts += 1
                if server_attempts <= SERVER_ERROR_RETRIES:
                    self._sleeper(SERVER_ERROR_WAIT_SECONDS)
                    continue
                self._raise_http(status)
            if status == 401 and allow_relogin and path != LOGIN_PATH:
                self._jwt = None
                self.login()
                headers = dict(kwargs.get("headers") or {})
                headers.update(self._auth_headers())
                kwargs["headers"] = headers
                allow_relogin = False
                continue
            if not (200 <= status < 300):
                self._raise_http(status)
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
            json={"access_key": self.access_key},
        )
        try:
            payload = response.json()
        except Exception as exc:
            raise VegaException("Vega login returned a non-JSON body.") from exc
        token = (
            payload.get("session_jwt")
            or payload.get("sessionJwt")
            or payload.get("token")
        )
        if not token:
            raise VegaUnauthorizedException(MSG_UNAUTHORIZED)
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
            raise VegaException(message or "Vega GraphQL returned errors.")
        return payload.get("data") or {}

    def test_connection(self) -> bool:
        """Reach Vega with login_machine only. Test does not run GraphQL."""
        self.login()
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
                raise VegaException(error.get("message") or "Vega query failed.")
            if isinstance(error, list) and error:
                raise VegaException(error[0].get("message") or "Vega query failed.")
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

    def get_alert_events(self, alert_id: str, limit: int = 200, offset: int = 0) -> dict:
        data = self.graphql(
            GET_ALERT_EVENTS_QUERY,
            {"alertId": alert_id, "limit": limit, "offset": offset},
        )
        return data.get("getAlertsEvents") or {}

    def get_all_alert_events(
        self, alert_id: str, page_size: int = ALERT_EVENTS_PAGE_SIZE
    ) -> list:
        collected: list = []
        offset = 0
        while True:
            envelope = self.get_alert_events(alert_id, limit=page_size, offset=offset)
            error = envelope.get("error") or {}
            if isinstance(error, dict) and (error.get("code") or error.get("message")):
                raise VegaException(error.get("message") or "getAlertsEvents failed.")
            results = envelope.get("results") or []
            if isinstance(results, dict):
                results = [results]
            if not isinstance(results, list) or not results:
                break
            collected.extend(results)
            offset += len(results)
            total = envelope.get("total")
            if total is not None and offset >= int(total):
                break
            if len(results) < page_size:
                break
        return collected

    def get_incident_timeline(
        self, incident_id: str, limit: int = 100, offset: int = 0
    ) -> dict:
        data = self.graphql(
            GET_INCIDENT_TIMELINE_QUERY,
            {"incidentId": incident_id, "limit": limit, "offset": offset},
        )
        return data.get("getIncidentTimeline") or {}

    def get_incident(self, incident_id: str) -> dict:
        records = self.get_incidents(
            {
                "incidentIds": [incident_id],
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
