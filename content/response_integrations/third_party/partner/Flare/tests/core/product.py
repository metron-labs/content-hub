"""Fake Flare backend: routes API calls to canned responses and records history."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import re
from typing import Any

from ..common import MOCKS_PATH


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, body: Any = None, status_code: int = 200) -> None:
        self._body = body
        self.status_code = status_code
        self.text = json.dumps(body) if body is not None else ""

    def json(self) -> Any:
        if self._body is None:
            raise ValueError("empty body")
        return self._body


@dataclasses.dataclass(slots=True)
class RecordedRequest:
    method: str
    path: str
    params: dict | None
    json: dict | None


# (method, path regex, mock file) - default successful responses.
DEFAULT_ROUTES: list[tuple[str, str, str]] = [
    ("GET", r"^/firework/v4/events/$", "event_details.json"),
    ("GET", r"^/events/v2/expand$", "event_field_details.json"),
    ("GET", r"^/events/ai-assistance$", "event_ai_insights.json"),
    ("GET", r"^/events/explain-identifier$", "explain_identifier_match.json"),
    ("POST", r"^/firework/v4/events/actions$", "event_action.json"),
    ("POST", r"^/events/credential-actions$", "credential_action.json"),
    ("PATCH", r"^/events/tenant-metadata$", "tenant_metadata.json"),
    ("POST", r"^/global/_search$", "global_search.json"),
    ("GET", r"^/global/_search/quota$", "global_search_quota.json"),
    ("GET", r"^/firework/v4/identifiers/$", "identifiers_list.json"),
    ("POST", r"^/firework/v4/identifiers/[^/]+/status$", "identifier_status.json"),
    ("GET", r"^/firework/v4/identifiers/[^/]+$", "identifier_details.json"),
    ("GET", r"^/firework/v4/alerts/channels$", "alert_channels_list.json"),
    ("GET", r"^/firework/v4/alerts/$", "alerts_list.json"),
    ("GET", r"^/firework/v4/alerts/[^/]+$", "alert_details.json"),
    ("POST", r"^/entities/_list$", "entities_list.json"),
    ("POST", r"^/entities/relations$", "entity_relations.json"),
    ("GET", r"^/entities/[^/]+$", "entity_details.json"),
]


class Flare:
    """In-memory fake of the Flare API used by FlareManager in tests."""

    def __init__(self) -> None:
        self.history: list[RecordedRequest] = []
        self._overrides: list[tuple[str, re.Pattern, list[tuple[Any, int]]]] = []
        self._fail_requests_active = False

    @contextlib.contextmanager
    def fail_requests(self):
        """Force every request inside the context to return HTTP 500."""
        self._fail_requests_active = True
        try:
            yield
        finally:
            self._fail_requests_active = False

    def set_response(self, method: str, path_regex: str, body: Any, status: int = 200) -> None:
        """Override one route with a single response (repeats for every call)."""
        self._overrides.insert(0, (method.upper(), re.compile(path_regex), [(body, status)]))

    def set_pages(self, method: str, path_regex: str, bodies: list[Any]) -> None:
        """Override one route with consecutive responses, one per call."""
        self._overrides.insert(0, (method.upper(), re.compile(path_regex), [(b, 200) for b in bodies]))

    @property
    def last(self) -> RecordedRequest:
        return self.history[-1]

    def handle(self, method: str, path: str, params: dict | None, body: dict | None) -> FakeResponse:
        method = method.upper()
        self.history.append(RecordedRequest(method, path, params, body))
        if self._fail_requests_active:
            return FakeResponse({"error": "boom"}, 500)
        for ov_method, pattern, queue in self._overrides:
            if ov_method == method and pattern.search(path):
                payload, status = queue.pop(0) if len(queue) > 1 else queue[0]
                return FakeResponse(payload, status)
        for route_method, regex, mock_file in DEFAULT_ROUTES:
            if route_method == method and re.search(regex, path):
                data = json.loads((MOCKS_PATH / mock_file).read_text())
                return FakeResponse(data)
        return FakeResponse({"error": "not found"}, 404)
