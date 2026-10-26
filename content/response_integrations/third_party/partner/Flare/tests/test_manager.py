from __future__ import annotations

import pytest

from ..core.exceptions import (
    FlareForbiddenException,
    FlareNotFoundException,
    FlareRateLimitException,
    FlareUnauthorizedException,
    FlareValidationException,
)
from ..core.FlareManager import FlareManager
from .core.product import FakeResponse, Flare

# Captured at import time, before the autouse fixture replaces it per test.
_REAL_REQUEST = FlareManager._request_with_auth_retry


class _FakeClient:
    """Stand-in for FlareApiClient that replays queued responses."""

    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict]] = []
        self.token_refreshes = 0

    def get(self, path: str, **kwargs):
        self.calls.append((path, kwargs))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    post = get

    def generate_token(self) -> None:
        self.token_refreshes += 1


def _manager() -> FlareManager:
    return FlareManager(api_key="key", tenant_id=42)


class TestRequestHandling:
    def test_401_refreshes_token_once_and_retries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(FlareManager, "_request_with_auth_retry", _REAL_REQUEST)
        manager = _manager()
        manager.client = _FakeClient([FakeResponse({}, 401), FakeResponse({"ok": True})])

        assert manager._call("get", "/x") == {"ok": True}
        assert manager.client.token_refreshes == 1
        assert len(manager.client.calls) == 2

    def test_persistent_401_raises_unauthorized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(FlareManager, "_request_with_auth_retry", _REAL_REQUEST)
        manager = _manager()
        manager.client = _FakeClient([FakeResponse({}, 401), FakeResponse({}, 401)])

        with pytest.raises(FlareUnauthorizedException):
            manager._call("get", "/x")

    def test_429_maps_to_rate_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(FlareManager, "_request_with_auth_retry", _REAL_REQUEST)
        manager = _manager()
        manager.client = _FakeClient([FakeResponse({}, 429)])

        with pytest.raises(FlareRateLimitException):
            manager._call("get", "/x")

    def test_rate_limit_error_from_sdk_maps_to_rate_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(FlareManager, "_request_with_auth_retry", _REAL_REQUEST)
        manager = _manager()
        manager.client = _FakeClient([Exception("429 Too Many Requests")])

        with pytest.raises(FlareRateLimitException):
            manager._call("get", "/x")

    @pytest.mark.parametrize(
        ("status", "expected"),
        [(403, FlareForbiddenException), (404, FlareNotFoundException)],
    )
    def test_status_mapping(self, flare: Flare, status: int, expected: type) -> None:
        flare.set_response("GET", r"^/x$", {}, status)

        with pytest.raises(expected):
            _manager()._call("get", "/x")

    def test_empty_body_returns_empty_dict(self, flare: Flare) -> None:
        flare.set_response("POST", r"^/x$", None, 204)

        assert _manager()._call("post", "/x", json={}) == {}


class TestPagination:
    def test_cursor_stops_without_next(self, flare: Flare) -> None:
        flare.set_pages("POST", r"^/p$", [{"items": [1, 2], "next": None}])

        items = _manager()._paginate_cursor("post", "/p", body={}, max_records=50)

        assert items == [1, 2]
        assert len(flare.history) == 1

    def test_cursor_stops_on_empty_page(self, flare: Flare) -> None:
        flare.set_pages("POST", r"^/p$", [{"items": [], "next": "loop"}])

        assert _manager()._paginate_cursor("post", "/p", body={}, max_records=50) == []
        assert len(flare.history) == 1

    def test_offset_accepts_plain_list(self, flare: Flare) -> None:
        flare.set_response("GET", r"^/p$", [{"id": 1}])

        assert _manager()._paginate_offset("/p", params=None, max_records=10) == [{"id": 1}]

    def test_offset_drops_empty_filters(self, flare: Flare) -> None:
        flare.set_response("GET", r"^/p$", {"items": []})

        _manager()._paginate_offset("/p", params={"type": "", "status": None}, max_records=10)

        assert flare.last.params == {"limit": 10, "offset": 0}


class TestEventAction:
    def test_rejects_unknown_action(self) -> None:
        with pytest.raises(FlareValidationException):
            _manager().execute_event_action("explode", ["a"])

    def test_requires_uids(self) -> None:
        with pytest.raises(FlareValidationException):
            _manager().execute_event_action("ignore", [" "])

    def test_action_is_normalised(self, flare: Flare) -> None:
        _manager().execute_event_action("  Remediate ", ["a"])

        assert flare.last.json["action"] == {"type": "remediate"}
