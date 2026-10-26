from __future__ import annotations

# Import soar_sdk first: it aliases the top-level SDK modules (SiemplifyUtils, ...)
# to the soar_sdk.* ones the actions import, so test fixtures patch the same objects.
import soar_sdk  # noqa: F401  # isort: skip
import pytest

from ..core.FlareManager import FlareManager
from .core.product import Flare

pytest_plugins = ("integration_testing.conftest",)


@pytest.fixture
def flare() -> Flare:
    return Flare()


@pytest.fixture(autouse=True)
def flare_session(monkeypatch: pytest.MonkeyPatch, flare: Flare) -> Flare:
    """Route every FlareManager request to the in-memory fake (no network)."""

    def fake_request(self, method: str, path: str, **kwargs):
        return flare.handle(method, path, kwargs.get("params"), kwargs.get("json"))

    monkeypatch.setattr(FlareManager, "_request_with_auth_retry", fake_request)
    return flare
