from __future__ import annotations

import json
from unittest.mock import MagicMock

from core.constants import TOKEN_CACHE_PROPERTY_KEY
from core.token_cache import TokenCache


def test_token_cache_uses_memory_then_context() -> None:
    siemplify = MagicMock()
    siemplify.integration_instance = "instance-1"
    siemplify.get_context_property.return_value = json.dumps(
        {"access_token": "ctx-token", "expires_at": 10_000},
    )
    cache = TokenCache(siemplify=siemplify, now=lambda: 1_000)
    assert cache.get_token() == "ctx-token"

    cache.set_token("mem-token", 86400)
    siemplify.set_context_property.assert_called()
    assert TOKEN_CACHE_PROPERTY_KEY in siemplify.set_context_property.call_args[0]
    assert cache.get_token() == "mem-token"
    siemplify.get_context_property.reset_mock()
    cache.get_token()
    siemplify.get_context_property.assert_not_called()


def test_token_cache_expires_with_buffer() -> None:
    cache = TokenCache(now=lambda: 1_000)
    cache.set_token("tok", 200)
    assert cache.get_token() is None


def test_token_cache_invalidate_clears_context() -> None:
    siemplify = MagicMock()
    siemplify.integration_instance = "instance-1"
    cache = TokenCache(siemplify=siemplify, now=lambda: 1_000)
    cache.set_token("tok", 86400)
    cache.invalidate()
    assert cache.get_token() is None
    assert siemplify.set_context_property.call_args[0][-1] == ""
