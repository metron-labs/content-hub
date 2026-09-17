from __future__ import annotations

import json
import time
from typing import Any

from .constants import GLOBAL_CONTEXT_SCOPE, TOKEN_CACHE_PROPERTY_KEY, TOKEN_EXPIRY_BUFFER_SECONDS


class TokenCache:
    """In-process plus SOAR-context cache for v2 OAuth access tokens."""

    def __init__(self, siemplify: Any | None = None, now: Any | None = None) -> None:
        self.siemplify = siemplify
        self._now = now or time.time
        self._memory: dict[str, Any] | None = None

    def _identifier(self) -> str:
        identifier = getattr(self.siemplify, "integration_instance", None)
        if identifier:
            return str(identifier)
        return "DoppelVision"

    def get_token(self) -> str | None:
        cached = self._memory if self._is_fresh(self._memory) else None
        if cached:
            return cached["access_token"]

        stored = self._read_context()
        if self._is_fresh(stored):
            self._memory = stored
            return stored["access_token"]
        return None

    def set_token(self, access_token: str, expires_in: int) -> None:
        record = {
            "access_token": access_token,
            "expires_at": self._now() + expires_in,
        }
        self._memory = record
        self._write_context(record)

    def invalidate(self) -> None:
        self._memory = None
        self._write_context(None)

    def _is_fresh(self, record: dict[str, Any] | None) -> bool:
        if not record or not record.get("access_token") or not record.get("expires_at"):
            return False
        return self._now() < float(record["expires_at"]) - TOKEN_EXPIRY_BUFFER_SECONDS

    def _read_context(self) -> dict[str, Any] | None:
        if self.siemplify is None or not hasattr(self.siemplify, "get_context_property"):
            return None
        try:
            raw = self.siemplify.get_context_property(
                GLOBAL_CONTEXT_SCOPE,
                self._identifier(),
                TOKEN_CACHE_PROPERTY_KEY,
            )
        except Exception:
            return None
        if not raw:
            return None
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _write_context(self, record: dict[str, Any] | None) -> None:
        if self.siemplify is None or not hasattr(self.siemplify, "set_context_property"):
            return
        try:
            value = "" if record is None else json.dumps(record)
            self.siemplify.set_context_property(
                GLOBAL_CONTEXT_SCOPE,
                self._identifier(),
                TOKEN_CACHE_PROPERTY_KEY,
                value,
            )
        except Exception:
            return
