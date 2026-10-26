from __future__ import annotations

import pytest

from ..core.exceptions import FlareValidationException
from ..core.utils import (
    parse_bool,
    parse_max_records,
    parse_optional_iso_date,
    require_non_empty,
    resolve_action_tenant,
)


class TestResolveActionTenant:
    def test_single_configured_tenant(self) -> None:
        assert resolve_action_tenant("42") == 42

    def test_override_picks_one_of_several(self) -> None:
        assert resolve_action_tenant("42,43", "43") == 43

    def test_several_without_override_fails(self) -> None:
        with pytest.raises(FlareValidationException, match="several tenants"):
            resolve_action_tenant("42,43")

    def test_override_must_be_configured(self) -> None:
        with pytest.raises(FlareValidationException, match="not configured"):
            resolve_action_tenant("42", "7")

    def test_override_must_be_numeric(self) -> None:
        with pytest.raises(FlareValidationException):
            resolve_action_tenant("42", "abc")


class TestInputParsers:
    @pytest.mark.parametrize(("value", "expected"), [("true", True), ("No", False), (None, True)])
    def test_parse_bool(self, value, expected) -> None:
        assert parse_bool(value, default=True) is expected

    def test_parse_bool_invalid(self) -> None:
        with pytest.raises(FlareValidationException):
            parse_bool("maybe")

    @pytest.mark.parametrize(("value", "expected"), [(None, 50), ("", 50), ("7", 7), ("1000", 1000)])
    def test_parse_max_records(self, value, expected) -> None:
        assert parse_max_records(value) == expected

    @pytest.mark.parametrize("value", ["0", "1001", "x", "1.5"])
    def test_parse_max_records_invalid(self, value) -> None:
        with pytest.raises(FlareValidationException):
            parse_max_records(value)

    def test_require_non_empty(self) -> None:
        assert require_non_empty(" a ", "X") == "a"
        with pytest.raises(FlareValidationException):
            require_non_empty("  ", "X")

    def test_parse_optional_iso_date(self) -> None:
        assert parse_optional_iso_date("", "D") is None
        assert parse_optional_iso_date("2026-01-01T05:30:00+05:30", "D") == "2026-01-01T00:00:00Z"
        with pytest.raises(FlareValidationException):
            parse_optional_iso_date("yesterday", "D")
