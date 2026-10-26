from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from ...actions import ListIdentifiers
from ..common import CONFIG_PATH
from ..core.product import Flare


class TestListIdentifiers:
    PARAMS = {"Type": "domain", "Status": "active", "Max Records To Return": "5"}

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_success(self, flare: Flare, action_output: MockActionOutput) -> None:
        ListIdentifiers.main()

        assert len(flare.history) == 1
        req = flare.last
        assert req.method == "GET"
        assert req.path == "/firework/v4/identifiers/"
        assert req.params == {"type": "domain", "status": "active", "limit": 5, "offset": 0}
        assert action_output.results.json_output.json_result["count"] == 1
        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_api_failure(self, flare: Flare, action_output: MockActionOutput) -> None:
        with flare.fail_requests():
            ListIdentifiers.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(
        parameters={"Max Records To Return": "abc"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_input(self, flare: Flare, action_output: MockActionOutput) -> None:
        ListIdentifiers.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED

    @set_metadata(
        parameters={**PARAMS, "Tenant ID": "99"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_unconfigured_tenant_is_rejected(self, flare: Flare, action_output: MockActionOutput) -> None:
        ListIdentifiers.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "not configured" in action_output.results.output_message

    @set_metadata(
        parameters={"Max Records To Return": "150"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_offset_pagination(self, flare: Flare, action_output: MockActionOutput) -> None:
        full_page = {"items": [{"id": str(i)} for i in range(100)]}
        short_page = {"items": [{"id": str(i)} for i in range(100, 130)]}
        flare.set_pages("GET", r"^/firework/v4/identifiers/$", [full_page, short_page])

        ListIdentifiers.main()

        assert len(flare.history) == 2
        assert flare.history[0].params == {"limit": 100, "offset": 0}
        assert flare.history[1].params == {"limit": 50, "offset": 100}
        assert action_output.results.json_output.json_result["count"] == 130

    @set_metadata(
        parameters={"Max Records To Return": "5"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_result_is_capped(self, flare: Flare, action_output: MockActionOutput) -> None:
        flare.set_response("GET", r"^/firework/v4/identifiers/$", {"items": [{"id": str(i)} for i in range(5)]})

        ListIdentifiers.main()

        assert len(flare.history) == 1
        assert action_output.results.json_output.json_result["count"] == 5
