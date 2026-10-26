from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from ...actions import GetIdentifierDetails
from ..common import CONFIG_PATH
from ..core.product import Flare


class TestGetIdentifierDetails:
    PARAMS = {"Identifier ID": "100"}

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_success(self, flare: Flare, action_output: MockActionOutput) -> None:
        GetIdentifierDetails.main()

        assert len(flare.history) == 1
        req = flare.last
        assert req.method == "GET"
        assert req.path == "/firework/v4/identifiers/100"
        assert action_output.results.json_output.json_result["id"] == "100"
        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_api_failure(self, flare: Flare, action_output: MockActionOutput) -> None:
        with flare.fail_requests():
            GetIdentifierDetails.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(
        parameters={"Identifier ID": ""},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_input(self, flare: Flare, action_output: MockActionOutput) -> None:
        GetIdentifierDetails.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_not_found(self, flare: Flare, action_output: MockActionOutput) -> None:
        flare.set_response("GET", r"^/firework/v4/identifiers/100", {"error": "missing"}, 404)

        GetIdentifierDetails.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is False
        assert "was not found" in action_output.results.output_message

    @set_metadata(
        parameters={**PARAMS, "Tenant ID": "99"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_unconfigured_tenant_is_rejected(self, flare: Flare, action_output: MockActionOutput) -> None:
        GetIdentifierDetails.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "not configured" in action_output.results.output_message

    @set_metadata(
        parameters={"Identifier ID": "a/b"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_identifier_id_is_url_quoted(self, flare: Flare, action_output: MockActionOutput) -> None:
        flare.set_response("GET", r"^/firework/v4/identifiers/", {"id": "a/b"})

        GetIdentifierDetails.main()

        assert flare.last.path == "/firework/v4/identifiers/a%2Fb"
