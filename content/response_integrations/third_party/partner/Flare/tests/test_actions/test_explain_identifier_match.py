from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from ...actions import ExplainIdentifierMatch
from ..common import CONFIG_PATH
from ..core.product import Flare


class TestExplainIdentifierMatch:
    PARAMS = {"Event UID": "evt-1", "Identifier ID": "100"}

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_success(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExplainIdentifierMatch.main()

        assert len(flare.history) == 1
        req = flare.last
        assert req.method == "GET"
        assert req.path == "/events/explain-identifier"
        assert req.params == {"uid": "evt-1", "identifier_id": "100"}
        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_api_failure(self, flare: Flare, action_output: MockActionOutput) -> None:
        with flare.fail_requests():
            ExplainIdentifierMatch.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(
        parameters={"Event UID": "evt-1", "Identifier ID": ""},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_input(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExplainIdentifierMatch.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_not_found(self, flare: Flare, action_output: MockActionOutput) -> None:
        flare.set_response("GET", r"^/events/explain-identifier", {"error": "missing"}, 404)

        ExplainIdentifierMatch.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is False
        assert "was not found" in action_output.results.output_message

    @set_metadata(
        parameters={**PARAMS, "Tenant ID": "99"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_unconfigured_tenant_is_rejected(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExplainIdentifierMatch.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "not configured" in action_output.results.output_message
