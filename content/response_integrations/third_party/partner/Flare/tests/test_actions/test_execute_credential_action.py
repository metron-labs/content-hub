from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from ...actions import ExecuteCredentialAction
from ..common import CONFIG_PATH
from ..core.product import Flare


class TestExecuteCredentialAction:
    PARAMS = {"Action Type": "remediate", "Credential IDs": "cred-1, cred-2"}

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_success(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteCredentialAction.main()

        assert len(flare.history) == 1
        req = flare.last
        assert req.method == "POST"
        assert req.path == "/events/credential-actions"
        assert req.json == {
            "action": {"type": "remediate"},
            "credential_ids": ["cred-1", "cred-2"],
        }
        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_api_failure(self, flare: Flare, action_output: MockActionOutput) -> None:
        with flare.fail_requests():
            ExecuteCredentialAction.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(
        parameters={"Action Type": "remediate", "Credential IDs": ""},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_input(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteCredentialAction.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED

    @set_metadata(
        parameters={**PARAMS, "Tenant ID": "99"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_unconfigured_tenant_is_rejected(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteCredentialAction.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "not configured" in action_output.results.output_message

    @set_metadata(
        parameters={"Action Type": "ignore", "Credential IDs": "cred-1,cred-1"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_duplicate_ids_removed(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteCredentialAction.main()

        assert flare.last.json["credential_ids"] == ["cred-1"]
        assert flare.last.json["action"] == {"type": "ignore"}
