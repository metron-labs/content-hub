from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from ...actions import ExecuteEventAction
from ..common import CONFIG_PATH
from ..core.product import Flare


class TestExecuteEventAction:
    PARAMS = {"Action Type": "remediate", "Event UIDs": "evt-1, evt-2"}

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_success(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteEventAction.main()

        assert len(flare.history) == 1
        req = flare.last
        assert req.method == "POST"
        assert req.path == "/firework/v4/events/actions"
        assert req.json == {"action": {"type": "remediate"}, "targets": [{"uid": "evt-1"}, {"uid": "evt-2"}]}
        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_api_failure(self, flare: Flare, action_output: MockActionOutput) -> None:
        with flare.fail_requests():
            ExecuteEventAction.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(
        parameters={"Action Type": "remediate", "Event UIDs": ""},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_input(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteEventAction.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED

    @set_metadata(
        parameters={**PARAMS, "Tenant ID": "99"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_unconfigured_tenant_is_rejected(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteEventAction.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "not configured" in action_output.results.output_message

    @set_metadata(
        parameters={"Action Type": "delete", "Event UIDs": "evt-1"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_action_type(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteEventAction.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "Invalid Action Type" in action_output.results.output_message

    @set_metadata(
        parameters={
            "Action Type": "ignore",
            "Event UIDs": ",".join(f"evt-{i}" for i in range(11)),
        },
        integration_config_file_path=CONFIG_PATH,
    )
    def test_more_than_ten_uids(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteEventAction.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "maximum of 10" in action_output.results.output_message

    @set_metadata(
        parameters={"Action Type": "unignore", "Event UIDs": "evt-1,evt-1"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_duplicate_uids_removed(self, flare: Flare, action_output: MockActionOutput) -> None:
        ExecuteEventAction.main()

        assert flare.last.json["targets"] == [{"uid": "evt-1"}]
        assert flare.last.json["action"] == {"type": "unignore"}
