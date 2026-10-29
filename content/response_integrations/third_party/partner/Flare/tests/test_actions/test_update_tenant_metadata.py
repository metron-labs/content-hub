from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from ...actions import UpdateTenantMetadata
from ..common import CONFIG_PATH
from ..core.product import Flare


class TestUpdateTenantMetadata:
    PARAMS = {
        "Event UID": "evt-1",
        "Severity": "high",
        "Tags": "reviewed, priority",
        "Notes": "Confirmed with the asset owner.",
    }

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_success(self, flare: Flare, action_output: MockActionOutput) -> None:
        UpdateTenantMetadata.main()

        assert len(flare.history) == 1
        req = flare.last
        assert req.method == "PATCH"
        assert req.path == "/events/tenant-metadata"
        assert req.params == {"uid": "evt-1"}
        assert req.json == {
            "severity": "high",
            "tags": ["reviewed", "priority"],
            "notes": "Confirmed with the asset owner.",
        }
        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_api_failure(self, flare: Flare, action_output: MockActionOutput) -> None:
        with flare.fail_requests():
            UpdateTenantMetadata.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(parameters={"Event UID": ""}, integration_config_file_path=CONFIG_PATH)
    def test_invalid_input(self, flare: Flare, action_output: MockActionOutput) -> None:
        UpdateTenantMetadata.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_not_found(self, flare: Flare, action_output: MockActionOutput) -> None:
        flare.set_response("PATCH", r"^/events/tenant-metadata", {"error": "missing"}, 404)

        UpdateTenantMetadata.main()

        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is False
        assert "was not found" in action_output.results.output_message

    @set_metadata(
        parameters={**PARAMS, "Tenant ID": "99"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_unconfigured_tenant_is_rejected(self, flare: Flare, action_output: MockActionOutput) -> None:
        UpdateTenantMetadata.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "not configured" in action_output.results.output_message

    @set_metadata(parameters={"Event UID": "evt-1"}, integration_config_file_path=CONFIG_PATH)
    def test_requires_a_field_to_update(self, flare: Flare, action_output: MockActionOutput) -> None:
        UpdateTenantMetadata.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "Severity, Tags, or Notes" in action_output.results.output_message

    @set_metadata(
        parameters={"Event UID": "evt-1", "Severity": "urgent"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_severity(self, flare: Flare, action_output: MockActionOutput) -> None:
        UpdateTenantMetadata.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "Invalid Severity" in action_output.results.output_message
