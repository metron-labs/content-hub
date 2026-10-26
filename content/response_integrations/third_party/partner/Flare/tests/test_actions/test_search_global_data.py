from __future__ import annotations

from integration_testing.platform.script_output import MockActionOutput
from integration_testing.set_meta import set_metadata
from TIPCommon.base.action import ExecutionState

from ...actions import SearchGlobalData
from ..common import CONFIG_PATH
from ..core.product import Flare


class TestSearchGlobalData:
    PARAMS = {
        "Query": "example.com",
        "Categories": "forum_post, paste",
        "From Date": "2026-01-01T00:00:00Z",
        "To Date": "2026-01-31T00:00:00Z",
        "Max Records To Return": "10",
    }

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_success(self, flare: Flare, action_output: MockActionOutput) -> None:
        SearchGlobalData.main()

        assert len(flare.history) == 1
        req = flare.last
        assert req.method == "POST"
        assert req.path == "/global/_search"
        assert req.json["query"] == {"type": "query_string", "query": "example.com"}
        assert req.json["filters"]["type"] == ["forum_post", "paste"]
        assert req.json["filters"]["estimated_created_at"] == {
            "gte": "2026-01-01T00:00:00Z",
            "lte": "2026-01-31T00:00:00Z",
        }
        assert action_output.results.json_output.json_result["count"] == 2
        assert action_output.results.execution_state == ExecutionState.COMPLETED
        assert action_output.results.result_value is True

    @set_metadata(parameters=PARAMS, integration_config_file_path=CONFIG_PATH)
    def test_api_failure(self, flare: Flare, action_output: MockActionOutput) -> None:
        with flare.fail_requests():
            SearchGlobalData.main()

        assert action_output.results.execution_state == ExecutionState.FAILED
        assert action_output.results.result_value is False

    @set_metadata(
        parameters={"Query": ""},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_input(self, flare: Flare, action_output: MockActionOutput) -> None:
        SearchGlobalData.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED

    @set_metadata(
        parameters={**PARAMS, "Tenant ID": "99"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_unconfigured_tenant_is_rejected(self, flare: Flare, action_output: MockActionOutput) -> None:
        SearchGlobalData.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "not configured" in action_output.results.output_message

    @set_metadata(
        parameters={"Query": "x", "From Date": "not-a-date"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_date(self, flare: Flare, action_output: MockActionOutput) -> None:
        SearchGlobalData.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
        assert "ISO 8601" in action_output.results.output_message

    @set_metadata(
        parameters={
            "Query": "x",
            "From Date": "2026-02-01T00:00:00Z",
            "To Date": "2026-01-01T00:00:00Z",
        },
        integration_config_file_path=CONFIG_PATH,
    )
    def test_reversed_date_range(self, flare: Flare, action_output: MockActionOutput) -> None:
        SearchGlobalData.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED

    @set_metadata(
        parameters={"Query": "x", "Max Records To Return": "3"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_cursor_pagination(self, flare: Flare, action_output: MockActionOutput) -> None:
        flare.set_pages(
            "POST",
            r"^/global/_search$",
            [
                {"items": [{"id": 1}, {"id": 2}], "next": "cursor-1"},
                {"items": [{"id": 3}, {"id": 4}], "next": "cursor-2"},
            ],
        )

        SearchGlobalData.main()

        assert len(flare.history) == 2
        assert "from" not in flare.history[0].json
        assert flare.history[1].json["from"] == "cursor-1"
        assert flare.history[1].json["size"] == 1
        result = action_output.results.json_output.json_result
        assert [item["id"] for item in result["items"]] == [1, 2, 3]

    @set_metadata(
        parameters={"Query": "x", "Max Records To Return": "0"},
        integration_config_file_path=CONFIG_PATH,
    )
    def test_invalid_max_records(self, flare: Flare, action_output: MockActionOutput) -> None:
        SearchGlobalData.main()

        assert flare.history == []
        assert action_output.results.execution_state == ExecutionState.FAILED
