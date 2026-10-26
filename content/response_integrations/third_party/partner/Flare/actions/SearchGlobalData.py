from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import SEARCH_GLOBAL_DATA_SCRIPT_NAME
from ..core.exceptions import FlareValidationException
from ..core.utils import (
    format_user_facing_error,
    parse_max_records,
    parse_optional_iso_date,
    require_non_empty,
    split_csv_param,
)


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = SEARCH_GLOBAL_DATA_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""

    try:
        query = siemplify.extract_action_param("Query", is_mandatory=True, print_value=True)
        categories = siemplify.extract_action_param("Categories", print_value=True)
        from_date = siemplify.extract_action_param("From Date", print_value=True)
        to_date = siemplify.extract_action_param("To Date", print_value=True)
        max_records = siemplify.extract_action_param("Max Records To Return", print_value=True)
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)
        query = require_non_empty(query, "Query")
        limit = parse_max_records(max_records)
        start = parse_optional_iso_date(from_date, "From Date")
        end = parse_optional_iso_date(to_date, "To Date")
        if start and end and start > end:
            raise FlareValidationException("From Date must be earlier than To Date.")

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        siemplify.LOGGER.warn("This search consumes Flare global search quota.")
        items = manager.search_global(query, split_csv_param(categories), start, end, limit)
        siemplify.result.add_result_json({"items": items, "count": len(items)})
        output_message = f"Global search returned {len(items)} result(s)."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except Exception as exc:
        output_message = (
            f"Error executing action {SEARCH_GLOBAL_DATA_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
