from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import GET_GLOBAL_SEARCH_QUOTA_SCRIPT_NAME
from ..core.utils import format_user_facing_error


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_GLOBAL_SEARCH_QUOTA_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""

    try:
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        quota = manager.get_global_search_quota()
        siemplify.result.add_result_json(quota)
        output_message = "Successfully retrieved the Flare global search quota."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except Exception as exc:
        output_message = (
            f"Error executing action {GET_GLOBAL_SEARCH_QUOTA_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
