from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import EXECUTE_EVENT_ACTION_SCRIPT_NAME
from ..core.utils import format_user_facing_error, require_non_empty, split_csv_param


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = EXECUTE_EVENT_ACTION_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""

    try:
        action_type = siemplify.extract_action_param("Action Type", is_mandatory=True, print_value=True)
        event_uids = siemplify.extract_action_param("Event UIDs", is_mandatory=True, print_value=True)
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)
        action_type = require_non_empty(action_type, "Action Type")
        event_uids = require_non_empty(event_uids, "Event UIDs")

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        uids = split_csv_param(event_uids)
        response = manager.execute_event_action(action_type, uids)
        siemplify.result.add_result_json({"action": action_type, "event_uids": uids, "response": response})
        output_message = f"Successfully applied action '{action_type}' to {len(uids)} Flare event(s)."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except Exception as exc:
        output_message = (
            f"Error executing action {EXECUTE_EVENT_ACTION_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
