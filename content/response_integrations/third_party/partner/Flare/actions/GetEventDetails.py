from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import GET_EVENT_DETAILS_SCRIPT_NAME
from ..core.exceptions import FlareNotFoundException
from ..core.utils import format_user_facing_error, require_non_empty


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_EVENT_DETAILS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""
    event_uid = ""

    try:
        event_uid = siemplify.extract_action_param("Event UID", is_mandatory=True, print_value=True)
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)
        event_uid = require_non_empty(event_uid, "Event UID")

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        event = manager.get_event_details(event_uid)
        siemplify.result.add_result_json(event)
        output_message = f"Successfully retrieved details for Flare event {event_uid}."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except FlareNotFoundException:
        output_message = f"The requested Flare event was not found: {event_uid}."
        status, result_value = EXECUTION_STATE_COMPLETED, False
    except Exception as exc:
        output_message = (
            f"Error executing action {GET_EVENT_DETAILS_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
