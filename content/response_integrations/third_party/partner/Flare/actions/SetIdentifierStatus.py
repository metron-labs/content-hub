from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import SET_IDENTIFIER_STATUS_SCRIPT_NAME
from ..core.exceptions import FlareNotFoundException
from ..core.utils import format_user_facing_error, parse_bool, require_non_empty


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = SET_IDENTIFIER_STATUS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""
    identifier_id = ""

    try:
        identifier_id = siemplify.extract_action_param("Identifier ID", is_mandatory=True, print_value=True)
        enabled = siemplify.extract_action_param("Enabled", input_type=bool, default_value=True, print_value=True)
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)
        identifier_id = require_non_empty(identifier_id, "Identifier ID")

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        enabled_flag = parse_bool(enabled, default=True)
        response = manager.set_identifier_status(identifier_id, enabled_flag)
        siemplify.result.add_result_json({
            "identifier_id": identifier_id,
            "enabled": enabled_flag,
            "response": response,
        })
        state = "enabled" if enabled_flag else "disabled"
        output_message = f"Monitoring for Flare identifier {identifier_id} was {state}."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except FlareNotFoundException:
        output_message = f"The requested Flare identifier was not found: {identifier_id}."
        status, result_value = EXECUTION_STATE_COMPLETED, False
    except Exception as exc:
        output_message = (
            f"Error executing action {SET_IDENTIFIER_STATUS_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
