from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import GET_ALERT_DETAILS_SCRIPT_NAME
from ..core.exceptions import FlareNotFoundException
from ..core.utils import format_user_facing_error, require_non_empty


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_ALERT_DETAILS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""
    alert_id = ""

    try:
        alert_id = siemplify.extract_action_param("Alert ID", is_mandatory=True, print_value=True)
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)
        alert_id = require_non_empty(alert_id, "Alert ID")

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        alert = manager.get_alert(alert_id)
        siemplify.result.add_result_json(alert)
        output_message = f"Successfully retrieved details for Flare alert rule {alert_id}."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except FlareNotFoundException:
        output_message = f"The requested Flare alert rule was not found: {alert_id}."
        status, result_value = EXECUTION_STATE_COMPLETED, False
    except Exception as exc:
        output_message = (
            f"Error executing action {GET_ALERT_DETAILS_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
