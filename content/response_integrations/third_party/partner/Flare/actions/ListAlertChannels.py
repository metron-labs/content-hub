from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import LIST_ALERT_CHANNELS_SCRIPT_NAME
from ..core.utils import format_user_facing_error


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ALERT_CHANNELS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""

    try:
        channel_type = siemplify.extract_action_param("Channel Type", print_value=True)
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        items = manager.list_alert_channels((channel_type or "").strip() or None)
        siemplify.result.add_result_json({"items": items, "count": len(items)})
        output_message = f"Successfully retrieved {len(items)} Flare alert channel(s)."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except Exception as exc:
        output_message = (
            f"Error executing action {LIST_ALERT_CHANNELS_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
