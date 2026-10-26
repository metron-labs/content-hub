from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import LIST_IDENTIFIERS_SCRIPT_NAME
from ..core.utils import format_user_facing_error, parse_max_records


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_IDENTIFIERS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""

    try:
        identifier_type = siemplify.extract_action_param("Type", print_value=True)
        identifier_status = siemplify.extract_action_param("Status", print_value=True)
        max_records = siemplify.extract_action_param("Max Records To Return", print_value=True)
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)
        limit = parse_max_records(max_records)

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        items = manager.list_identifiers(
            (identifier_type or "").strip() or None,
            (identifier_status or "").strip() or None,
            limit,
        )
        siemplify.result.add_result_json({"items": items, "count": len(items)})
        output_message = f"Successfully retrieved {len(items)} Flare identifier(s)."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except Exception as exc:
        output_message = (
            f"Error executing action {LIST_IDENTIFIERS_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
