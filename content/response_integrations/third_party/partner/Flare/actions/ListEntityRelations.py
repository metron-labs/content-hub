from __future__ import annotations

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler

from ..core.action_helpers import build_manager
from ..core.constants import LIST_ENTITY_RELATIONS_SCRIPT_NAME
from ..core.exceptions import FlareNotFoundException
from ..core.utils import format_user_facing_error, parse_max_records, require_non_empty, split_csv_param


@output_handler
def main() -> None:
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ENTITY_RELATIONS_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    status, result_value = EXECUTION_STATE_FAILED, False
    output_message = ""
    entity_id = ""

    try:
        entity_id = siemplify.extract_action_param("Entity ID", is_mandatory=True, print_value=True)
        relation_types = siemplify.extract_action_param("Relation Types", print_value=True)
        max_records = siemplify.extract_action_param("Max Records To Return", print_value=True)
        tenant_override = siemplify.extract_action_param("Tenant ID", print_value=True)
        entity_id = require_non_empty(entity_id, "Entity ID")
        limit = parse_max_records(max_records)

        manager = build_manager(siemplify, tenant_override)
        siemplify.LOGGER.info("----------------- Main - Started -----------------")

        items = manager.list_entity_relations(entity_id, split_csv_param(relation_types), limit)
        siemplify.result.add_result_json({"items": items, "count": len(items)})
        output_message = f"Successfully retrieved {len(items)} relation(s) for Flare entity {entity_id}."
        result_value = True
        status = EXECUTION_STATE_COMPLETED
    except FlareNotFoundException:
        output_message = f"The requested Flare entity was not found: {entity_id}."
        status, result_value = EXECUTION_STATE_COMPLETED, False
    except Exception as exc:
        output_message = (
            f"Error executing action {LIST_ENTITY_RELATIONS_SCRIPT_NAME}. Reason: {format_user_facing_error(exc)}"
        )
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(exc)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}, Result: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
