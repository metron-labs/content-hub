from __future__ import annotations
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler
from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


@output_handler
def main():
    siemplify = SiemplifyAction()
    from ..core.constants import (
        INTEGRATION_NAME,
        PARAM_ACCESS_KEY,
        PARAM_ACCESS_KEY_ID,
        PARAM_API_ROOT,
        SET_DETECTIONS_STATE_SCRIPT_NAME,
    )
    from ..core.utils import format_user_facing_error, parse_csv_list
    from ..core.VegaManager import VegaManager

    siemplify.script_name = SET_DETECTIONS_STATE_SCRIPT_NAME
    ids = parse_csv_list(siemplify.extract_action_param("Detection IDs", is_mandatory=True))
    state = str(siemplify.extract_action_param("State", is_mandatory=True) or "").strip()
    try:
        manager = VegaManager(
            api_root=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_API_ROOT),
            access_key_id=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_ACCESS_KEY_ID),
            access_key=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_ACCESS_KEY),
            logger_instance=siemplify.LOGGER,
        )
        result = manager.set_detections_state(ids, state)
        siemplify.result.add_result_json(result)
        siemplify.end(
            f"Set Vega detection state {state} for {len(result.get('ids') or ids)} ID(s).",
            True,
            EXECUTION_STATE_COMPLETED,
        )
    except Exception as error:
        message = f'Error executing action "Set Detections State". Reason: {format_user_facing_error(error)}'
        siemplify.LOGGER.error(message)
        siemplify.end(message, False, EXECUTION_STATE_FAILED)


if __name__ == "__main__":
    main()
