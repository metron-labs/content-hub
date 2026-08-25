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
        UPDATE_DETECTIONS_SCRIPT_NAME,
    )
    from ..core.utils import format_user_facing_error, parse_csv_list
    from ..core.VegaManager import VegaManager

    siemplify.script_name = UPDATE_DETECTIONS_SCRIPT_NAME
    detection_ids = parse_csv_list(
        siemplify.extract_action_param("Detection IDs", is_mandatory=True)
    )
    severity = str(siemplify.extract_action_param("Severity", default_value="") or "").strip()
    state = str(siemplify.extract_action_param("State", default_value="") or "").strip()
    tags = parse_csv_list(siemplify.extract_action_param("Tags", default_value=""))
    detections = []
    for detection_id in detection_ids:
        item = {"detectionId": detection_id}
        if severity:
            item["severity"] = severity
        if state:
            item["state"] = state
        if tags:
            item["tags"] = tags
        detections.append(item)
    try:
        manager = VegaManager(
            api_root=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_API_ROOT),
            access_key_id=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_ACCESS_KEY_ID),
            access_key=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_ACCESS_KEY),
            logger_instance=siemplify.LOGGER,
        )
        result = manager.update_detections(detections)
        siemplify.result.add_result_json(result)
        summary = result.get("summary") or {}
        siemplify.end(
            f"Updated Vega detections. Committed: {summary.get('committed', 'unknown')}.",
            True,
            EXECUTION_STATE_COMPLETED,
        )
    except Exception as error:
        message = f'Error executing action "Update Detections". Reason: {format_user_facing_error(error)}'
        siemplify.LOGGER.error(message)
        siemplify.end(message, False, EXECUTION_STATE_FAILED)


if __name__ == "__main__":
    main()
