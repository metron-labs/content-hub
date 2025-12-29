from __future__ import annotations

from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from DoppelManager import DoppelManager


@output_handler
def main():
    siemplify, manager = DoppelManager.from_siemplify()
    siemplify.script_name = "DoppelVision - Get Alert"

    entity = siemplify.extract_action_param("Entity", is_mandatory=False)
    alert_id = siemplify.extract_action_param("Alert_ID", is_mandatory=False)

    entity_clean = entity.strip() if entity else None
    alert_id_clean = alert_id.strip() if alert_id else None

    if (entity_clean and alert_id_clean) or (not entity_clean and not alert_id_clean):
        siemplify.end(
            "Error: Provide exactly one of 'Entity' or 'Alert_ID'.",
            False,
            EXECUTION_STATE_FAILED
        )

    result = manager.get_alert(entity=entity_clean, alert_id=alert_id_clean)

    if result:
        siemplify.result.add_result_json(result)
        siemplify.end("Alert retrieved successfully.", True, EXECUTION_STATE_COMPLETED)
    else:
        siemplify.end("Alert not found or API error.", False, EXECUTION_STATE_FAILED)


if __name__ == "__main__":
    main()