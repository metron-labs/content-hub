from __future__ import annotations

from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from DoppelManager import DoppelManager

@output_handler
def main():
    siemplify, manager = DoppelManager.from_siemplify()
    siemplify.script_name = "DoppelVision - Update Alert"

    entity = siemplify.extract_action_param("Entity", is_mandatory=False)
    alert_id = siemplify.extract_action_param("Alert_ID", is_mandatory=False)
    queue_state = siemplify.extract_action_param("Queue_State", is_mandatory=True).strip()
    entity_state = siemplify.extract_action_param("Entity_State", is_mandatory=True).strip()

    if (entity and alert_id) or (not entity and not alert_id):
        siemplify.end("Error: Provide exactly one of 'Entity' or 'Alert_ID'.", False, EXECUTION_STATE_FAILED)

    result = manager.update_alert(
        queue_state=queue_state,
        entity_state=entity_state,
        entity=entity.strip() if entity else None,
        alert_id=alert_id.strip() if alert_id else None
    )

    if result:
        siemplify.result.add_result_json(result)
        siemplify.end("Alert updated successfully.", True, EXECUTION_STATE_COMPLETED)
    else:
        siemplify.end("Failed to update alert.", False, EXECUTION_STATE_FAILED)

if __name__ == "__main__":
    main()