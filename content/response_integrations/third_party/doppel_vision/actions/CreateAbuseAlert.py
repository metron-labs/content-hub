from __future__ import annotations

from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from DoppelManager import DoppelManager





@output_handler
def main():
    siemplify, manager = DoppelManager.from_siemplify()
    siemplify.script_name = "DoppelVision - Create Abuse Alert"

    raw_entity = siemplify.extract_action_param("Entity", is_mandatory=True)
    entity = raw_entity.strip() if raw_entity else None

    if not entity:
        siemplify.end("Error: Entity cannot be empty.", False, EXECUTION_STATE_FAILED)

    result = manager.create_abuse_alert(entity)

    if result:
        siemplify.result.add_result_json(result)
        siemplify.end("Abuse alert created successfully.", True, EXECUTION_STATE_COMPLETED)
    else:
        siemplify.end("Failed to create abuse alert.", False, EXECUTION_STATE_FAILED)


if __name__ == "__main__":
    main()