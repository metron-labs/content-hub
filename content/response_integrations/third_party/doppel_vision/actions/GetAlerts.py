from __future__ import annotations

from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from DoppelManager import DoppelManager

@output_handler
def main():
    siemplify, manager = DoppelManager.from_siemplify()
    siemplify.script_name = "DoppelVision - Get All Alerts"

    search_key = siemplify.extract_action_param(param_name="Search Key", is_mandatory=False)
    queue_state = siemplify.extract_action_param(param_name="Queue State", is_mandatory=False)
    product = siemplify.extract_action_param(param_name="Product", is_mandatory=False)
    created_before = siemplify.extract_action_param(param_name="Created Before", is_mandatory=False)
    created_after = siemplify.extract_action_param(param_name="Created After", is_mandatory=False)
    sort_type = siemplify.extract_action_param(param_name="Sort Type", default_value="date_sourced")
    sort_order = siemplify.extract_action_param(param_name="Sort Order", default_value="desc")
    page = siemplify.extract_action_param(param_name="Page", input_type=int, default_value=0)
    tags = siemplify.extract_action_param(param_name="Tags", is_mandatory=False)

    tags_list = [tag.strip() for tag in tags.split(",")] if tags and tags.strip() else None

    filters = {
        "search_key": search_key.strip() if search_key and search_key.strip() else None,
        "queue_state": queue_state.strip() if queue_state and queue_state.strip() else None,
        "product": product.strip() if product and product.strip() else None,
        "created_before": created_before.strip() if created_before and created_before.strip() else None,
        "created_after": created_after.strip() if created_after and created_after.strip() else None,
        "sort_type": sort_type,
        "sort_order": sort_order,
        "page": int(page) if page else 0,
        "tags": tags_list
    }

    filters = {k: v for k, v in filters.items() if v is not None and v != "" and v != []}

    status = EXECUTION_STATE_COMPLETED
    output_message = "Alerts retrieved successfully."
    result_value = True

    try:
        siemplify.LOGGER.info(f"Fetching alerts with filters: {filters}")
        alerts = manager.get_alerts(filters=filters if filters else None)

        if alerts:
            total_alerts = len(alerts)
            siemplify.result.add_result_json({"alerts": alerts})
            output_message = f"Successfully retrieved {total_alerts} alert(s)."
            siemplify.LOGGER.info(f"Retrieved {total_alerts} alerts.")
        else:
            output_message = "No alerts found matching the provided filters."
            siemplify.LOGGER.info("No alerts found.")

    except Exception as e:
        siemplify.LOGGER.error(f"Failed to retrieve alerts: {e}")
        output_message = f"Failed to retrieve alerts: {str(e)}"
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(f"Action Completed | Status: {status} | Result: {result_value} | Message: {output_message}")
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()