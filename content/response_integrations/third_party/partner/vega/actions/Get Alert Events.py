from __future__ import annotations
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler
from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


def _current_vega_id(siemplify):
    try:
        alert = siemplify.current_alert
        events = getattr(alert, "security_events", None) or getattr(alert, "events", None) or []
        for event in events:
            additional = getattr(event, "additional_properties", None) or {}
            for key in ("vega_id", "product_log_id"):
                value = additional.get(key) if isinstance(additional, dict) else None
                if value:
                    return str(value)
    except Exception:
        return ""
    return ""


@output_handler
def main():
    siemplify = SiemplifyAction()
    from ..core.constants import (
        GET_ALERT_EVENTS_SCRIPT_NAME,
        INTEGRATION_NAME,
        PARAM_ACCESS_KEY,
        PARAM_ACCESS_KEY_ID,
        PARAM_API_ROOT,
    )
    from ..core.utils import format_user_facing_error
    from ..core.VegaManager import VegaManager

    siemplify.script_name = GET_ALERT_EVENTS_SCRIPT_NAME
    alert_id = siemplify.extract_action_param("Alert ID", default_value="", print_value=True)
    limit = siemplify.extract_action_param("Limit", default_value="100")
    offset = siemplify.extract_action_param("Offset", default_value="0")
    if not str(alert_id).strip():
        alert_id = _current_vega_id(siemplify)
    try:
        manager = VegaManager(
            api_root=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_API_ROOT),
            access_key_id=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_ACCESS_KEY_ID),
            access_key=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_ACCESS_KEY),
            logger_instance=siemplify.LOGGER,
        )
        page_size = int(limit or 100)
        all_events = manager.get_all_alert_events(
            str(alert_id).strip(),
            page_size=page_size,
        )
        result = {
            "total": len(all_events),
            "limit": page_size,
            "offset": int(offset or 0),
            "results": all_events,
        }
        siemplify.result.add_result_json(result)
        siemplify.end(
            f"Fetched {len(all_events)} Vega alert event(s) for {alert_id}.",
            True,
            EXECUTION_STATE_COMPLETED,
        )
    except Exception as error:
        message = f'Error executing action "Get Alert Events". Reason: {format_user_facing_error(error)}'
        siemplify.LOGGER.error(message)
        siemplify.end(message, False, EXECUTION_STATE_FAILED)


if __name__ == "__main__":
    main()
