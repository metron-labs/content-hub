from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from constants import DEFAULT_FLARE_API_URL, INTEGRATION_NAME, PING_SCRIPT_NAME
from FlareManager import FlareManager
from utils import format_user_facing_error, parse_tenant_ids


@output_handler
def main():
    """Connectivity test for the Flare API (supports multiple tenant IDs)."""
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME

    flare_api_key = siemplify.extract_configuration_param(
        INTEGRATION_NAME, "Flare API Key"
    )
    flare_tenant_id = siemplify.extract_configuration_param(
        INTEGRATION_NAME, "Flare Tenant ID"
    )

    if not flare_api_key:
        siemplify.end(
            "Flare API Key is required. Enter your API key and try again.",
            False,
            EXECUTION_STATE_FAILED,
        )
        return

    status = EXECUTION_STATE_COMPLETED
    result_value = True

    try:
        tenant_ids = parse_tenant_ids(flare_tenant_id)
        for tenant_id in tenant_ids:
            flare = FlareManager(
                api_key=flare_api_key,
                tenant_id=tenant_id,
                api_url=DEFAULT_FLARE_API_URL,
                logger_instance=siemplify.LOGGER,
            )
            flare.test_connection()
        tenants_label = ", ".join(str(t) for t in tenant_ids)
        output_message = (
            f"Successfully connected to the {INTEGRATION_NAME} server "
            f"for tenant ID(s): {tenants_label}!"
        )
    except Exception as error:
        result_value = False
        status = EXECUTION_STATE_FAILED
        friendly = format_user_facing_error(error)
        output_message = (
            f"Failed to connect to the {INTEGRATION_NAME} server! Error: {friendly}"
        )
        siemplify.LOGGER.error(output_message)

    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
