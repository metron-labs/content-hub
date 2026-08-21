from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED


@output_handler
def main():
    siemplify = SiemplifyAction()
    from constants import (
        INTEGRATION_NAME,
        PARAM_ACCESS_KEY,
        PARAM_ACCESS_KEY_ID,
        PARAM_API_ROOT,
        PING_SCRIPT_NAME,
    )
    from utils import format_user_facing_error
    from VegaManager import VegaManager

    siemplify.script_name = PING_SCRIPT_NAME
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    try:
        manager = VegaManager(
            api_root=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_API_ROOT),
            access_key_id=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_ACCESS_KEY_ID),
            access_key=siemplify.extract_configuration_param(INTEGRATION_NAME, PARAM_ACCESS_KEY),
            logger_instance=siemplify.LOGGER,
        )
        manager.test_connection()
        output_message = f"Successfully connected to the {INTEGRATION_NAME} server!"
    except Exception as error:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = (
            f"Failed to connect to the {INTEGRATION_NAME} server! "
            f"Error: {format_user_facing_error(error)}"
        )
        siemplify.LOGGER.error(output_message)

    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
