"""
Vega Alerts and Incidents Connector.

Polls Vega alerts/incidents into SOAR AlertInfo packages. Optional outbound
sync writes closed Vega-sourced cases back to Vega.
"""
from __future__ import annotations

import json
import sys

from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler


def _connector_id(siemplify) -> str:
    return str(siemplify.context.connector_info.identifier)


def _read_json(siemplify, identifier: str, key: str) -> dict:
    raw = siemplify.get_connector_context_property(identifier=identifier, property_key=key)
    if not raw:
        return {}
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def _write_json(siemplify, identifier: str, key: str, payload: dict) -> None:
    siemplify.set_connector_context_property(
        identifier=identifier,
        property_key=key,
        property_value=json.dumps(payload or {}),
    )


@output_handler
def main(is_test_run: bool):
    siemplify = SiemplifyConnectorExecution()
    from AlertPackager import create_alerts
    from constants import (
        CHECKPOINT_PROPERTY_KEY,
        CONNECTOR_NAME,
        PARAM_ACCESS_KEY,
        PARAM_ACCESS_KEY_ID,
        PARAM_ALERT_SEVERITIES,
        PARAM_ALERT_STATUSES,
        PARAM_ALERT_VERDICTS,
        PARAM_API_ROOT,
        PARAM_BACKFILL,
        PARAM_ENTITIES,
        PARAM_HAS_RELATED,
        PARAM_INCIDENT_SEVERITIES,
        PARAM_INCIDENT_STATUSES,
        PARAM_INCIDENT_VERDICTS,
        PARAM_LOOKBACK,
        PARAM_OUTGOING_FIELDS,
        PARAM_SYNC,
        REMEDIATION_PROPERTY_KEY,
        TEST_RUN_MAX_FETCH,
    )
    from IngestionPipeline import IngestionPipeline
    from Remediator import SoarRemediator
    from utils import format_user_facing_error, truthy
    from VegaManager import VegaManager

    siemplify.script_name = CONNECTOR_NAME
    alerts = []
    try:
        manager = VegaManager(
            api_root=siemplify.extract_connector_param(param_name=PARAM_API_ROOT),
            access_key_id=siemplify.extract_connector_param(param_name=PARAM_ACCESS_KEY_ID),
            access_key=siemplify.extract_connector_param(param_name=PARAM_ACCESS_KEY),
            logger_instance=siemplify.LOGGER,
        )
        if is_test_run:
            manager.test_connection()
        pipeline = IngestionPipeline(
            manager=manager,
            entities_raw=siemplify.extract_connector_param(
                param_name=PARAM_ENTITIES, default_value="Alerts,Incidents"
            ),
            lookback_minutes=siemplify.extract_connector_param(
                param_name=PARAM_LOOKBACK, default_value="5"
            ),
            backfill_days=siemplify.extract_connector_param(
                param_name=PARAM_BACKFILL, default_value="30"
            ),
            alert_severities=siemplify.extract_connector_param(
                param_name=PARAM_ALERT_SEVERITIES, default_value=""
            ),
            alert_statuses=siemplify.extract_connector_param(
                param_name=PARAM_ALERT_STATUSES, default_value=""
            ),
            alert_verdicts=siemplify.extract_connector_param(
                param_name=PARAM_ALERT_VERDICTS, default_value=""
            ),
            has_related=siemplify.extract_connector_param(
                param_name=PARAM_HAS_RELATED, default_value="Yes,No"
            ),
            incident_severities=siemplify.extract_connector_param(
                param_name=PARAM_INCIDENT_SEVERITIES, default_value=""
            ),
            incident_statuses=siemplify.extract_connector_param(
                param_name=PARAM_INCIDENT_STATUSES, default_value=""
            ),
            incident_verdicts=siemplify.extract_connector_param(
                param_name=PARAM_INCIDENT_VERDICTS, default_value=""
            ),
            max_fetch=TEST_RUN_MAX_FETCH if is_test_run else None,
            logger_instance=siemplify.LOGGER,
        )
        checkpoint = {} if is_test_run else _read_json(
            siemplify, _connector_id(siemplify), CHECKPOINT_PROPERTY_KEY
        )
        summary = pipeline.run(checkpoint=checkpoint)
        alerts = create_alerts(summary.get("records") or [], siemplify, siemplify.LOGGER)
        siemplify.LOGGER.info(
            f"Fetched {summary.get('fetched') or 0} Vega record(s); "
            f"built {len(alerts)} alert package(s)."
        )
        if not is_test_run:
            _write_json(
                siemplify,
                _connector_id(siemplify),
                CHECKPOINT_PROPERTY_KEY,
                summary.get("checkpoint") or {},
            )
            if truthy(
                siemplify.extract_connector_param(
                    param_name=PARAM_SYNC, default_value="true"
                )
            ):
                rem_state = _read_json(
                    siemplify, _connector_id(siemplify), REMEDIATION_PROPERTY_KEY
                )
                remediator = SoarRemediator(
                    manager=manager,
                    siemplify=siemplify,
                    fields_raw=siemplify.extract_connector_param(
                        param_name=PARAM_OUTGOING_FIELDS, default_value=""
                    ),
                    logger_instance=siemplify.LOGGER,
                )
                rem_result = remediator.run_once(rem_state)
                if rem_result.get("message"):
                    siemplify.LOGGER.info(rem_result["message"])
                if rem_result.get("state"):
                    _write_json(
                        siemplify,
                        _connector_id(siemplify),
                        REMEDIATION_PROPERTY_KEY,
                        rem_result["state"],
                    )
    except Exception as error:
        siemplify.LOGGER.error(format_user_facing_error(error))
        alerts = []
    siemplify.return_package(alerts)


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == "True")
    main(is_test_run)
