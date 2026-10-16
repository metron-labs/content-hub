"""
Threat Findings Ingestion connector.

Polls Flare findings → SOAR AlertInfo packages via return_package().
When Auto Remediate is enabled, syncs closed SOAR Flare cases back to Flare
using the SOAR SDK only (no Google service account).

Supports one or more Flare Tenant IDs (comma-separated). Checkpoint and
remediation state keys are scoped by connector identifier + tenant ID so
tenants do not share watermarks or remediations.
"""
from __future__ import annotations

import json
import sys

from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyUtils import output_handler

from AlertPackager import create_alerts
from constants import (
    CHECKPOINT_PROPERTY_KEY,
    DEFAULT_FLARE_API_URL,
    REMEDIATION_PROPERTY_KEY,
    THREAT_FINDINGS_CONNECTOR_NAME,
    VENDOR_NAME,
)
from FlareManager import FlareManager
from IngestionPipeline import IngestionPipeline
from Remediator import SoarRemediator
from utils import (
    format_user_facing_error,
    parse_tenant_ids,
    validate_backfill_range_days,
)


def _truthy(value) -> bool:
    return str(value or "").strip().lower() in ("true", "1", "yes")


def _connector_instance_id(siemplify: SiemplifyConnectorExecution) -> str:
    return str(siemplify.context.connector_info.identifier)


def _checkpoint_id(
    siemplify: SiemplifyConnectorExecution, tenant_id: int
) -> str:
    # Tenant-scoped so switching Flare Tenant ID cannot reuse another tenant's
    # watermark. Legacy key (no tenant suffix) is still read once for migration.
    return (
        f"flare_ingestion_checkpoint_"
        f"{_connector_instance_id(siemplify)}_{int(tenant_id)}"
    )


def _checkpoint_id_legacy(siemplify: SiemplifyConnectorExecution) -> str:
    return f"flare_ingestion_checkpoint_{_connector_instance_id(siemplify)}"


def _remediation_id(
    siemplify: SiemplifyConnectorExecution, tenant_id: int
) -> str:
    return (
        f"flare_remediation_state_"
        f"{_connector_instance_id(siemplify)}_{int(tenant_id)}"
    )


def _remediation_id_legacy(siemplify: SiemplifyConnectorExecution) -> str:
    return f"flare_remediation_state_{_connector_instance_id(siemplify)}"


def _read_context_json(siemplify, identifier: str, property_key: str) -> dict:
    raw = siemplify.get_connector_context_property(
        identifier=identifier,
        property_key=property_key,
    )
    if not raw:
        return {}
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def load_checkpoint(siemplify, tenant_id: int) -> dict:
    try:
        data = _read_context_json(
            siemplify,
            _checkpoint_id(siemplify, tenant_id),
            CHECKPOINT_PROPERTY_KEY,
        )
        if data:
            return data
        # Migrate legacy connector-only checkpoint into the tenant-scoped key.
        return _read_context_json(
            siemplify,
            _checkpoint_id_legacy(siemplify),
            CHECKPOINT_PROPERTY_KEY,
        )
    except Exception as exc:
        siemplify.LOGGER.error(
            f"Unable to read ingestion checkpoint: {format_user_facing_error(exc)}"
        )
        return {}


def save_checkpoint(siemplify, tenant_id: int, checkpoint: dict) -> None:
    try:
        siemplify.set_connector_context_property(
            identifier=_checkpoint_id(siemplify, tenant_id),
            property_key=CHECKPOINT_PROPERTY_KEY,
            property_value=json.dumps(checkpoint or {}),
        )
    except Exception as exc:
        siemplify.LOGGER.error(
            f"Failed to store ingestion checkpoint: {format_user_facing_error(exc)}"
        )


def load_remediation_state(siemplify, tenant_id: int) -> dict:
    empty = {
        "last_successful_check_timestamp": None,
        "processed_alerts": {},
        "tenant_id": int(tenant_id),
    }
    try:
        data = _read_context_json(
            siemplify,
            _remediation_id(siemplify, tenant_id),
            REMEDIATION_PROPERTY_KEY,
        )
        if not data:
            data = _read_context_json(
                siemplify,
                _remediation_id_legacy(siemplify),
                REMEDIATION_PROPERTY_KEY,
            )
        if not data:
            return empty
        data.setdefault("processed_alerts", {})
        data["tenant_id"] = int(tenant_id)
        return data
    except Exception as exc:
        siemplify.LOGGER.error(
            f"Unable to read remediation state: {format_user_facing_error(exc)}"
        )
        return empty


def save_remediation_state(siemplify, tenant_id: int, state: dict) -> None:
    try:
        payload = dict(state or {})
        payload["tenant_id"] = int(tenant_id)
        siemplify.set_connector_context_property(
            identifier=_remediation_id(siemplify, tenant_id),
            property_key=REMEDIATION_PROPERTY_KEY,
            property_value=json.dumps(payload),
        )
    except Exception as exc:
        siemplify.LOGGER.error(
            f"Failed to store remediation state: {format_user_facing_error(exc)}"
        )


@output_handler
def main(is_test_run: bool):
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = THREAT_FINDINGS_CONNECTOR_NAME
    alerts = []

    flare_api_key = siemplify.extract_connector_param(param_name="Flare API Key")
    flare_tenant_id = siemplify.extract_connector_param(param_name="Flare Tenant ID")
    # Empty = fetch all values from Flare filter APIs (case-insensitive resolve).
    severity_filter = siemplify.extract_connector_param(
        param_name="Severity Filter", default_value=""
    )
    source_types_filter = siemplify.extract_connector_param(
        param_name="Source Types Filter", default_value=""
    )
    ingest_full = siemplify.extract_connector_param(
        param_name="Ingest Full Event", default_value="true"
    )
    backfill_range_days = siemplify.extract_connector_param(
        param_name="Backfill Range (Days)"
    )
    auto_remediate = siemplify.extract_connector_param(
        param_name="Auto Remediate", default_value="false"
    )

    try:
        if not flare_api_key:
            raise Exception(
                "Flare API Key is required. Enter your API key and try again."
            )

        if backfill_range_days is None or str(backfill_range_days).strip() == "":
            raise Exception(
                "Backfill Range (Days) is required. Enter a value from 0 to 180."
            )

        # Fail fast on bad Backfill Range (allowed 0-180).
        backfill_range_days = str(validate_backfill_range_days(backfill_range_days))

        tenant_ids = parse_tenant_ids(flare_tenant_id)
        siemplify.LOGGER.info(
            f"Ingesting Flare findings for {len(tenant_ids)} tenant(s): "
            f"{', '.join(str(t) for t in tenant_ids)}"
        )

        # Validate every tenant before fetching so one bad ID fails fast.
        for tenant_id in tenant_ids:
            FlareManager(
                api_key=flare_api_key,
                tenant_id=tenant_id,
                api_url=DEFAULT_FLARE_API_URL,
                logger_instance=siemplify.LOGGER,
            ).test_connection()

        total_fetched = 0
        for tenant_id in tenant_ids:
            flare = FlareManager(
                api_key=flare_api_key,
                tenant_id=tenant_id,
                api_url=DEFAULT_FLARE_API_URL,
                logger_instance=siemplify.LOGGER,
            )

            checkpoint = (
                {} if is_test_run else load_checkpoint(siemplify, tenant_id)
            )
            pipeline = IngestionPipeline(
                flare_manager=flare,
                tenant_id=tenant_id,
                severity_filter=severity_filter or "",
                source_types_filter=source_types_filter or "",
                ingest_full_event=_truthy(ingest_full),
                backfill_range_days=str(backfill_range_days or "0"),
                max_events=5 if is_test_run else None,
                logger_instance=siemplify.LOGGER,
            )
            summary = pipeline.run(checkpoint=checkpoint)
            fetched_count = int(summary.get("fetched") or 0)
            findings = summary.get("findings") or []
            total_fetched += fetched_count

            tenant_alerts = create_alerts(
                findings,
                siemplify,
                tenant_id=tenant_id,
                logger_instance=siemplify.LOGGER,
            )
            alerts.extend(tenant_alerts)
            ingested_events = sum(
                len(getattr(alert, "events", None) or [])
                for alert in tenant_alerts
            )
            siemplify.LOGGER.info(
                f"Tenant {tenant_id}: fetched {fetched_count} event(s); "
                f"ingested {ingested_events} into {len(tenant_alerts)} "
                f"alert package(s)."
            )

            if not is_test_run:
                save_checkpoint(
                    siemplify, tenant_id, summary.get("checkpoint") or {}
                )

            if _truthy(auto_remediate) and not is_test_run:
                rem_state = load_remediation_state(siemplify, tenant_id)
                remediator = SoarRemediator(
                    flare_manager=flare,
                    siemplify=siemplify,
                    rule_generator=VENDOR_NAME,
                    state=rem_state,
                    logger_instance=siemplify.LOGGER,
                )
                rem_result = remediator.run_once()
                if rem_result.get("message"):
                    siemplify.LOGGER.info(
                        f"Tenant {tenant_id}: {rem_result.get('message')}"
                    )
                if rem_result.get("state"):
                    save_remediation_state(
                        siemplify, tenant_id, rem_result["state"]
                    )

        siemplify.LOGGER.info(
            f"All tenants: fetched {total_fetched} event(s); "
            f"built {len(alerts)} alert package(s)."
        )

    except Exception as error:
        # Clean single-line ERROR. Always return_package([]) and exit 0 so SecOps
        # does not wrap with "Did you call build_result/end_script?".
        siemplify.LOGGER.error(format_user_facing_error(error))
        alerts = []

    siemplify.return_package(alerts)


if __name__ == "__main__":
    is_test_run = not (len(sys.argv) < 2 or sys.argv[1] == "True")
    main(is_test_run)
