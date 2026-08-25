"""Fetch Vega alerts/incidents, enrich, checkpoint, and return records."""
from __future__ import annotations

import logging
from typing import Optional

from .constants import ENTITY_TYPE_ALERT, ENTITY_TYPE_INCIDENT, INGESTED_ID_CAP
from .mapping import record_id
from .utils import (
    compute_time_window,
    parse_backfill_days,
    parse_lookback_minutes,
    resolve_alert_filters,
    resolve_entities,
    resolve_incident_filters,
    safe_log,
)

logger = logging.getLogger(__name__)


def _drop_none(payload: dict) -> dict:
    return {key: value for key, value in payload.items() if value is not None}


class IngestionPipeline:
    """Poll Vega and return new alert/incident records for packaging."""

    def __init__(
        self,
        manager,
        entities_raw: str,
        lookback_minutes: str,
        backfill_days: str,
        alert_severities: str = "",
        alert_statuses: str = "",
        alert_verdicts: str = "",
        has_related: str = "Yes,No",
        incident_severities: str = "",
        incident_statuses: str = "",
        incident_verdicts: str = "",
        max_fetch: Optional[int] = None,
        logger_instance=None,
    ) -> None:
        self.manager = manager
        self.entities = resolve_entities(entities_raw)
        self.max_fetch = max_fetch
        self.lookback_minutes = parse_lookback_minutes(lookback_minutes)
        self.backfill_days = parse_backfill_days(backfill_days)
        self.alert_filters = resolve_alert_filters(
            {
                "alert_severities": alert_severities,
                "alert_statuses": alert_statuses,
                "alert_verdicts": alert_verdicts,
                "has_related": has_related,
            }
        )
        self.incident_filters = resolve_incident_filters(
            {
                "incident_severities": incident_severities,
                "incident_statuses": incident_statuses,
                "incident_verdicts": incident_verdicts,
            }
        )
        self.logger = logger_instance or logger

    def _log(self, level: str, msg: str, *args) -> None:
        safe_log(self.logger, level, msg, *args)

    def _alert_variables(self, window: dict) -> dict:
        filters = self.alert_filters
        return _drop_none(
            {
                "alertSeverities": filters["severities"],
                "statuses": filters["statuses"],
                "alertVerdicts": filters["verdicts"],
                "hasRelatedIncidents": filters["has_related"],
                "from": window.get("from"),
                "to": window.get("to"),
                "updatedFrom": window.get("updated_from"),
                "updatedTo": window.get("updated_to"),
            }
        )

    def _incident_variables(self, window: dict) -> dict:
        filters = self.incident_filters
        return _drop_none(
            {
                "severities": filters["severities"],
                "statuses": filters["statuses"],
                "verdicts": filters["verdicts"],
                "from": window.get("from"),
                "to": window.get("to"),
                "updatedFrom": window.get("updated_from"),
                "updatedTo": window.get("updated_to"),
            }
        )

    def _enrich_incident(self, record: dict) -> dict:
        identifier = record_id(record, ENTITY_TYPE_INCIDENT)
        if not identifier:
            return record
        try:
            timeline = self.manager.get_incident_timeline(identifier)
            record = dict(record)
            record["timeline"] = timeline.get("events") or []
        except Exception as exc:
            self._log(
                "warning",
                "Unable to fetch timeline for Vega incident %s: %s",
                identifier,
                exc,
            )
        return record

    def _enrich_alert(self, record: dict) -> dict:
        identifier = record_id(record, ENTITY_TYPE_ALERT)
        if not identifier:
            return record
        try:
            events = self.manager.get_all_alert_events(identifier)
            record = dict(record)
            record["alert_events"] = events
        except Exception as exc:
            self._log(
                "warning",
                "Unable to fetch events for Vega alert %s: %s",
                identifier,
                exc,
            )
        return record

    def _remaining(self, collected: int) -> Optional[int]:
        if self.max_fetch is None:
            return None
        leftover = self.max_fetch - collected
        return leftover if leftover > 0 else 0

    def run(self, checkpoint: Optional[dict] = None) -> dict:
        state = dict(checkpoint or {})
        ingested = list(state.get("ingested_ids") or [])
        ingested_set = set(ingested)
        window = compute_time_window(state, self.backfill_days, self.lookback_minutes)
        records: list[tuple[str, dict]] = []

        if "Alerts" in self.entities:
            remaining = self._remaining(len(records))
            if remaining != 0:
                alerts = self.manager.get_alerts(
                    self._alert_variables(window), remaining
                )
                self._log("info", "Fetched %s Vega alert(s).", len(alerts))
                for alert in alerts:
                    identifier = record_id(alert, ENTITY_TYPE_ALERT)
                    if not identifier or identifier in ingested_set:
                        continue
                    records.append((ENTITY_TYPE_ALERT, self._enrich_alert(alert)))
                    ingested_set.add(identifier)
                    ingested.append(identifier)
                    if self._remaining(len(records)) == 0:
                        break

        if "Incidents" in self.entities:
            remaining = self._remaining(len(records))
            if remaining != 0:
                incidents = self.manager.get_incidents(
                    self._incident_variables(window), remaining
                )
                self._log("info", "Fetched %s Vega incident(s).", len(incidents))
                for incident in incidents:
                    identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
                    if not identifier or identifier in ingested_set:
                        continue
                    records.append(
                        (ENTITY_TYPE_INCIDENT, self._enrich_incident(incident))
                    )
                    ingested_set.add(identifier)
                    ingested.append(identifier)
                    if self._remaining(len(records)) == 0:
                        break

        if len(ingested) > INGESTED_ID_CAP:
            ingested = ingested[-INGESTED_ID_CAP:]
        state["ingested_ids"] = ingested
        state["watermark"] = window["end"]
        return {
            "records": records,
            "checkpoint": state,
            "fetched": len(records),
            "window": window,
        }
