"""Fetch Vega alerts/incidents, enrich, checkpoint, and return records.

Connector flow
--------------
1. The connector reads instance configuration (entities, lookback, filters,
   Has Related Incidents) and constructs this pipeline.
2. `run()` computes the time window from checkpoint + lookback/backfill.
3. Vega Entities to Fetch and Has Related Incidents together decide what is
   packaged. Each emitted record becomes one SOAR alert inside a case:

   Incidents + Alerts
     Yes,No: incident case with related alerts nested; unrelated alerts as
             their own cases.
     Yes:    incident case with related alerts nested; skip unrelated alerts.
     No:     incident-only case (no nested related alerts); unrelated alerts
             as their own cases.

   Incidents only (Yes, No, or Yes,No): incident-only cases. Do not fetch
     related or unrelated alerts.

   Alerts only
     Yes,No: standalone cases for related alerts and unrelated alerts.
     Yes:    standalone cases for related alerts only.
     No:     standalone cases for unrelated alerts only.

4. Records are packaged into SOAR AlertInfo objects by AlertPackager.
"""
from __future__ import annotations

import logging
from typing import Optional

from .constants import (
    ALERT_ID_LOOKUP_BATCH,
    ALERT_ID_LOOKUP_FROM,
    ENTITY_TYPE_ALERT,
    ENTITY_TYPE_INCIDENT,
    INGESTED_ID_CAP,
    MAX_ALERT_EVENT_FETCHES_PER_CYCLE,
    MAX_ALERTS_PER_CASE,
    SOAR_ALERT_TYPE_ALERT,
    SOAR_ALERT_TYPE_INCIDENT,
)
from .mapping import (
    alert_grouping_id,
    case_display_name,
    chunk_case_alerts,
    incident_alert_ids,
    incident_alert_stubs,
    incident_case_title,
    incident_grouping_id,
    index_alert_records,
    record_alert_ids,
    record_display_id,
    record_id,
    record_label_tags,
    record_name,
    record_timestamp,
    related_incident_ref,
    set_soar_meta,
    stub_to_alert,
)
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
    """Poll Vega and return packages that match SecOps Case > Alert > Event."""

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
        max_alerts_per_case: int = MAX_ALERTS_PER_CASE,
        max_alert_event_fetches: int = MAX_ALERT_EVENT_FETCHES_PER_CYCLE,
        logger_instance=None,
    ) -> None:
        self.manager = manager
        self.entities = resolve_entities(entities_raw)
        self.max_fetch = max_fetch
        self.max_alerts_per_case = max(2, int(max_alerts_per_case))
        self.max_alert_event_fetches = max(0, int(max_alert_event_fetches))
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
        self._incident_cache: dict[str, dict] = {}
        self._event_fetches = 0

    def _log(self, level: str, msg: str, *args) -> None:
        safe_log(self.logger, level, msg, *args)

    def _alert_variables(
        self,
        window: dict,
        has_related: Optional[bool],
        alert_ids: Optional[list[str]] = None,
        vega_alert_ids: Optional[list[str]] = None,
        include_time: bool = True,
    ) -> dict:
        filters = self.alert_filters
        payload = {
            "alertSeverities": filters["severities"],
            "statuses": filters["statuses"],
            "alertVerdicts": filters["verdicts"],
        }
        if alert_ids:
            payload["alertIds"] = alert_ids
        if vega_alert_ids:
            payload["vegaAlertIds"] = vega_alert_ids
        if alert_ids or vega_alert_ids:
            # Keep the ingest time window. Vega getAlerts returns 0 rows when
            # alertIds are sent without from/to/updatedFrom/updatedTo.
            if include_time:
                payload["from"] = (window or {}).get("from")
                payload["to"] = (window or {}).get("to")
                payload["updatedFrom"] = (window or {}).get("updated_from")
                payload["updatedTo"] = (window or {}).get("updated_to")
            return _drop_none(payload)
        payload["hasRelatedIncidents"] = has_related
        payload["from"] = (window or {}).get("from")
        payload["to"] = (window or {}).get("to")
        payload["updatedFrom"] = (window or {}).get("updated_from")
        payload["updatedTo"] = (window or {}).get("updated_to")
        return _drop_none(payload)

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
            events = self.manager.get_all_incident_timeline(identifier)
            record = dict(record)
            record["timeline"] = events
            self._log(
                "info",
                "Fetched %s timeline event(s) for Vega incident %s.",
                len(events),
                identifier,
            )
        except Exception as exc:
            self._log(
                "warning",
                "Unable to fetch timeline for Vega incident %s: %s",
                identifier,
                exc,
            )
        return record

    def _enrich_alert(self, record: dict) -> dict:
        # Child Vega Alert Events live on the Related Vega Alert, not the incident.
        # Cap per-cycle event fetches so one 800-alert incident cannot 429 Vega
        # and abort the whole connector run before any case is returned.
        record = dict(record)
        if self._event_fetches >= self.max_alert_event_fetches:
            if not record.get("alert_events"):
                record["alert_events"] = []
            return record
        candidates = record_alert_ids(record)
        if not candidates:
            record.setdefault("alert_events", [])
            return record
        events: list = []
        used_id = candidates[0]
        for alert_id in candidates:
            try:
                events = self.manager.get_all_alert_events(alert_id)
            except Exception as exc:
                self._log(
                    "warning",
                    "Unable to fetch events for Vega alert %s: %s",
                    alert_id,
                    exc,
                )
                continue
            used_id = alert_id
            self._event_fetches += 1
            if self._event_fetches == self.max_alert_event_fetches:
                self._log(
                    "info",
                    "Reached per-cycle Vega alert-event fetch cap (%s). "
                    "Remaining related alerts are still packaged without events.",
                    self.max_alert_event_fetches,
                )
            if events or self._event_fetches >= self.max_alert_event_fetches:
                break
        record["alert_events"] = events
        self._log(
            "info",
            "Fetched %s event(s) for Vega alert %s (eventCount=%s).",
            len(events),
            used_id,
            record.get("eventCount"),
        )
        return record

    def _remaining(self, collected: int) -> Optional[int]:
        if self.max_fetch is None:
            return None
        leftover = self.max_fetch - collected
        return leftover if leftover > 0 else 0

    def _mark_ingested(self, ingested: list[str], ingested_set: set[str], identifier: str) -> None:
        if identifier in ingested_set:
            return
        ingested_set.add(identifier)
        ingested.append(identifier)

    def _cache_incident(self, incident: dict) -> None:
        identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
        if identifier:
            self._incident_cache[identifier] = incident
        display_id = record_display_id(incident, ENTITY_TYPE_INCIDENT)
        if display_id:
            self._incident_cache[display_id] = incident

    def _id_lookup_window(self, window: dict) -> dict:
        """Wide created/updated range so related alerts older than the ingest window still resolve."""
        end = (
            (window or {}).get("to")
            or (window or {}).get("updated_to")
            or (window or {}).get("end")
        )
        return {
            "from": ALERT_ID_LOOKUP_FROM,
            "to": end,
            "updated_from": ALERT_ID_LOOKUP_FROM,
            "updated_to": end,
        }

    def _fetch_alerts_by_ids(self, alert_ids: list[str], window: dict) -> dict[str, dict]:
        """Resolve full alert records (including vegaAlertId) for incident alertIds.

        Vega getAlerts often returns 0 rows for alertIds without a time bound,
        so ID lookups use a wide createdAt window rather than the ingest window.
        Related alerts are often months older than the incident update.
        """
        unique: list[str] = []
        seen: set[str] = set()
        for alert_id in alert_ids:
            value = str(alert_id or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            unique.append(value)
        if not unique:
            return {}
        collected: list[dict] = []
        batch_size = max(1, int(ALERT_ID_LOOKUP_BATCH))
        lookup_window = self._id_lookup_window(window)

        def _lookup(batch: list[str], *, use_alert_ids: bool) -> list[dict]:
            key = "alertIds" if use_alert_ids else "vegaAlertIds"
            try:
                if use_alert_ids:
                    variables = self._alert_variables(
                        lookup_window, None, alert_ids=batch
                    )
                else:
                    variables = self._alert_variables(
                        lookup_window, None, vega_alert_ids=batch
                    )
                page = self.manager.get_alerts(variables, len(batch))
            except Exception as exc:
                self._log("warning", "Unable to fetch Vega alerts by %s: %s", key, exc)
                return []
            return [item for item in page if isinstance(item, dict)]

        for index in range(0, len(unique), batch_size):
            batch = unique[index : index + batch_size]
            page = _lookup(batch, use_alert_ids=True)
            collected.extend(page)
            found: set[str] = set()
            for alert in page:
                found.update(record_alert_ids(alert))
            missing = [item for item in batch if item not in found]
            if missing:
                collected.extend(_lookup(missing, use_alert_ids=False))

        if not collected:
            self._log(
                "warning",
                "getAlerts(alertIds) returned 0 of %s ids; falling back to "
                "hasRelatedIncidents=true in the ingest window.",
                len(unique),
            )
            try:
                collected = [
                    item
                    for item in self.manager.get_alerts(
                        self._alert_variables(window, True), self._pool_limit()
                    )
                    if isinstance(item, dict)
                ]
            except Exception as exc:
                self._log(
                    "warning",
                    "Fallback getAlerts(hasRelatedIncidents=true) failed: %s",
                    exc,
                )
                collected = []
        self._log(
            "info",
            "Fetched %s Vega alert(s) by id from %s incident alert id(s).",
            len(collected),
            len(unique),
        )
        return index_alert_records(collected)

    def _pool_limit(self) -> Optional[int]:
        if self.max_fetch is None:
            return None
        return max(self.max_fetch * 10, self.max_fetch)

    def _resolve_related_alerts(self, incident: dict, related_index: dict[str, dict]) -> list[dict]:
        """Match incident.alerts stubs to full getAlerts records (stub if missing)."""
        incident_id = record_id(incident, ENTITY_TYPE_INCIDENT)
        display_id = record_display_id(incident, ENTITY_TYPE_INCIDENT)
        seen: set[str] = set()
        resolved: list[dict] = []

        def _add(alert: dict) -> None:
            identifier = record_id(alert, ENTITY_TYPE_ALERT)
            if not identifier or identifier in seen:
                return
            seen.add(identifier)
            resolved.append(alert)

        for stub in incident_alert_stubs(incident):
            full = None
            for key in record_alert_ids(stub):
                full = related_index.get(key)
                if full:
                    break
            _add(full if isinstance(full, dict) else stub_to_alert(stub))

        for alert in related_index.values():
            ref_id, _ = related_incident_ref(alert)
            if ref_id and ref_id in {incident_id, display_id}:
                _add(alert)
        return resolved

    def _apply_incident_context(self, alert: dict, incident: dict, case_part: int = 1) -> dict:
        incident_id = record_id(incident, ENTITY_TYPE_INCIDENT)
        display_id = record_display_id(incident, ENTITY_TYPE_INCIDENT)
        alert = dict(alert)
        if incident.get("labels") and not alert.get("labels"):
            alert["labels"] = incident.get("labels")
        if incident.get("timeline") and not alert.get("timeline"):
            alert["timeline"] = incident.get("timeline")
        description = str(alert.get("description") or "").strip()
        summary = str(
            incident.get("incidentSummary")
            or incident.get("incidentFindings")
            or incident.get("description")
            or ""
        ).strip()
        if summary and summary not in description:
            alert["description"] = f"{summary}\n\n{description}".strip() if description else summary
        return set_soar_meta(
            alert,
            soar_alert_type=SOAR_ALERT_TYPE_ALERT,
            grouping_id=incident_grouping_id(incident_id, case_part),
            case_tags=record_label_tags(incident),
            case_title=incident_case_title(incident, case_part),
            grouping_time=record_timestamp(incident),
            incident_id=incident_id,
            incident_display_id=display_id,
            incident_name=record_name(incident),
            is_incident_case=True,
            case_part=case_part,
        )

    def _append_incident_alert(
        self,
        incident: dict,
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
        case_part: int = 1,
    ) -> bool:
        if self._remaining(len(records)) == 0:
            return False
        identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
        synthetic_key = f"incident:{identifier}"
        if case_part > 1:
            synthetic_key = f"{synthetic_key}:part:{case_part}"
        if not identifier or synthetic_key in ingested_set:
            return False
        display_id = record_display_id(incident, ENTITY_TYPE_INCIDENT)
        packaged = set_soar_meta(
            incident,
            soar_alert_type=SOAR_ALERT_TYPE_INCIDENT,
            grouping_id=incident_grouping_id(identifier, case_part),
            case_tags=record_label_tags(incident),
            case_title=incident_case_title(incident, case_part),
            grouping_time=record_timestamp(incident),
            incident_id=identifier,
            incident_display_id=display_id,
            incident_name=record_name(incident),
            is_incident_case=True,
            case_part=case_part,
            ticket_suffix=f"part:{case_part}" if case_part > 1 else None,
        )
        records.append((ENTITY_TYPE_INCIDENT, packaged))
        self._mark_ingested(ingested, ingested_set, synthetic_key)
        return True

    def _append_related_alert(
        self,
        alert: dict,
        incident: dict,
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
        case_part: int = 1,
    ) -> bool:
        if self._remaining(len(records)) == 0:
            return False
        identifier = record_id(alert, ENTITY_TYPE_ALERT)
        if not identifier or identifier in ingested_set:
            return False
        try:
            enriched = self._enrich_alert(alert)
        except Exception as exc:
            self._log(
                "warning",
                "Unable to enrich Vega alert %s; packaging without events: %s",
                identifier,
                exc,
            )
            enriched = dict(alert)
            enriched.setdefault("alert_events", [])
        packaged = self._apply_incident_context(enriched, incident, case_part)
        records.append((ENTITY_TYPE_ALERT, packaged))
        self._mark_ingested(ingested, ingested_set, identifier)
        return True

    def _emit_incident_cases(
        self,
        incident: dict,
        related: list[dict],
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
    ) -> None:
        """Incident case: 1 incident alert + related alerts, split at the 90 cap.

        Part 1: Vega incident alert + up to 89 related alerts (each with events).
        Later parts: up to 90 related alerts only (incident is not duplicated).
        Alerts in a part share case title, grouping id, and grouping time.
        """
        chunks = chunk_case_alerts(related, self.max_alerts_per_case)
        identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
        if len(chunks) > 1:
            self._log(
                "info",
                "Vega incident %s has %s related alert(s); splitting into %s "
                "SOAR case(s) (max %s alerts per case). Part 1 includes the "
                "incident alert; later parts are related alerts only.",
                identifier,
                len(related),
                len(chunks),
                self.max_alerts_per_case,
            )
        for index, chunk in enumerate(chunks, start=1):
            if self._remaining(len(records)) == 0:
                break
            if index == 1:
                self._append_incident_alert(
                    incident, records, ingested, ingested_set, case_part=index
                )
            for alert in chunk:
                if not self._append_related_alert(
                    alert, incident, records, ingested, ingested_set, case_part=index
                ):
                    if self._remaining(len(records)) == 0:
                        return

    def _ingest_incidents(
        self,
        window: dict,
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
        include_related: bool = True,
    ) -> None:
        """Fetch Vega incidents and optionally nest related alerts in the case."""
        remaining = self._remaining(len(records))
        if remaining == 0:
            return
        try:
            incidents = self.manager.get_incidents(
                self._incident_variables(window), remaining
            )
        except Exception as exc:
            self._log("error", "Unable to fetch Vega incidents: %s", exc)
            return
        self._log("info", "Fetched %s Vega incident(s).", len(incidents))
        related_index: dict[str, dict] = {}
        if include_related and incidents:
            all_alert_ids: list[str] = []
            for incident in incidents:
                all_alert_ids.extend(incident_alert_ids(incident))
            related_index = self._fetch_alerts_by_ids(all_alert_ids, window)
        for incident in incidents:
            if self._remaining(len(records)) == 0:
                break
            identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
            if not identifier:
                continue
            incident = self._enrich_incident(incident)
            self._cache_incident(incident)
            related = (
                self._resolve_related_alerts(incident, related_index)
                if include_related
                else []
            )
            self._log(
                "info",
                "Vega incident %s has %s related alert(s)%s.",
                identifier,
                len(related),
                "" if include_related else " (not nested)",
            )
            self._emit_incident_cases(incident, related, records, ingested, ingested_set)

    def _append_standalone_alert(
        self,
        alert: dict,
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
    ) -> bool:
        if self._remaining(len(records)) == 0:
            return False
        identifier = record_id(alert, ENTITY_TYPE_ALERT)
        if not identifier or identifier in ingested_set:
            return False
        packaged = set_soar_meta(
            self._enrich_alert(alert),
            soar_alert_type=SOAR_ALERT_TYPE_ALERT,
            grouping_id=alert_grouping_id(identifier),
            case_tags=[],
            case_title=case_display_name(alert, ENTITY_TYPE_ALERT),
            incident_id="",
            is_incident_case=False,
        )
        records.append((ENTITY_TYPE_ALERT, packaged))
        self._mark_ingested(ingested, ingested_set, identifier)
        return True

    def _ingest_standalone_alerts(
        self,
        window: dict,
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
        has_related: bool,
        label: str,
    ) -> None:
        """One SOAR case per Vega alert (related or unrelated, never nested)."""
        remaining = self._remaining(len(records))
        if remaining == 0:
            return
        try:
            alerts = self.manager.get_alerts(
                self._alert_variables(window, has_related), remaining
            )
        except Exception as exc:
            self._log("error", "Unable to fetch %s Vega alerts: %s", label, exc)
            return
        self._log("info", "Fetched %s %s Vega alert(s).", len(alerts), label)
        for alert in alerts:
            if not self._append_standalone_alert(alert, records, ingested, ingested_set):
                if self._remaining(len(records)) == 0:
                    break

    def _ingest_plan(self) -> dict:
        """Map Vega Entities + Has Related Incidents to fetch/package behavior."""
        fetch_alerts = "Alerts" in self.entities
        fetch_incidents = "Incidents" in self.entities
        has_related = self.alert_filters["has_related"]
        want_related = has_related is not False
        want_unrelated = has_related is not True
        return {
            "fetch_incidents": fetch_incidents,
            "nest_related_alerts": fetch_incidents and fetch_alerts and want_related,
            "standalone_related_alerts": fetch_alerts and not fetch_incidents and want_related,
            "standalone_unrelated_alerts": fetch_alerts and want_unrelated,
            "has_related": has_related,
        }

    def run(self, checkpoint: Optional[dict] = None) -> dict:
        # 1. Configuration is already on this pipeline (entities, filters, has-related).
        # 2. Time window: first run uses backfill; later runs resume from watermark.
        state = dict(checkpoint or {})
        ingested = list(state.get("ingested_ids") or [])
        ingested_set = set(ingested)
        window = compute_time_window(state, self.backfill_days, self.lookback_minutes)
        records: list[tuple[str, dict]] = []
        plan = self._ingest_plan()

        checkpoint_ids = len(ingested_set)
        self._log(
            "info",
            "Ingest start: entities=%s has_related=%s nest_related=%s "
            "standalone_related=%s standalone_unrelated=%s window=%s checkpoint_ids=%s",
            ",".join(self.entities),
            plan["has_related"],
            plan["nest_related_alerts"],
            plan["standalone_related_alerts"],
            plan["standalone_unrelated_alerts"],
            {key: window.get(key) for key in ("from", "to", "updated_from", "updated_to")},
            checkpoint_ids,
        )

        self._event_fetches = 0
        try:
            if plan["fetch_incidents"]:
                self._ingest_incidents(
                    window,
                    records,
                    ingested,
                    ingested_set,
                    include_related=plan["nest_related_alerts"],
                )
            if plan["standalone_related_alerts"]:
                self._ingest_standalone_alerts(
                    window, records, ingested, ingested_set, True, "related"
                )
            if plan["standalone_unrelated_alerts"]:
                self._ingest_standalone_alerts(
                    window, records, ingested, ingested_set, False, "unrelated"
                )
        except Exception as exc:
            # Keep whatever was already packaged so SOAR still gets cases.
            self._log(
                "error",
                "Ingest stopped after %s record(s): %s",
                len(records),
                exc,
            )

        if len(ingested) > INGESTED_ID_CAP:
            ingested = ingested[-INGESTED_ID_CAP:]
        state["ingested_ids"] = ingested
        state["watermark"] = window["end"]
        self._log(
            "info",
            "Ingest complete: emitting %s new record(s) (checkpoint had %s id(s)).",
            len(records),
            checkpoint_ids,
        )
        if not records:
            self._log(
                "info",
                "No new Vega records to package. If this connector already ingested "
                "these Vega IDs, reset the connector instance context or wait for new "
                "Vega alerts/incidents.",
            )
        return {
            "records": records,
            "checkpoint": state,
            "fetched": len(records),
            "window": window,
        }
