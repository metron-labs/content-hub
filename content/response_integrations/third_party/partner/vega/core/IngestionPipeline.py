"""Fetch Vega alerts/incidents, enrich, checkpoint, and return records.

Connector flow
--------------
1. The connector reads instance configuration (entities, lookback, filters,
   Has Related Incidents) and constructs this pipeline.
2. `run()` computes the time window from checkpoint + lookback/backfill.
   If a cycle stops early to avoid connector timeout, the checkpoint stores
   the last packaged record timestamp (not the current time) so the next
   run continues the remaining incidents, alerts, and events.
3. Vega Entities to Fetch and Has Related Incidents together decide what is
   packaged. Each emitted record becomes one SOAR alert inside a case:

   Incidents + Alerts
     Yes,No: incident-only case, related alerts in separate batch cases,
             unrelated alerts as their own cases.
     Yes:    incident-only case plus related-alert batch cases; skip
             unrelated alerts.
     No:     incident-only case; unrelated alerts as their own cases.

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
import time
from datetime import datetime
from typing import Optional

from .constants import (
    ALERT_ID_LOOKUP_BATCH,
    ALERT_ID_LOOKUP_FROM,
    ENTITY_TYPE_ALERT,
    ENTITY_TYPE_INCIDENT,
    INGESTED_ID_CAP,
    MAX_ALERTS_PER_CASE,
    SOAR_ALERT_TYPE_ALERT,
    SOAR_ALERT_TYPE_INCIDENT,
    TEST_RUN_MAX_FETCH,
)
from .mapping import (
    alert_grouping_id,
    case_display_name,
    chunk_case_alerts,
    collect_label_tags,
    incident_alert_ids,
    incident_alert_stubs,
    incident_case_title,
    incident_grouping_id,
    index_alert_records,
    is_graphql_alert_id,
    merge_related_alert,
    record_alert_ids,
    record_display_id,
    record_id,
    record_label_tags,
    record_name,
    record_timestamp,
    related_incident_ref,
    set_soar_meta,
)
from .utils import (
    compute_time_window,
    parse_backfill_days,
    parse_iso_timestamp,
    parse_lookback_minutes,
    resolve_alert_filters,
    resolve_entities,
    resolve_incident_filters,
    safe_log,
    to_iso,
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
        incident_user_statuses: str = "",
        incident_investigation_statuses: str = "",
        incident_verdicts: str = "",
        max_fetch: Optional[int] = None,
        max_alerts_per_case: int = MAX_ALERTS_PER_CASE,
        logger_instance=None,
    ) -> None:
        self.manager = manager
        self.entities = resolve_entities(entities_raw)
        self.max_fetch = max_fetch
        self.max_alerts_per_case = max(1, int(max_alerts_per_case))
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
                "incident_user_statuses": incident_user_statuses,
                "incident_investigation_statuses": incident_investigation_statuses,
                "incident_verdicts": incident_verdicts,
            }
        )
        self.logger = logger_instance or logger
        self._incident_cache: dict[str, dict] = {}
        self._incomplete = False
        self._progress_ts: Optional[datetime] = None
        self._deadline: Optional[float] = None

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
        payload: dict = {}
        if not (alert_ids or vega_alert_ids):
            filters = self.alert_filters
            payload = {
                "alertSeverities": filters["severities"],
                "statuses": filters["statuses"],
                "alertVerdicts": filters["verdicts"],
            }
        # ID lookups skip connector alert filters so nested related alerts
        # keep their Vega labels instead of being replaced by stubs.
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
                "userStatuses": filters["user_statuses"],
                "investigationStatuses": filters["investigation_statuses"],
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
            events = self.manager.get_all_incident_timeline(
                identifier, deadline_monotonic=self._deadline
            )
            self._mark_if_truncated()
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

    def _now(self) -> float:
        return time.monotonic()

    def _deadline_reached(self) -> bool:
        return self._deadline is not None and self._now() >= self._deadline

    def _mark_if_truncated(self) -> None:
        if getattr(self.manager, "last_fetch_truncated", False):
            self._incomplete = True

    def _should_stop(self, collected: int) -> bool:
        if self._remaining(collected) == 0:
            return True
        if not self._deadline_reached():
            return False
        if not self._incomplete:
            self._incomplete = True
            resume = (
                to_iso(self._progress_ts) if self._progress_ts else "the current watermark"
            )
            self._log(
                "info",
                "Stopping ingest before connector timeout so this cycle can "
                "package cases and save the watermark. Remaining Vega records "
                "resume next run from %s.",
                resume,
            )
        return True

    def _note_progress(self, record: dict) -> None:
        parsed = parse_iso_timestamp(record_timestamp(record))
        if parsed is None:
            return
        if self._progress_ts is None or parsed > self._progress_ts:
            self._progress_ts = parsed

    def _sort_by_timestamp(self, rows: list[dict]) -> list[dict]:
        return sorted(rows, key=lambda row: record_timestamp(row) or "")

    def _enrich_alert(self, record: dict) -> dict:
        # Child Vega Alert Events live on the Vega Alert, not the incident.
        record = dict(record)
        candidates = record_alert_ids(record)
        if not candidates:
            record.setdefault("alert_events", [])
            return record
        events: list = []
        used_id = candidates[0]
        for alert_id in candidates:
            try:
                events = self.manager.get_all_alert_events(
                    alert_id, deadline_monotonic=self._deadline
                )
                self._mark_if_truncated()
            except Exception as exc:
                self._log(
                    "warning",
                    "Unable to fetch events for Vega alert %s: %s",
                    alert_id,
                    exc,
                )
                continue
            used_id = alert_id
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
        """Resolve full alert records (including labels) for incident alertIds.

        Vega getAlerts often returns 0 rows for alertIds without a time bound,
        so ID lookups use a wide createdAt window rather than the ingest window.
        Related alerts are often months older than the incident update.

        Do not send human vegaAlertIds (VEGA-123) in alertIds: [ID!]. That can
        fail the whole batch and leave stubs with empty labels.
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
        graphql_ids = [item for item in unique if is_graphql_alert_id(item)]
        vega_ids = [item for item in unique if item not in graphql_ids]
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
                page = self.manager.get_alerts(
                    variables, len(batch), deadline_monotonic=self._deadline
                )
                self._mark_if_truncated()
            except Exception as exc:
                self._log("warning", "Unable to fetch Vega alerts by %s: %s", key, exc)
                return []
            return [item for item in page if isinstance(item, dict)]

        def _lookup_batches(ids: list[str], *, use_alert_ids: bool) -> None:
            for index in range(0, len(ids), batch_size):
                if self._deadline_reached():
                    self._incomplete = True
                    return
                collected.extend(
                    _lookup(ids[index : index + batch_size], use_alert_ids=use_alert_ids)
                )

        def _found_ids() -> set[str]:
            found: set[str] = set()
            for alert in collected:
                found.update(record_alert_ids(alert))
            return found

        _lookup_batches(graphql_ids, use_alert_ids=True)
        pending_vega = [item for item in vega_ids if item not in _found_ids()]
        if pending_vega:
            _lookup_batches(pending_vega, use_alert_ids=False)

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
                        self._alert_variables(window, True),
                        self._pool_limit(),
                        deadline_monotonic=self._deadline,
                    )
                    if isinstance(item, dict)
                ]
                self._mark_if_truncated()
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
            _add(merge_related_alert(stub, full))

        for alert in related_index.values():
            ref_id, _ = related_incident_ref(alert)
            if ref_id and ref_id in {incident_id, display_id}:
                _add(alert)
        return resolved

    def _apply_incident_context(
        self,
        alert: dict,
        incident: dict,
        related_batch: int,
        case_tags: Optional[list[str]] = None,
    ) -> dict:
        incident_id = record_id(incident, ENTITY_TYPE_INCIDENT)
        display_id = record_display_id(incident, ENTITY_TYPE_INCIDENT)
        alert = dict(alert)
        # Related alerts keep their own Vega labels. Empty stays empty on the
        # event (`[]`); never copy incident labels onto a related alert's
        # `labels` field. Incident names still go on case_tags (every batch)
        # and incident_label_tags so related-alert cases can tag from events.
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
            grouping_id=incident_grouping_id(incident_id, related_batch),
            case_tags=list(case_tags or []),
            incident_label_tags=record_label_tags(incident),
            case_title=incident_case_title(incident, related_batch),
            grouping_time=record_timestamp(incident),
            incident_id=incident_id,
            incident_display_id=display_id,
            incident_name=record_name(incident),
            is_incident_case=True,
            is_related_batch=True,
            case_part=related_batch,
        )

    def _append_incident_alert(
        self,
        incident: dict,
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
        case_tags: Optional[list[str]] = None,
    ) -> bool:
        if self._should_stop(len(records)):
            return False
        identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
        synthetic_key = f"incident:{identifier}"
        if not identifier or synthetic_key in ingested_set:
            return False
        display_id = record_display_id(incident, ENTITY_TYPE_INCIDENT)
        packaged = set_soar_meta(
            incident,
            soar_alert_type=SOAR_ALERT_TYPE_INCIDENT,
            grouping_id=incident_grouping_id(identifier),
            case_tags=list(case_tags or []),
            case_title=incident_case_title(incident),
            grouping_time=record_timestamp(incident),
            incident_id=identifier,
            incident_display_id=display_id,
            incident_name=record_name(incident),
            is_incident_case=True,
            is_related_batch=False,
            case_part=0,
        )
        records.append((ENTITY_TYPE_INCIDENT, packaged))
        self._mark_ingested(ingested, ingested_set, synthetic_key)
        self._note_progress(packaged)
        return True

    def _append_related_alert(
        self,
        alert: dict,
        incident: dict,
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
        related_batch: int,
        case_tags: Optional[list[str]] = None,
        apply_case_tags: bool = False,
    ) -> bool:
        if self._should_stop(len(records)):
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
        packaged = self._apply_incident_context(
            enriched, incident, related_batch, case_tags=case_tags
        )
        if apply_case_tags:
            packaged = set_soar_meta(packaged, apply_case_tags=True)
        records.append((ENTITY_TYPE_ALERT, packaged))
        self._mark_ingested(ingested, ingested_set, identifier)
        self._note_progress(packaged)
        return True

    def _emit_incident_cases(
        self,
        incident: dict,
        related: list[dict],
        records: list[tuple[str, dict]],
        ingested: list[str],
        ingested_set: set[str],
    ) -> None:
        """Incident-only case, then related alerts in batches of up to 90.

        The Vega incident is never grouped with related alerts so closing the
        incident case can resolve the incident without touching those alerts.
        """
        identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
        self._append_incident_alert(
            incident,
            records,
            ingested,
            ingested_set,
            case_tags=collect_label_tags(incident),
        )
        chunks = chunk_case_alerts(
            self._sort_by_timestamp(list(related or [])),
            self.max_alerts_per_case,
        )
        if chunks:
            self._log(
                "info",
                "Vega incident %s has %s related alert(s); incident-only case "
                "plus %s related-alert case(s) (max %s alerts per case).",
                identifier,
                len(related),
                len(chunks),
                self.max_alerts_per_case,
            )
        for index, chunk in enumerate(chunks, start=1):
            if self._should_stop(len(records)):
                break
            case_tags = collect_label_tags(incident, *chunk)
            for offset, alert in enumerate(chunk):
                if not self._append_related_alert(
                    alert,
                    incident,
                    records,
                    ingested,
                    ingested_set,
                    related_batch=index,
                    case_tags=case_tags,
                    apply_case_tags=offset == 0,
                ):
                    if self._should_stop(len(records)):
                        return

    def _incident_ingested_key(self, incident: dict) -> str:
        identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
        return f"incident:{identifier}" if identifier else ""

    def _new_related_alert_ids(self, incident: dict, ingested_set: set[str]) -> list[str]:
        """Alert IDs from this incident that are not already in the checkpoint."""
        ids: list[str] = []
        seen: set[str] = set()
        for stub in incident_alert_stubs(incident):
            keys = record_alert_ids(stub)
            if any(key in ingested_set for key in keys):
                continue
            for key in keys:
                if key not in seen:
                    seen.add(key)
                    ids.append(key)
        return ids

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
        if remaining == 0 or self._should_stop(len(records)):
            return
        try:
            incidents = self.manager.get_incidents(
                self._incident_variables(window),
                remaining,
                deadline_monotonic=self._deadline,
            )
            self._mark_if_truncated()
        except Exception as exc:
            self._incomplete = True
            self._log("error", "Unable to fetch Vega incidents: %s", exc)
            return
        incidents = self._sort_by_timestamp(
            [item for item in incidents if isinstance(item, dict)]
        )
        self._log("info", "Fetched %s Vega incident(s).", len(incidents))
        related_index: dict[str, dict] = {}
        if include_related and incidents and not self._should_stop(len(records)):
            all_alert_ids: list[str] = []
            for incident in incidents:
                all_alert_ids.extend(self._new_related_alert_ids(incident, ingested_set))
            related_index = self._fetch_alerts_by_ids(all_alert_ids, window)
        for incident in incidents:
            if self._should_stop(len(records)):
                break
            identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
            if not identifier:
                continue
            already_ingested = self._incident_ingested_key(incident) in ingested_set
            pending_related = (
                self._new_related_alert_ids(incident, ingested_set)
                if include_related
                else []
            )
            if already_ingested and not pending_related:
                continue
            if not already_ingested:
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
        if self._should_stop(len(records)):
            return False
        identifier = record_id(alert, ENTITY_TYPE_ALERT)
        if not identifier or identifier in ingested_set:
            return False
        packaged = set_soar_meta(
            self._enrich_alert(alert),
            soar_alert_type=SOAR_ALERT_TYPE_ALERT,
            grouping_id=alert_grouping_id(identifier),
            case_tags=collect_label_tags(alert),
            case_title=case_display_name(alert, ENTITY_TYPE_ALERT),
            incident_id="",
            is_incident_case=False,
        )
        records.append((ENTITY_TYPE_ALERT, packaged))
        self._mark_ingested(ingested, ingested_set, identifier)
        self._note_progress(packaged)
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
        if remaining == 0 or self._should_stop(len(records)):
            return
        try:
            alerts = self.manager.get_alerts(
                self._alert_variables(window, has_related),
                remaining,
                deadline_monotonic=self._deadline,
            )
            self._mark_if_truncated()
        except Exception as exc:
            self._incomplete = True
            self._log("error", "Unable to fetch %s Vega alerts: %s", label, exc)
            return
        alerts = self._sort_by_timestamp(
            [item for item in alerts if isinstance(item, dict)]
        )
        self._log("info", "Fetched %s %s Vega alert(s).", len(alerts), label)
        for alert in alerts:
            if not self._append_standalone_alert(alert, records, ingested, ingested_set):
                if self._should_stop(len(records)):
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

    def _append_sample_incidents(
        self,
        window: dict,
        records: list[tuple[str, dict]],
        remaining: int,
        incidents: Optional[list[dict]] = None,
    ) -> int:
        if remaining <= 0:
            return 0
        if incidents is None:
            incidents = self.manager.get_incidents(
                self._incident_variables(window), remaining
            )
        added = 0
        for incident in incidents:
            if added >= remaining:
                break
            if not isinstance(incident, dict):
                continue
            identifier = record_id(incident, ENTITY_TYPE_INCIDENT)
            if not identifier:
                continue
            display_id = record_display_id(incident, ENTITY_TYPE_INCIDENT)
            packaged = set_soar_meta(
                incident,
                soar_alert_type=SOAR_ALERT_TYPE_INCIDENT,
                grouping_id=incident_grouping_id(identifier),
                case_tags=collect_label_tags(incident),
                case_title=incident_case_title(incident),
                grouping_time=record_timestamp(incident),
                incident_id=identifier,
                incident_display_id=display_id,
                incident_name=record_name(incident),
                is_incident_case=True,
                is_related_batch=False,
                case_part=0,
            )
            records.append((ENTITY_TYPE_INCIDENT, packaged))
            added += 1
        return added

    def _append_sample_alerts(
        self,
        window: dict,
        records: list[tuple[str, dict]],
        remaining: int,
        has_related: bool,
    ) -> int:
        if remaining <= 0:
            return 0
        alerts = self.manager.get_alerts(
            self._alert_variables(window, has_related), remaining
        )
        added = 0
        for alert in alerts:
            if added >= remaining:
                break
            if not isinstance(alert, dict):
                continue
            identifier = record_id(alert, ENTITY_TYPE_ALERT)
            if not identifier:
                continue
            packaged = set_soar_meta(
                alert,
                soar_alert_type=SOAR_ALERT_TYPE_ALERT,
                grouping_id=alert_grouping_id(identifier),
                case_tags=collect_label_tags(alert),
                case_title=case_display_name(alert, ENTITY_TYPE_ALERT),
                incident_id="",
                is_incident_case=False,
            )
            records.append((ENTITY_TYPE_ALERT, packaged))
            added += 1
        return added

    def _related_alert_count(self, incidents: list[dict]) -> int:
        """Count unique nested alerts on incidents (not getAlerts time-window).

        Related Vega alerts are often older than the ingest window, so
        getAlerts(hasRelatedIncidents=true) in that window returns 0.
        """
        seen: set[str] = set()
        alerts_count_sum = 0
        for incident in incidents:
            for alert_id in incident_alert_ids(incident):
                seen.add(alert_id)
            raw = incident.get("alertsCount")
            try:
                alerts_count_sum += max(int(raw or 0), 0)
            except (TypeError, ValueError):
                pass
        return len(seen) if seen else alerts_count_sum

    def preview(self, sample_limit: int = TEST_RUN_MAX_FETCH) -> dict:
        """Count matching Vega records and return sample packages without ingest.

        Does not fetch timelines or alert events, and does not write a checkpoint.
        Counts follow Vega Entities to Fetch and Has Related Incidents.
        """
        window = compute_time_window({}, self.backfill_days, self.lookback_minutes)
        plan = self._ingest_plan()
        include_incidents = bool(plan["fetch_incidents"])
        include_related = bool(
            plan["nest_related_alerts"] or plan["standalone_related_alerts"]
        )
        include_unrelated = bool(plan["standalone_unrelated_alerts"])
        incident_count = 0
        related_count = 0
        unrelated_count = 0
        incidents: list[dict] = []
        if include_incidents:
            incidents = [
                item
                for item in self.manager.get_incidents(self._incident_variables(window))
                if isinstance(item, dict)
            ]
            incident_count = len(incidents)
        if include_related:
            if include_incidents:
                related_count = self._related_alert_count(incidents)
            else:
                related_count = self.manager.count_alerts(
                    self._alert_variables(self._id_lookup_window(window), True)
                )
        if include_unrelated:
            unrelated_count = self.manager.count_alerts(
                self._alert_variables(window, False)
            )
        remaining = max(1, int(sample_limit))
        records: list[tuple[str, dict]] = []
        if include_incidents:
            remaining -= self._append_sample_incidents(
                window, records, remaining, incidents=incidents
            )
        if remaining and include_related:
            remaining -= self._append_sample_alerts(window, records, remaining, True)
        if remaining and include_unrelated:
            self._append_sample_alerts(window, records, remaining, False)
        return {
            "incident_count": incident_count,
            "related_alert_count": related_count,
            "unrelated_alert_count": unrelated_count,
            "total_alert_count": related_count + unrelated_count,
            "include_incidents": include_incidents,
            "include_related": include_related,
            "include_unrelated": include_unrelated,
            "records": records,
            "window": window,
        }

    def run(
        self,
        checkpoint: Optional[dict] = None,
        deadline_monotonic: Optional[float] = None,
    ) -> dict:
        # 1. Configuration is already on this pipeline (entities, filters, has-related).
        # 2. Time window: first run uses backfill; later runs resume from watermark.
        state = dict(checkpoint or {})
        ingested = list(state.get("ingested_ids") or [])
        ingested_set = set(ingested)
        window = compute_time_window(state, self.backfill_days, self.lookback_minutes)
        records: list[tuple[str, dict]] = []
        plan = self._ingest_plan()

        self._incomplete = False
        self._progress_ts = None
        self._deadline = deadline_monotonic

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
            {key: window.get(key) for key in ("from", "to", "updated_from", "updated_to", "origin_from")},
            checkpoint_ids,
        )

        try:
            if plan["fetch_incidents"]:
                self._ingest_incidents(
                    window,
                    records,
                    ingested,
                    ingested_set,
                    include_related=plan["nest_related_alerts"],
                )
            if not self._should_stop(len(records)) and plan["standalone_related_alerts"]:
                self._ingest_standalone_alerts(
                    window, records, ingested, ingested_set, True, "related"
                )
            if not self._should_stop(len(records)) and plan["standalone_unrelated_alerts"]:
                self._ingest_standalone_alerts(
                    window, records, ingested, ingested_set, False, "unrelated"
                )
        except Exception as exc:
            self._incomplete = True
            self._log(
                "error",
                "Ingest stopped after %s record(s): %s",
                len(records),
                exc,
            )

        if len(ingested) > INGESTED_ID_CAP:
            ingested = ingested[-INGESTED_ID_CAP:]
        state["ingested_ids"] = ingested
        state["origin_from"] = window.get("origin_from") or state.get("origin_from")
        if self._incomplete:
            # Keep the previous watermark when this cycle packaged nothing.
            if self._progress_ts is not None:
                state["watermark"] = to_iso(self._progress_ts)
            state["incomplete"] = True
            state["query_mode"] = "created"
        else:
            state["watermark"] = window["end"]
            state["incomplete"] = False
            state["query_mode"] = "updated"
        self._log(
            "info",
            "Ingest complete: emitting %s new record(s) (checkpoint had %s id(s), "
            "incomplete=%s watermark=%s).",
            len(records),
            checkpoint_ids,
            self._incomplete,
            state.get("watermark"),
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
            "incomplete": self._incomplete,
        }
