"""
Ingestion orchestrator — Flare poll → enrich → return findings for SOAR alerts.

Caller owns persistence (connector context) and AlertInfo packaging.
"""
from __future__ import annotations

import logging
from typing import Optional

from constants import DEFAULT_FLARE_PAGE_SIZE
from utils import (
    default_backfill_start,
    format_flare_timestamp,
    max_event_timestamp,
    parse_csv_list,
    parse_iso_timestamp,
    resolve_selected_filters,
    safe_log,
    validate_backfill_range_days,
)


def _info(log, msg: str, *args) -> None:
    safe_log(log, "info", msg, *args)

logger = logging.getLogger(__name__)


def reconcile_checkpoint(
    tenant_state: dict,
    backfill_range_days: str = "0",
    config_snapshot: Optional[dict] = None,
    logger_instance=None,
) -> dict:
    """
    Record config snapshot for audit only — never reset the ingestion watermark.

    Matches Flare-App event ingestor: changing Backfill Range, Severity,
    Source Types, or Ingest Full Event does not trigger re-backfill. The
    watermark / cursor keep advancing from where ingestion left off.
    Backfill Range is used only to seed the first-run start when no
    watermark or cursor exists yet.
    """
    log = logger_instance or logger
    if not isinstance(tenant_state, dict):
        tenant_state = {}

    if tenant_state.get("next_token") and not tenant_state.get("last_next_token"):
        tenant_state["last_next_token"] = tenant_state.pop("next_token")

    # Normalize once so "05" and "5" compare equal and invalid values fail loudly.
    incoming_backfill = str(validate_backfill_range_days(backfill_range_days))

    if config_snapshot:
        saved = tenant_state.get("_config") or {}
        if not isinstance(saved, dict):
            saved = {}
        snapshot = dict(config_snapshot)
        snapshot["backfill_setting"] = incoming_backfill

        if saved and saved != snapshot:
            _info(
                log,
                "Connector config changed — keeping checkpoint watermark %s "
                "(no historical re-fetch).",
                tenant_state.get("last_processed_timestamp") or "(none)",
            )

        tenant_state["_config"] = snapshot
        tenant_state["last_historical_config"] = incoming_backfill

    # Seed initial window only before any watermark/cursor exists (first run).
    has_watermark = bool(tenant_state.get("last_processed_timestamp"))
    has_cursor = bool((tenant_state.get("last_next_token") or "").strip())
    if (
        not tenant_state.get("initial_backfill_start")
        and not has_watermark
        and not has_cursor
    ):
        tenant_state["initial_backfill_start"] = default_backfill_start(
            incoming_backfill
        )

    return tenant_state


class IngestionPipeline:
    """Fetch Flare pages and return enriched findings for AlertInfo packaging."""

    def __init__(
        self,
        flare_manager,
        tenant_id: int,
        severity_filter: str = "",
        source_types_filter: str = "",
        ingest_full_event: bool = True,
        backfill_range_days: str = "0",
        max_events: Optional[int] = None,
        logger_instance=None,
    ) -> None:
        self.flare = flare_manager
        self.tenant_id = int(tenant_id or 0)
        # Keep raw user input; resolve against Flare catalogs in run().
        self.severity_filter_raw = severity_filter
        self.source_types_filter_raw = source_types_filter
        self.severities: list = parse_csv_list(severity_filter)
        self.source_types: list = parse_csv_list(source_types_filter)
        self.ingest_full_event = bool(ingest_full_event)
        # Store normalized integer days (0-180) so checkpoint compares stay stable.
        self.backfill_range_days = str(
            validate_backfill_range_days(backfill_range_days or "0")
        )
        self.max_events = max_events
        self.logger = logger_instance or logger

    def _log(self, level: str, msg: str, *args) -> None:
        safe_log(self.logger, level, msg, *args)

    def _resolve_filters(self) -> None:
        """
        Map connector Severity / Source Type filters to Flare API keys.

        Empty input → all values returned by Flare filter APIs (defaults).
        Specific input → case-insensitive match on key or display label.
        Source Types: a parent category (e.g. open_web / Open Web) expands to
        all nested sub-types from /events/filters/types.
        Invalid values raise FlareValidationException (shown in Testing/Logs).
        """
        severity_options = self.flare.list_severity_options()
        self.severities = resolve_selected_filters(
            self.severity_filter_raw,
            severity_options,
            "Severity Filter",
            allow_empty_as_all=True,
        )

        source_type_options = self.flare.list_source_type_options()
        user_types = parse_csv_list(self.source_types_filter_raw)
        if not user_types and not source_type_options:
            # Catalog unavailable and no user input → omit type filter (all types).
            self.source_types = []
            return

        self.source_types = resolve_selected_filters(
            self.source_types_filter_raw,
            source_type_options,
            "Source Types Filter",
            allow_empty_as_all=True,
        )

    def _config_snapshot(self) -> dict:
        return {
            "backfill_setting": self.backfill_range_days,
            "selected_severities": self.severities,
            "selected_types": self.source_types,
            "ingest_full_event": self.ingest_full_event,
        }

    def _prepare_events(self, items: list) -> list:
        prepared = []
        for event in items:
            if self.ingest_full_event:
                prepared.append(self.flare.enrich_event(event))
            else:
                prepared.append(event)
        return prepared

    def run(self, checkpoint: Optional[dict] = None) -> dict:
        """Fetch pages until exhausted or max_events; return findings + checkpoint."""
        self._resolve_filters()

        state = reconcile_checkpoint(
            dict(checkpoint or {}),
            self.backfill_range_days,
            config_snapshot=self._config_snapshot(),
            logger_instance=self.logger,
        )

        from_token = state.get("last_next_token") or None
        if isinstance(from_token, str) and not from_token.strip():
            from_token = None

        watermark_ts = format_flare_timestamp(state.get("last_processed_timestamp"))
        initial_backfill_start = format_flare_timestamp(
            state.get("initial_backfill_start")
            or default_backfill_start(self.backfill_range_days)
        )
        state["initial_backfill_start"] = initial_backfill_start

        if from_token:
            ingest_mode = "resume_cursor"
        elif watermark_ts:
            ingest_mode = "incremental"
        else:
            ingest_mode = "initial_backfill"

        running_watermark = watermark_ts
        total_fetched = 0
        findings: list = []

        while True:
            if running_watermark and not from_token:
                start_date = running_watermark
                start_date_op = "gt"
            else:
                start_date = initial_backfill_start
                start_date_op = "gte"

            result = self.flare.fetch_events_page(
                from_token=from_token,
                size=DEFAULT_FLARE_PAGE_SIZE,
                severities=self.severities or None,
                source_types=self.source_types or None,
                start_date=start_date,
                start_date_op=start_date_op,
            )
            items = result.get("items") or []
            next_token = result.get("next")
            if next_token:
                from_token = next_token

            if not items:
                state["last_next_token"] = ""
                state["last_processed_timestamp"] = running_watermark
                break

            if self.max_events is not None:
                remaining = max(0, self.max_events - total_fetched)
                if remaining <= 0:
                    break
                items = items[:remaining]

            findings.extend(self._prepare_events(items))
            total_fetched += len(items)

            page_max_ts = max_event_timestamp(items)
            if page_max_ts:
                page_dt = parse_iso_timestamp(page_max_ts)
                running_dt = parse_iso_timestamp(running_watermark)
                if page_dt and (running_dt is None or page_dt > running_dt):
                    running_watermark = page_max_ts

            state["last_next_token"] = from_token or ""
            state["last_processed_timestamp"] = running_watermark
            state["initial_backfill_start"] = initial_backfill_start

            if self.max_events is not None and total_fetched >= self.max_events:
                break

            if not next_token:
                state["last_next_token"] = ""
                break

        return {
            "ingest_mode": ingest_mode,
            "fetched": total_fetched,
            "findings": findings,
            "checkpoint": state,
            "resolved_severities": list(self.severities),
            "resolved_source_types": list(self.source_types),
            "message": (
                f"Fetched {total_fetched} Flare event(s) ({ingest_mode})."
            ),
        }
