"""Tests for incident-case vs unrelated-alert ingestion."""
from __future__ import annotations

from core.constants import (
    ENTITY_TYPE_ALERT,
    ENTITY_TYPE_INCIDENT,
    SOAR_ALERT_TYPE_ALERT,
    SOAR_ALERT_TYPE_INCIDENT,
)
from core.IngestionPipeline import IngestionPipeline
from core.mapping import soar_meta


class FakeManager:
    def __init__(self) -> None:
        self.incidents: list[dict] = []
        self.alerts: list[dict] = []
        self.alert_events: dict[str, list] = {}
        self.timelines: dict[str, list] = {}
        self.incident_by_id: dict[str, dict] = {}
        self.alert_calls: list[dict] = []
        self.incident_calls: list[dict] = []

    def get_incidents(self, variables, max_records=None):
        self.incident_calls.append(dict(variables or {}))
        rows = list(self.incidents)
        if max_records is not None:
            return rows[:max_records]
        return rows

    def get_alerts(self, variables, max_records=None):
        variables = dict(variables or {})
        self.alert_calls.append(variables)
        alert_ids = {str(item) for item in (variables.get("alertIds") or []) if item}
        vega_ids = {str(item) for item in (variables.get("vegaAlertIds") or []) if item}
        lookup_ids = alert_ids | vega_ids
        has_related = variables.get("hasRelatedIncidents")
        rows = []
        for alert in self.alerts:
            keys = {
                str(alert.get("id") or ""),
                str(alert.get("vegaAlertId") or ""),
                str(alert.get("alertId") or ""),
            }
            keys.discard("")
            if lookup_ids:
                if not keys.intersection(lookup_ids):
                    continue
            else:
                related = bool(alert.get("relatedIncidents") or [])
                if has_related is True and not related:
                    continue
                if has_related is False and related:
                    continue
            rows.append(alert)
        if max_records is not None:
            return rows[:max_records]
        return rows

    def get_all_alert_events(self, alert_id):
        return list(self.alert_events.get(alert_id) or [])

    def get_all_incident_timeline(self, incident_id):
        return list(self.timelines.get(incident_id) or [])

    def get_incident(self, incident_id):
        return dict(self.incident_by_id.get(incident_id) or {})


def _pipeline(
    manager: FakeManager,
    entities: str = "Alerts,Incidents",
    has_related: str = "Yes,No",
    max_fetch: int = 20,
    max_alerts_per_case: int = 90,
    max_alert_event_fetches: int = 25,
):
    return IngestionPipeline(
        manager=manager,
        entities_raw=entities,
        lookback_minutes="5",
        backfill_days="0",
        has_related=has_related,
        max_fetch=max_fetch,
        max_alerts_per_case=max_alerts_per_case,
        max_alert_event_fetches=max_alert_event_fetches,
    )


def _sample_manager() -> FakeManager:
    manager = FakeManager()
    manager.incidents = [
        {
            "id": "inc-1",
            "vegaUniqueIncidentId": "VINC-1",
            "name": "Campaign",
            "labels": [{"name": "malware"}],
            "alerts": [
                {"alertId": "alert-1", "name": "Phish"},
                {"alertId": "alert-2", "name": "Beacon"},
            ],
        }
    ]
    manager.alerts = [
        {
            "id": "alert-1",
            "vegaAlertId": "VALERT-1",
            "name": "Phish",
            "relatedIncidents": [{"incidentId": "inc-1", "name": "Campaign"}],
        },
        {
            "id": "alert-2",
            "vegaAlertId": "VALERT-2",
            "name": "Beacon",
            "relatedIncidents": [{"incidentId": "inc-1", "name": "Campaign"}],
        },
        {"id": "alert-3", "vegaAlertId": "VALERT-3", "name": "Noise"},
    ]
    manager.alert_events = {
        "alert-1": [{"name": "evt-a"}],
        "alert-2": [{"name": "evt-b"}, {"name": "evt-c"}],
    }
    return manager


def _ids(summary: dict) -> list[str]:
    return [record.get("id") for _, record in summary["records"]]


def test_incident_related_alerts_share_incident_grouping() -> None:
    manager = _sample_manager()
    summary = _pipeline(manager).run()
    records = summary["records"]
    related = [item for item in records if soar_meta(item[1]).get("is_incident_case")]
    unrelated = [item for item in records if not soar_meta(item[1]).get("is_incident_case")]
    assert len(related) == 3
    assert related[0][0] == ENTITY_TYPE_INCIDENT
    assert {item[0] for item in related[1:]} == {ENTITY_TYPE_ALERT}
    groupings = {soar_meta(item[1])["grouping_id"] for item in related}
    assert groupings == {"Vega:incident:inc-1"}
    titles = {soar_meta(item[1])["case_title"] for item in related}
    assert all(title.startswith("Vega Incident - VINC-1 - Campaign") for title in titles)
    assert soar_meta(related[0][1])["case_tags"] == ["malware"]
    assert [item[1]["id"] for item in related[1:]] == ["alert-1", "alert-2"]
    assert related[1][1]["vegaAlertId"] == "VALERT-1"
    assert related[2][1]["vegaAlertId"] == "VALERT-2"
    assert [evt["name"] for evt in related[1][1]["alert_events"]] == ["evt-a"]
    assert [evt["name"] for evt in related[2][1]["alert_events"]] == ["evt-b", "evt-c"]
    assert len(unrelated) == 1
    assert unrelated[0][1]["id"] == "alert-3"
    assert soar_meta(unrelated[0][1])["soar_alert_type"] == SOAR_ALERT_TYPE_ALERT
    assert soar_meta(unrelated[0][1])["grouping_id"] == "Vega:alert:alert-3"
    assert soar_meta(unrelated[0][1])["case_title"].startswith("Vega Alert - VALERT-3 - Noise")
    id_lookups = [call for call in manager.alert_calls if call.get("alertIds")]
    assert id_lookups
    assert set(id_lookups[0]["alertIds"]) == {"alert-1", "alert-2"}
    assert "hasRelatedIncidents" not in id_lookups[0]
    assert "from" in id_lookups[0] or "updatedFrom" in id_lookups[0]
    unrelated_lookups = [
        call for call in manager.alert_calls if call.get("hasRelatedIncidents") is False
    ]
    assert unrelated_lookups


def test_incidents_alerts_yes_nests_related_and_skips_unrelated() -> None:
    manager = _sample_manager()
    summary = _pipeline(manager, entities="Incidents,Alerts", has_related="Yes").run()
    assert _ids(summary) == ["inc-1", "alert-1", "alert-2"]
    assert all(soar_meta(record).get("is_incident_case") for _, record in summary["records"])
    assert not any(call.get("hasRelatedIncidents") is False for call in manager.alert_calls)


def test_incidents_alerts_no_skips_nested_related_and_keeps_unrelated() -> None:
    manager = _sample_manager()
    summary = _pipeline(manager, has_related="No").run()
    ids = _ids(summary)
    assert ids == ["inc-1", "alert-3"]
    assert soar_meta(summary["records"][0][1])["soar_alert_type"] == SOAR_ALERT_TYPE_INCIDENT
    assert soar_meta(summary["records"][1][1])["grouping_id"] == "Vega:alert:alert-3"
    assert not any(call.get("alertIds") for call in manager.alert_calls)
    assert all(call.get("hasRelatedIncidents") is False for call in manager.alert_calls)


def test_incidents_only_skips_related_and_unrelated_alerts() -> None:
    manager = _sample_manager()
    for has_related in ("Yes", "No", "Yes,No"):
        manager.alert_calls = []
        manager.incident_calls = []
        summary = _pipeline(manager, entities="Incidents", has_related=has_related).run()
        assert _ids(summary) == ["inc-1"]
        assert not manager.alert_calls
        assert manager.incident_calls


def test_alerts_yes_no_creates_standalone_related_and_unrelated() -> None:
    manager = _sample_manager()
    summary = _pipeline(manager, entities="Alerts", has_related="Yes,No").run()
    ids = _ids(summary)
    assert ids == ["alert-1", "alert-2", "alert-3"]
    assert not manager.incident_calls
    assert all(not soar_meta(record).get("is_incident_case") for _, record in summary["records"])
    assert {soar_meta(record)["grouping_id"] for _, record in summary["records"]} == {
        "Vega:alert:alert-1",
        "Vega:alert:alert-2",
        "Vega:alert:alert-3",
    }


def test_alerts_yes_creates_standalone_related_only() -> None:
    manager = _sample_manager()
    summary = _pipeline(manager, entities="Alerts", has_related="Yes").run()
    assert _ids(summary) == ["alert-1", "alert-2"]
    assert not manager.incident_calls
    assert all(call.get("hasRelatedIncidents") is True for call in manager.alert_calls)
    assert all(not soar_meta(record).get("is_incident_case") for _, record in summary["records"])
    assert soar_meta(summary["records"][0][1])["grouping_id"] == "Vega:alert:alert-1"


def test_alerts_no_creates_standalone_unrelated_only() -> None:
    manager = _sample_manager()
    summary = _pipeline(manager, entities="Alerts", has_related="No").run()
    ids = _ids(summary)
    assert ids == ["alert-3"]
    assert not manager.incident_calls
    assert all(call.get("hasRelatedIncidents") is False for call in manager.alert_calls)
    assert soar_meta(summary["records"][0][1])["case_title"].startswith("Vega Alert - VALERT-3 - Noise")
    assert soar_meta(summary["records"][0][1])["grouping_id"] == "Vega:alert:alert-3"


def test_singular_entity_names_match_alerts_and_incidents() -> None:
    manager = _sample_manager()
    summary = _pipeline(manager, entities="Incident, Alert", has_related="Yes,No").run()
    assert _ids(summary) == ["inc-1", "alert-1", "alert-2", "alert-3"]


def test_incident_overflow_creates_duplicate_cases() -> None:
    manager = FakeManager()
    manager.incidents = [
        {
            "id": "inc-1",
            "vegaUniqueIncidentId": "VINC-1",
            "name": "Campaign",
            "alerts": [
                {"alertId": "alert-1"},
                {"alertId": "alert-2"},
                {"alertId": "alert-3"},
                {"alertId": "alert-4"},
                {"alertId": "alert-5"},
            ],
        }
    ]
    manager.alerts = [
        {"id": f"alert-{index}", "name": f"A{index}"} for index in range(1, 6)
    ]
    summary = _pipeline(
        manager,
        entities="Alerts,Incidents",
        has_related="Yes",
        max_fetch=20,
        max_alerts_per_case=3,
    ).run()
    records = summary["records"]
    assert [kind for kind, _ in records] == [
        ENTITY_TYPE_INCIDENT,
        ENTITY_TYPE_ALERT,
        ENTITY_TYPE_ALERT,
        ENTITY_TYPE_ALERT,
        ENTITY_TYPE_ALERT,
        ENTITY_TYPE_ALERT,
    ]
    groupings = [soar_meta(record)["grouping_id"] for _, record in records]
    parts = [soar_meta(record).get("case_part") for _, record in records]
    titles = [soar_meta(record)["case_title"] for _, record in records]
    assert all(title.startswith("Vega Incident - VINC-1 - Campaign") for title in titles)
    assert titles[0].find("(part") == -1
    assert titles[3].endswith("(part 2)")
    assert groupings == [
        "Vega:incident:inc-1",
        "Vega:incident:inc-1",
        "Vega:incident:inc-1",
        "Vega:incident:inc-1:part:2",
        "Vega:incident:inc-1:part:2",
        "Vega:incident:inc-1:part:2",
    ]
    assert parts == [1, 1, 1, 2, 2, 2]
    assert [record.get("id") for kind, record in records if kind == ENTITY_TYPE_INCIDENT] == [
        "inc-1"
    ]
    assert [record.get("id") for kind, record in records if kind == ENTITY_TYPE_ALERT] == [
        "alert-1",
        "alert-2",
        "alert-3",
        "alert-4",
        "alert-5",
    ]


def test_two_incidents_one_related_and_overflow() -> None:
    manager = FakeManager()
    manager.incidents = [
        {
            "id": "inc-small",
            "vegaUniqueIncidentId": "VINC-S",
            "name": "Small",
            "alerts": [{"alertId": "small-1"}],
        },
        {
            "id": "inc-large",
            "vegaUniqueIncidentId": "VINC-L",
            "name": "Large",
            "alerts": [{"alertId": f"large-{index}"} for index in range(1, 6)],
        },
    ]
    manager.alerts = [{"id": "small-1", "name": "Only"}] + [
        {"id": f"large-{index}", "name": f"L{index}"} for index in range(1, 6)
    ]
    manager.alert_events = {"small-1": [{"name": "evt-small"}]}
    summary = _pipeline(
        manager,
        entities="Alerts,Incidents",
        has_related="Yes",
        max_fetch=20,
        max_alerts_per_case=3,
    ).run()
    records = summary["records"]
    small = [item for item in records if soar_meta(item[1]).get("incident_id") == "inc-small"]
    large = [item for item in records if soar_meta(item[1]).get("incident_id") == "inc-large"]
    assert [kind for kind, _ in small] == [ENTITY_TYPE_INCIDENT, ENTITY_TYPE_ALERT]
    assert small[1][1]["id"] == "small-1"
    assert [evt["name"] for evt in small[1][1]["alert_events"]] == ["evt-small"]
    assert {soar_meta(item[1])["grouping_id"] for item in small} == {"Vega:incident:inc-small"}
    assert [kind for kind, _ in large] == [
        ENTITY_TYPE_INCIDENT,
        ENTITY_TYPE_ALERT,
        ENTITY_TYPE_ALERT,
        ENTITY_TYPE_ALERT,
        ENTITY_TYPE_ALERT,
        ENTITY_TYPE_ALERT,
    ]
    assert [soar_meta(item[1]).get("case_part") for item in large] == [1, 1, 1, 2, 2, 2]
    assert [record.get("id") for kind, record in large if kind == ENTITY_TYPE_INCIDENT] == [
        "inc-large"
    ]


def test_incident_without_related_alerts_creates_incident_package() -> None:
    manager = FakeManager()
    manager.incidents = [{"id": "inc-empty", "vegaUniqueIncidentId": "VINC-E", "name": "Empty"}]
    summary = _pipeline(manager, entities="Incidents").run()
    assert len(summary["records"]) == 1
    entity_type, record = summary["records"][0]
    assert entity_type == ENTITY_TYPE_INCIDENT
    assert soar_meta(record)["soar_alert_type"] == SOAR_ALERT_TYPE_INCIDENT
    assert soar_meta(record)["grouping_id"] == "Vega:incident:inc-empty"
    assert soar_meta(record)["case_title"].startswith("Vega Incident - VINC-E - Empty")


def test_related_alerts_are_not_ingested_twice_when_both_entities_selected() -> None:
    manager = FakeManager()
    manager.incidents = [
        {"id": "inc-1", "name": "Campaign", "alerts": [{"alertId": "alert-1"}]}
    ]
    manager.alerts = [
        {
            "id": "alert-1",
            "name": "Phish",
            "relatedIncidents": [{"incidentId": "inc-1"}],
        }
    ]
    summary = _pipeline(manager).run()
    ids = [rec.get("id") for _, rec in summary["records"]]
    assert ids == ["inc-1", "alert-1"]
    assert all(soar_meta(rec)["is_incident_case"] for _, rec in summary["records"])


def test_unrelated_fetch_failure_still_emits_incident_cases() -> None:
    class BoomManager(FakeManager):
        def get_alerts(self, variables, max_records=None):
            if variables.get("hasRelatedIncidents") is False:
                raise RuntimeError("getAlerts boom")
            return super().get_alerts(variables, max_records)

    manager = BoomManager()
    manager.incidents = [
        {"id": "inc-1", "name": "Campaign", "alerts": [{"alertId": "alert-1"}]}
    ]
    manager.alerts = [{"id": "alert-1", "name": "Phish"}]
    summary = _pipeline(manager, has_related="Yes,No").run()
    ids = [record.get("id") for _, record in summary["records"]]
    assert ids == ["inc-1", "alert-1"]


def test_checkpoint_skips_already_ingested_records() -> None:
    manager = FakeManager()
    manager.incidents = [{"id": "inc-1", "name": "Campaign"}]
    manager.alerts = [{"id": "alert-3", "vegaAlertId": "VALERT-3", "name": "Noise"}]
    first = _pipeline(manager).run()
    second = _pipeline(manager).run(checkpoint=first["checkpoint"])
    assert first["fetched"] >= 1
    assert second["fetched"] == 0


def test_related_alert_name_uses_vega_alert_id_not_uuid() -> None:
    uuid = "019e1b27-5119-7822-bde3-344b13e481cf"
    manager = FakeManager()
    manager.incidents = [
        {
            "id": "inc-1",
            "vegaUniqueIncidentId": "VINC-1",
            "name": "Campaign",
            "alerts": [{"alertId": uuid, "name": "Persist"}],
        }
    ]
    manager.alerts = [
        {
            "id": uuid,
            "vegaAlertId": "VALERT-9",
            "name": "Persist",
            "relatedIncidents": [{"incidentId": "inc-1"}],
        }
    ]
    summary = _pipeline(manager, entities="Alerts,Incidents", has_related="Yes").run()
    related = [item for item in summary["records"] if item[0] == ENTITY_TYPE_ALERT]
    assert len(related) == 1
    assert related[0][1]["vegaAlertId"] == "VALERT-9"
    from core.mapping import case_display_name

    assert case_display_name(related[0][1], ENTITY_TYPE_ALERT).startswith(
        "Vega Alert - VALERT-9 - Persist"
    )
    assert uuid not in case_display_name(related[0][1], ENTITY_TYPE_ALERT)


def test_alert_id_lookup_falls_back_to_related_window_query() -> None:
    class EmptyIdManager(FakeManager):
        def get_alerts(self, variables, max_records=None):
            variables = dict(variables or {})
            if variables.get("alertIds") or variables.get("vegaAlertIds"):
                self.alert_calls.append(variables)
                return []
            return super().get_alerts(variables, max_records)

    manager = EmptyIdManager()
    manager.incidents = [
        {"id": "inc-1", "name": "Campaign", "alerts": [{"alertId": "alert-1"}]}
    ]
    manager.alerts = [
        {
            "id": "alert-1",
            "name": "Phish",
            "relatedIncidents": [{"incidentId": "inc-1"}],
        }
    ]
    summary = _pipeline(manager, entities="Alerts,Incidents", has_related="Yes").run()
    ids = [record.get("id") for _, record in summary["records"]]
    assert ids == ["inc-1", "alert-1"]
    assert any(call.get("hasRelatedIncidents") is True for call in manager.alert_calls)


def test_event_fetches_are_capped_per_cycle() -> None:
    manager = FakeManager()
    manager.incidents = [
        {
            "id": "inc-1",
            "name": "Campaign",
            "alerts": [{"alertId": f"alert-{i}"} for i in range(1, 6)],
        }
    ]
    manager.alerts = [{"id": f"alert-{i}", "name": f"A{i}"} for i in range(1, 6)]
    manager.alert_events = {f"alert-{i}": [{"name": f"e{i}"}] for i in range(1, 6)}
    calls = {"n": 0}
    original = manager.get_all_alert_events

    def _counted(alert_id):
        calls["n"] += 1
        return original(alert_id)

    manager.get_all_alert_events = _counted
    summary = _pipeline(
        manager,
        entities="Alerts,Incidents",
        has_related="Yes",
        max_fetch=20,
        max_alert_event_fetches=2,
    ).run()
    related = [item for item in summary["records"] if item[0] == ENTITY_TYPE_ALERT]
    assert len(related) == 5
    assert calls["n"] == 2
    with_events = [item for item in related if item[1].get("alert_events")]
    assert len(with_events) == 2
