"""Tests for Vega SOAR case/alert/event hierarchy mapping."""
from __future__ import annotations

from core.constants import (
    ENTITY_TYPE_ALERT,
    ENTITY_TYPE_INCIDENT,
    SOAR_ALERT_TYPE_ALERT,
    SOAR_ALERT_TYPE_INCIDENT,
)
from core.mapping import (
    alert_grouping_id,
    build_event_dict,
    build_vega_alert_event_dict,
    case_display_name,
    chunk_case_alerts,
    incident_alert_ids,
    incident_case_title,
    incident_grouping_id,
    record_id,
    record_label_tags,
    related_incident_ref,
    set_soar_meta,
    soar_meta,
    stub_to_alert,
)
from core.Remediator import extract_sync_targets


def test_case_display_name_uses_entity_display_id_and_name() -> None:
    assert case_display_name(
        {"vegaAlertId": "VALERT-1", "name": "Phish"}, ENTITY_TYPE_ALERT
    ).startswith("Vega Alert - VALERT-1 - Phish")
    assert case_display_name(
        {"vegaUniqueIncidentId": "VINC-1", "name": "Campaign"},
        ENTITY_TYPE_INCIDENT,
    ).startswith("Vega Incident - VINC-1 - Campaign")
    incident = {"vegaUniqueIncidentId": "VINC-1", "name": "Campaign"}
    assert incident_case_title(incident).startswith("Vega Incident - VINC-1 - Campaign")
    assert incident_case_title(incident, 2).endswith("(part 2)")
    uuid = "019e1b27-5119-7822-bde3-344b13e481cf"
    assert case_display_name(
        {"id": uuid, "alertId": uuid, "vegaAlertId": "VALERT-9", "name": "Persist"},
        ENTITY_TYPE_ALERT,
    ).startswith("Vega Alert - VALERT-9 - Persist")
    uuid_only = case_display_name(
        {"id": uuid, "alertId": uuid, "name": "Persist"}, ENTITY_TYPE_ALERT
    )
    assert uuid not in uuid_only
    assert uuid_only.startswith("Vega Alert - Persist")


def test_record_id_reads_nested_alert_stub() -> None:
    assert record_id({"alertId": "abc"}, ENTITY_TYPE_ALERT) == "abc"
    assert stub_to_alert({"alertId": "abc", "name": "x"})["id"] == "abc"


def test_label_tags_are_unique_by_name() -> None:
    tags = record_label_tags(
        {
            "labels": [
                {"name": "malware"},
                {"name": "Malware"},
                {"name": "apt"},
                "apt",
                {"name": ""},
            ]
        }
    )
    assert tags == ["malware", "apt"]


def test_related_incident_ref() -> None:
    assert related_incident_ref(
        {"relatedIncidents": [{"incidentId": "inc-1", "name": "Campaign"}]}
    ) == ("inc-1", "Campaign")
    assert related_incident_ref({}) == ("", "")


def test_grouping_ids() -> None:
    assert incident_grouping_id("inc-1") == "Vega:incident:inc-1"
    assert incident_grouping_id("inc-1", 2) == "Vega:incident:inc-1:part:2"
    assert alert_grouping_id("a-1") == "Vega:alert:a-1"


def test_incident_alert_ids_and_case_chunks() -> None:
    incident = {
        "alerts": [
            {"alertId": "alert-1", "name": "Phish"},
            {"alertId": "alert-1"},
            {"alertId": "alert-2"},
        ]
    }
    assert incident_alert_ids(incident) == ["alert-1", "alert-2"]
    chunks = chunk_case_alerts(["a", "b", "c", "d", "e"], max_alerts_per_case=3)
    assert chunks == [["a", "b"], ["c", "d", "e"]]
    assert chunk_case_alerts([], max_alerts_per_case=90) == [[]]
    overflow = chunk_case_alerts(list(range(806)), max_alerts_per_case=90)
    assert len(overflow[0]) == 89
    assert all(len(chunk) == 90 for chunk in overflow[1:-1])
    assert len(overflow[-1]) == 87
    assert sum(len(chunk) for chunk in overflow) == 806
    assert len(overflow) == 9


def test_summary_event_carries_incident_id_and_alert_type() -> None:
    record = set_soar_meta(
        {"id": "alert-1", "vegaAlertId": "VALERT-1", "name": "Phish"},
        soar_alert_type=SOAR_ALERT_TYPE_INCIDENT,
        incident_id="inc-1",
        incident_display_id="VINC-1",
    )
    event = build_event_dict(record, ENTITY_TYPE_ALERT, 1, 1)
    assert event["vega_soar_alert_type"] == SOAR_ALERT_TYPE_INCIDENT
    assert event["vega_incident_id"] == "inc-1"
    assert event["vega_unique_incident_id"] == "VINC-1"
    assert "_soar_meta" not in event["details"]


_EMPTY_API_KEYS = (
    "status",
    "verdict",
    "verdict_reasoning",
    "description",
    "source_url",
    "created_at",
    "updated_at",
    "vega_incident_id",
    "vega_unique_incident_id",
    "comments",
    "labels",
    "skills",
    "recommended_actions",
    "investigation_plan",
    "timeline",
    "observables",
    "assets",
    "vega_entities",
    "vega_alert_events_count",
    "vega_comments",
    "vega_labels",
    "vega_skills",
    "vega_recommended_actions",
    "vega_investigation_plan",
    "vega_timeline",
    "vega_observables",
    "vega_assets",
)


def test_alert_event_omits_missing_api_fields() -> None:
    event = build_event_dict(
        {"id": "alert-1", "vegaAlertId": "VALERT-1", "name": "Phish"},
        ENTITY_TYPE_ALERT,
        1,
        1,
    )
    assert event["vega_alert_id"] == "VALERT-1"
    for key in _EMPTY_API_KEYS:
        assert key not in event, key


def test_alert_event_maps_get_alerts_fields() -> None:
    event = build_event_dict(
        {
            "id": "alert-1",
            "vegaAlertId": "VALERT-1",
            "name": "Phish",
            "description": "Click",
            "severity": "HIGH",
            "status": "OPEN",
            "detectionId": "det-1",
            "dataSources": ["splunk"],
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
            "verdict": "MALICIOUS",
            "verdictReasoning": "because",
            "eventCount": 3,
            "href": "https://vega.example/alerts/1",
            "comments": [{"text": "hi"}],
            "labels": [{"name": "phish"}],
            "relatedIncidents": [{"incidentId": "inc-1", "name": "Campaign"}],
        },
        ENTITY_TYPE_ALERT,
        1,
        1,
    )
    assert event["detection_id"] == "det-1"
    assert event["event_count"] == "3"
    assert event["verdict"] == "MALICIOUS"
    assert event["source_url"] == "https://vega.example/alerts/1"
    assert "recommended_actions" not in event
    assert "investigation_plan" not in event
    assert "observables" not in event
    assert "assets" not in event
    assert "vega_entities" not in event


def test_incident_event_maps_get_incidents_fields() -> None:
    event = build_event_dict(
        {
            "id": "inc-1",
            "vegaUniqueIncidentId": "VINC-1",
            "name": "Campaign",
            "incidentSummary": "summary",
            "incidentFindings": "findings",
            "status": "NEW",
            "severity": "HIGH",
            "recommendedActions": [{"name": "block"}],
            "investigationPlan": [{"stepName": "scope"}],
            "observables": ["1.1.1.1"],
            "assets": ["host-1"],
            "alertsCount": 2,
            "createdBy": "analyst",
            "link": "https://vega.example/incidents/1",
            "timeline": [{"summary": "opened"}],
        },
        ENTITY_TYPE_INCIDENT,
        1,
        1,
    )
    assert event["vega_unique_incident_id"] == "VINC-1"
    assert event["description"] == "summary"
    assert event["incident_findings"] == "findings"
    assert event["created_by"] == "analyst"
    assert event["source_url"] == "https://vega.example/incidents/1"
    assert "vega_alert_id" not in event
    assert "detection_id" not in event
    assert "event_count" not in event
    assert "recommended_actions" in event
    assert "investigation_plan" in event
    assert "observables" in event
    assert "assets" in event
    assert "timeline" in event
    assert "vega_entities" not in event
    for key in ("vega_recommended_actions", "vega_investigation_plan", "vega_observables"):
        assert key not in event, key


def test_child_events_stay_scoped_to_parent_alert() -> None:
    parent = set_soar_meta(
        {"id": "alert-1", "vegaAlertId": "VALERT-1"},
        incident_id="inc-1",
    )
    event = build_vega_alert_event_dict(
        parent, {"name": "login", "src_ip": "1.1.1.1"}, 1, 1, 0
    )
    assert event["product_log_id"] == "alert-1:event:0"
    assert event["vega_id"] == "alert-1"
    assert event["vega_incident_id"] == "inc-1"
    assert event["vega_entity_type"] == "Alert Event"


def test_alert_event_payload_maps_dynamic_api_fields() -> None:
    event = build_vega_alert_event_dict(
        {"id": "alert-1", "vegaAlertId": "VALERT-1"},
        {
            "name": "login",
            "src_ip": "1.1.1.1",
            "custom_field": "abc",
            "empty_field": "",
            "null_field": None,
            "empty_list": [],
            "nested": {"user": "bob", "host": "ws1"},
        },
        1,
        1,
        0,
    )
    assert event["src_ip"] == "1.1.1.1"
    assert event["custom_field"] == "abc"
    assert event["user"] == "bob"
    assert event["host"] == "ws1"
    assert event["ip"] == "1.1.1.1"
    assert event["vega_alert_id"] == "VALERT-1"
    assert "empty_field" not in event
    assert "null_field" not in event
    assert "empty_list" not in event
    assert "vega_incident_id" not in event
    assert "source_grouping_identifier" not in event


def test_extract_sync_targets_prefers_incident_and_skips_child_events() -> None:
    targets = extract_sync_targets(
        {
            "events": [
                {
                    "vega_entity_type": "Alert",
                    "vega_id": "alert-1",
                    "vega_incident_id": "inc-1",
                },
                {
                    "vega_entity_type": "Alert Event",
                    "vega_id": "alert-1",
                    "product_log_id": "alert-1:event:0",
                    "vega_incident_id": "inc-1",
                },
            ]
        }
    )
    assert targets["incidents"] == ["inc-1"]
    assert targets["alerts"] == ["alert-1"]


def test_soar_meta_round_trip() -> None:
    record = set_soar_meta({"id": "1"}, soar_alert_type=SOAR_ALERT_TYPE_ALERT)
    assert soar_meta(record)["soar_alert_type"] == SOAR_ALERT_TYPE_ALERT
