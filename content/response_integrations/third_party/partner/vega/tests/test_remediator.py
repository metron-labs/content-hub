"""Tests for connector close-sync: status-only, exclusive incident vs alert paths."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from core.Remediator import SoarRemediator, extract_sync_targets

PRIOR_STATE = {"last_check_ms": 1_700_000_000_000, "processed_ids": []}


class FakeManager:
    def __init__(self) -> None:
        self.resolved_incidents: list[list[str]] = []
        self.resolved_alerts: list[list[str]] = []

    def resolve_incidents(self, incident_ids):
        self.resolved_incidents.append(list(incident_ids))
        return {"incidents": [{"incidentId": item, "status": "RESOLVED"} for item in incident_ids]}

    def resolve_alerts(self, alert_ids):
        self.resolved_alerts.append(list(alert_ids))
        return {"alerts": [{"id": item, "status": "RESOLVED"} for item in alert_ids]}


class FakeResponse:
    def __init__(self, payload, status=200) -> None:
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, results, details) -> None:
        self.results = results
        self.details = details
        self.posts: list[tuple] = []
        self.gets: list[str] = []

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        return FakeResponse({"results": self.results})

    def get(self, url, timeout=None):
        self.gets.append(url)
        case_id = url.split("GetCaseFullDetails/")[-1].split("?")[0]
        return FakeResponse(self.details.get(case_id) or {})


def _siemplify(ticket_cases: dict) -> SimpleNamespace:
    def _tickets(_since_ms):
        return list(ticket_cases)

    def _case(ticket_id):
        return ticket_cases.get(ticket_id) or {}

    return SimpleNamespace(
        get_alerts_ticket_ids_from_cases_closed_since_timestamp=_tickets,
        get_cases_by_ticket_id=_case,
    )


def _rest_siemplify(results, details, environment="Default Environment") -> SimpleNamespace:
    return SimpleNamespace(
        API_ROOT="https://soar.example",
        session=FakeSession(results, details),
        context=SimpleNamespace(
            connector_info=SimpleNamespace(environment=environment)
        ),
    )


def test_first_run_baselines_without_syncing_history() -> None:
    manager = FakeManager()
    siemplify = _siemplify(
        {
            "Vega:alert-3": {
                "events": [{"vega_entity_type": "Alert", "vega_id": "alert-3"}]
            }
        }
    )
    result = SoarRemediator(manager, siemplify).run_once({})
    assert manager.resolved_alerts == []
    assert manager.resolved_incidents == []
    assert "baseline" in result["message"].lower()
    assert int(result["state"]["last_check_ms"]) > 0


def test_close_unrelated_alert_resolves_that_alert_only() -> None:
    manager = FakeManager()
    siemplify = _siemplify(
        {
            "Vega:alert-3": {
                "events": [{"vega_entity_type": "Alert", "vega_id": "alert-3"}]
            }
        }
    )
    result = SoarRemediator(manager, siemplify).run_once(dict(PRIOR_STATE))
    assert manager.resolved_alerts == [["alert-3"]]
    assert manager.resolved_incidents == []
    assert "Synced 1" in result["message"]
    assert "case:" not in "".join(result["state"]["processed_ids"])
    assert "alert-3" in result["state"]["processed_ids"]


def test_close_incident_case_resolves_incident_not_related_alerts() -> None:
    manager = FakeManager()
    siemplify = _siemplify(
        {
            "Vega:inc-1": {
                "events": [
                    {"vega_entity_type": "Incident", "vega_id": "inc-1"},
                    {
                        "vega_entity_type": "Alert",
                        "vega_id": "alert-1",
                        "vega_incident_id": "inc-1",
                    },
                ]
            }
        }
    )
    SoarRemediator(manager, siemplify).run_once(dict(PRIOR_STATE))
    assert manager.resolved_incidents == [["inc-1"]]
    assert manager.resolved_alerts == []


def test_close_related_batch_resolves_alerts_not_incident() -> None:
    manager = FakeManager()
    payload = {
        "events": [
            {
                "vega_entity_type": "Alert",
                "vega_id": "alert-4",
                "vega_incident_id": "inc-1",
            },
            {
                "vega_entity_type": "Alert",
                "vega_id": "alert-5",
                "vega_incident_id": "inc-1",
            },
        ]
    }
    siemplify = _siemplify({"Vega:alert-4": payload, "Vega:alert-5": payload})
    SoarRemediator(manager, siemplify).run_once(dict(PRIOR_STATE))
    assert manager.resolved_incidents == []
    assert manager.resolved_alerts == [["alert-4", "alert-5"]]


def test_close_sync_falls_back_to_rest_without_sdk() -> None:
    manager = FakeManager()
    siemplify = SimpleNamespace(
        get_alerts_ticket_ids_from_cases_closed_since_timestamp=lambda _since: ["Vega:alert-3"],
        get_cases_by_ticket_id=None,
        API_ROOT="",
        session=None,
    )
    result = SoarRemediator(manager, siemplify).run_once(dict(PRIOR_STATE))
    assert manager.resolved_alerts == []
    assert manager.resolved_incidents == []
    assert "Synced 0" in result["message"]


def test_job_sdk_two_arg_signature_uses_rest_search() -> None:
    manager = FakeManager()

    def _job_sdk(_since, _rule_generator):
        raise AssertionError("must not guess a Vega rule generator")

    session = FakeSession(
        [{"id": "7", "title": "Vega Alert - alert-3 - brute force"}],
        {
            "7": {
                "id": 7,
                "cyberAlerts": [
                    {
                        "ticketId": "Vega:alert-3",
                        "securityEvents": [
                            {
                                "additionalProperties": json.dumps(
                                    {"vega_id": "alert-3", "vega_entity_type": "Alert"}
                                )
                            }
                        ],
                    }
                ],
            }
        },
    )
    siemplify = SimpleNamespace(
        get_alerts_ticket_ids_from_cases_closed_since_timestamp=_job_sdk,
        get_cases_by_ticket_id=lambda _ticket: {},
        API_ROOT="https://soar.example",
        session=session,
        context=SimpleNamespace(
            connector_info=SimpleNamespace(environment="Default Environment")
        ),
    )
    SoarRemediator(manager, siemplify).run_once(dict(PRIOR_STATE))
    assert manager.resolved_alerts == [["alert-3"]]
    assert manager.resolved_incidents == []
    assert session.posts
    assert "CaseSearchEverything" in session.posts[0][0]


def test_rest_search_resolves_incident_from_nested_case_details() -> None:
    manager = FakeManager()
    siemplify = _rest_siemplify(
        [{"id": "42", "title": "Vega Incident - INC-1 - phishing"}],
        {
            "42": {
                "id": 42,
                "title": "Vega Incident - INC-1 - phishing",
                "cyberAlerts": [
                    {
                        "ticketId": "Vega:inc-1",
                        "securityEvents": [
                            {
                                "additionalProperties": json.dumps(
                                    {
                                        "vega_id": "inc-1",
                                        "vega_entity_type": "Incident",
                                    }
                                )
                            },
                            {
                                "additionalProperties": json.dumps(
                                    {
                                        "vega_id": "alert-1",
                                        "vega_entity_type": "Alert",
                                        "vega_incident_id": "inc-1",
                                    }
                                )
                            },
                        ],
                    }
                ],
            }
        },
    )
    result = SoarRemediator(manager, siemplify).run_once(dict(PRIOR_STATE))
    assert manager.resolved_incidents == [["inc-1"]]
    assert manager.resolved_alerts == []
    assert "case:42" in result["state"]["processed_ids"]
    assert "inc-1" in result["state"]["processed_ids"]
    posted = siemplify.session.posts[0][1]
    assert posted["isCaseClosed"] is True
    assert posted["title"] == "Vega"
    assert posted["environments"] == ["Default Environment"]


def test_extract_sync_targets_skips_child_events_on_related_batch() -> None:
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
                    "vega_id": "alert-1:event:0",
                    "vega_incident_id": "inc-1",
                },
            ]
        }
    )
    assert targets["mode"] == "alerts"
    assert targets["alert_ids"] == ["alert-1"]
    assert targets["incident_ids"] == []


def test_extract_sync_targets_reads_json_additional_properties() -> None:
    targets = extract_sync_targets(
        {
            "cyberAlerts": [
                {
                    "securityEvents": [
                        {
                            "additionalProperties": json.dumps(
                                {
                                    "vega_id": "alert-9",
                                    "vega_entity_type": "Alert",
                                }
                            )
                        }
                    ]
                }
            ]
        }
    )
    assert targets["mode"] == "alerts"
    assert targets["alert_ids"] == ["alert-9"]


def test_resolve_helpers_are_used_not_full_update() -> None:
    manager = MagicMock()
    manager.resolve_incidents = MagicMock(return_value={})
    manager.resolve_alerts = MagicMock(return_value={})
    manager.update_incidents = MagicMock()
    manager.update_alerts = MagicMock()
    siemplify = _siemplify(
        {"Vega:inc-1": {"events": [{"vega_entity_type": "Incident", "vega_id": "inc-1"}]}}
    )
    SoarRemediator(manager, siemplify).run_once(dict(PRIOR_STATE))
    manager.resolve_incidents.assert_called_once_with(["inc-1"])
    manager.update_incidents.assert_not_called()
    manager.update_alerts.assert_not_called()
    manager.resolve_alerts.assert_not_called()
