import pytest

from core.exceptions import VegaValidationException
from core.utils import (
    format_test_connection_summary,
    validate_connector_fields,
)
from core.VegaManager import VegaManager


class DummySession:
    trust_env = False
    verify = True


def _valid_kwargs(**overrides):
    values = {
        "api_root": "https://api.vega.io",
        "access_key_id": "kid",
        "access_key": "secret",
        "entities_raw": "Alerts,Incidents",
        "lookback_minutes": "5",
        "backfill_days": "30",
        "alert_severities": "LOW,HIGH",
        "alert_statuses": "",
        "alert_verdicts": "",
        "has_related": "Yes,No",
        "incident_severities": "",
        "incident_statuses": "",
        "incident_verdicts": "",
        "python_timeout": "930",
    }
    values.update(overrides)
    return values


def test_validate_connector_fields_accepts_valid_values() -> None:
    validate_connector_fields(**_valid_kwargs())


def test_validate_connector_fields_lists_every_invalid_field() -> None:
    with pytest.raises(VegaValidationException) as exc:
        validate_connector_fields(
            **_valid_kwargs(
                api_root="http://not-https.example",
                access_key_id="",
                entities_raw="Foo",
                lookback_minutes="999",
                alert_severities="URGENT",
                has_related="Maybe",
                python_timeout="abc",
            )
        )
    text = str(exc.value)
    assert "Cannot run the Vega Alerts and Incidents Connector" in text
    assert "API Root" in text
    assert "Access Key ID" in text
    assert "Vega Entities to Fetch" in text
    assert "Fetch Lookback (Minutes)" in text
    assert "Alert Severities to Fetch" in text
    assert "Has Related Incidents" in text
    assert "PythonProcessTimeout" in text
    assert "URGENT" in text
    assert "Maybe" in text


def test_format_test_connection_summary_lists_counts() -> None:
    text = format_test_connection_summary(
        incident_count=12,
        related_alert_count=34,
        unrelated_alert_count=8,
        total_alert_count=42,
        sample_count=3,
    )
    assert "Successfully connected to Vega." in text
    assert "- Vega incidents: 12" in text
    assert "- Vega related alerts: 34" in text
    assert "- Vega unrelated alerts: 8" in text
    assert "- Total Vega alerts: 42" in text
    assert "Showing 3 sample alert(s) below. Nothing was ingested." in text


def test_format_test_connection_summary_hides_unrelated_when_yes_only() -> None:
    text = format_test_connection_summary(
        incident_count=3,
        related_alert_count=1,
        unrelated_alert_count=105,
        total_alert_count=1,
        sample_count=1,
        include_incidents=True,
        include_related=True,
        include_unrelated=False,
    )
    assert "- Vega incidents: 3" in text
    assert "- Vega related alerts: 1" in text
    assert "unrelated" not in text.lower()
    assert "- Total Vega alerts: 1" in text
    assert "105" not in text


def test_count_alerts_uses_graphql_total() -> None:
    manager = VegaManager(
        api_root="https://api.vega.io",
        access_key_id="kid",
        access_key="secret",
        session=DummySession(),
        sleeper=lambda _seconds: None,
    )
    manager._jwt = "token"

    def _graphql(_query, variables=None):
        assert variables["limit"] == 1
        return {"getAlerts": {"alerts": [{"id": "a-1"}], "total": 42}}

    manager.graphql = _graphql
    assert manager.count_alerts({"hasRelatedIncidents": True}) == 42


def test_get_incident_uses_uuid_or_vega_id_not_both() -> None:
    manager = VegaManager(
        api_root="https://api.vega.io",
        access_key_id="kid",
        access_key="secret",
        session=DummySession(),
        sleeper=lambda _seconds: None,
    )
    calls: list[dict] = []

    def _get_incidents(variables, max_records=None):
        calls.append(dict(variables or {}))
        return [{"id": "inc-1"}]

    manager.get_incidents = _get_incidents
    uuid = "019e1b27-5119-7822-bde3-344b13e481cf"
    assert manager.get_incident(uuid)["id"] == "inc-1"
    assert calls == [{"incidentIds": [uuid]}]
    calls.clear()
    assert manager.get_incident("VINC-1")["id"] == "inc-1"
    assert calls == [{"vegaIncidentIds": ["VINC-1"]}]
