"""Shared constants for the Vega Google SecOps integration."""
from __future__ import annotations

INTEGRATION_NAME = "Vega"
DEVICE_PRODUCT = "Vega"
PRODUCT_NAME = "Vega"
VENDOR_NAME = "Vega"
ENTITY_TYPE_ALERT = "Alert"
ENTITY_TYPE_INCIDENT = "Incident"

PING_SCRIPT_NAME = f"{INTEGRATION_NAME} - Ping"
GET_ALERT_EVENTS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Alert Events"
GET_INCIDENT_TIMELINE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Incident Timeline"
GET_INCIDENT_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Incident Details"
SET_DETECTIONS_STATE_SCRIPT_NAME = f"{INTEGRATION_NAME} - Set Detections State"
UPDATE_DETECTIONS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Update Detections"
UPDATE_ALERT_SCRIPT_NAME = f"{INTEGRATION_NAME} - Update Alert"
UPDATE_INCIDENT_SCRIPT_NAME = f"{INTEGRATION_NAME} - Update Incident"

CONNECTOR_NAME = "Vega Alerts and Incidents Connector"
CHECKPOINT_PROPERTY_KEY = "vega_ingestion_checkpoint"
REMEDIATION_PROPERTY_KEY = "vega_sync_state"

DEFAULT_API_ROOT = "https://api.vega.io"
LOGIN_PATH = "/api/v1/login_machine"
QUERY_PATH = "/api/v1/query"

DEFAULT_HTTP_TIMEOUT = (10, 60)
LOOKBACK_MIN = 1
LOOKBACK_MAX = 60
BACKFILL_MIN = 0
BACKFILL_MAX = 365
GRAPHQL_PAGE_SIZE = 50
ALERT_EVENTS_PAGE_SIZE = 100
ALERT_EVENTS_MAX_FETCH = 2500
MAX_EVENTS_PER_ALERT = 200
TIMELINE_PAGE_SIZE = 100
TIMELINE_MAX_FETCH = 2500
TEST_RUN_MAX_FETCH = 5
MAX_CONSECUTIVE_429 = 6
RATE_LIMIT_INITIAL_WAIT_SECONDS = 2
RATE_LIMIT_STEP_SECONDS = 2
SERVER_ERROR_RETRIES = 3
SERVER_ERROR_WAIT_SECONDS = 2
INGESTED_ID_CAP = 5000
PYTHON_PROCESS_TIMEOUT_DEFAULT = "930"

INTEGRATION_VERSION = 2
DOCUMENTATION_LINK = "https://vega.io"

PARAM_API_ROOT = "API Root"
PARAM_ACCESS_KEY_ID = "Access Key ID"
PARAM_ACCESS_KEY = "Access Key"
PARAM_ENTITIES = "Vega Entities to Fetch"
PARAM_LOOKBACK = "Fetch Lookback (Minutes)"
PARAM_BACKFILL = "Max Days Backwards"
PARAM_ALERT_SEVERITIES = "Alert Severities to Fetch"
PARAM_ALERT_STATUSES = "Alert Statuses to Fetch"
PARAM_ALERT_VERDICTS = "Alert Verdicts to Fetch"
PARAM_HAS_RELATED = "Has Related Incidents"
PARAM_INCIDENT_SEVERITIES = "Incident Severities to Fetch"
PARAM_INCIDENT_STATUSES = "Incident Statuses to Fetch"
PARAM_INCIDENT_VERDICTS = "Incident Verdicts to Fetch"
PARAM_SYNC = "Sync Case Close to Vega"

SEVERITY_OPTIONS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ALERT_STATUS_OPTIONS = ("OPEN", "IN PROGRESS", "PEER REVIEW", "RESOLVED")
INCIDENT_STATUS_OPTIONS = (
    "NEW",
    "INVESTIGATING",
    "ON HOLD",
    "EXTERNAL ESCALATION",
    "RESOLVED",
    "REOPENED",
    "REVIEW RECOMMENDED",
    "RESPONSE REQUIRED",
    "UNDER REVIEW",
)
VERDICT_OPTIONS = ("MALICIOUS", "SUSPICIOUS", "BENIGN", "INCONCLUSIVE", "NA")
ENTITY_OPTIONS = ("Alerts", "Incidents")
RELATED_OPTIONS = ("Yes", "No")
DETECTION_STATES = ("ENABLED", "DISABLED", "TEST_MODE")

SEVERITY_TO_ALERT_PRIORITY = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 60,
    "LOW": 40,
}

MSG_UNAUTHORIZED = (
    "The Access Key or Access Key ID is incorrect. Check both values and try again."
)
MSG_INVALID_ACCESS_KEY = (
    "The Access Key is incorrect. Enter a valid Access Key and try again."
)
MSG_INVALID_ACCESS_KEY_ID = (
    "The Access Key ID is incorrect. Enter a valid Access Key ID and try again."
)
MSG_INVALID_API_ROOT = (
    "The API Root is incorrect or unreachable. Enter a valid Vega HTTPS URL, "
    "for example https://api.vega.io."
)
MSG_FORBIDDEN = "Access denied by Vega. Verify the Access Key permissions."
MSG_BAD_REQUEST = "Invalid request to Vega. Check filters and identifiers."
MSG_NOT_FOUND = "Requested Vega resource was not found."
MSG_RATE_LIMIT = "Vega rate limit reached. Wait and try again."
MSG_SERVER_ERROR = "Vega is temporarily unavailable. Try again later."
MSG_TIMEOUT = (
    "Connection to Vega timed out. Check the API Root and network access, "
    "then try again."
)
MSG_UNREACHABLE = MSG_INVALID_API_ROOT

GET_ALERTS_QUERY = """
query GetAlerts(
  $alertSeverities: [AlertSeverity!],
  $statuses: [AlertStatus!],
  $alertVerdicts: [AlertVerdict!],
  $hasRelatedIncidents: Boolean,
  $from: Time,
  $to: Time,
  $updatedFrom: Time,
  $updatedTo: Time,
  $limit: Int,
  $offset: Int
) {
  getAlerts(
    alertSeverities: $alertSeverities,
    statuses: $statuses,
    alertVerdicts: $alertVerdicts,
    hasRelatedIncidents: $hasRelatedIncidents,
    from: $from,
    to: $to,
    updatedFrom: $updatedFrom,
    updatedTo: $updatedTo,
    limit: $limit,
    offset: $offset
  ) {
    alerts {
      id
      vegaAlertId
      detectionId
      name
      description
      severity
      status
      assignee { userId displayName email }
      assignees { userId displayName email }
      dataSources
      createdAt
      updatedAt
      mitre { mitreTactics mitreTechniques }
      relatedIncidents { incidentId name }
      detectionSource
      detectionDescription
      detectionQuery
      eventCount
      isTestMode
      verdict
      verdictReasoning
      dedupCount
      comments { text addedBy addedAt }
      href
    }
    total
    limit
    offset
    error { code message }
  }
}
""".strip()

GET_INCIDENTS_QUERY = """
query GetIncidents(
  $incidentNames: [String!],
  $nameContains: String,
  $incidentIds: [ID!],
  $vegaIncidentIds: [String!],
  $severities: [IncidentSeverity!],
  $statuses: [IncidentStatusPublic!],
  $verdicts: [IncidentVerdictPublic!],
  $assets: [String!],
  $from: Time,
  $to: Time,
  $updatedFrom: Time,
  $updatedTo: Time,
  $sortBy: IncidentSortFieldPublic,
  $sortOrder: SortOrderPublic,
  $limit: Int,
  $offset: Int
) {
  getIncidents(
    incidentNames: $incidentNames,
    nameContains: $nameContains,
    incidentIds: $incidentIds,
    vegaIncidentIds: $vegaIncidentIds,
    severities: $severities,
    statuses: $statuses,
    verdicts: $verdicts,
    assets: $assets,
    from: $from,
    to: $to,
    updatedFrom: $updatedFrom,
    updatedTo: $updatedTo,
    sortBy: $sortBy,
    sortOrder: $sortOrder,
    limit: $limit,
    offset: $offset
  ) {
    incidents {
      id
      vegaUniqueIncidentId
      name
      createdBy
      createdAt
      lastUpdated
      severity
      status
      dataSources
      verdict
      verdictReasoning
      assignee { userId displayName email }
      assignees { userId displayName email }
      comments { text addedBy addedAt }
      incidentSummary
      incidentFindings
      assets
      observables
      alertsCount
      alerts { alertId name createdAt }
      recommendedActions { name description actionKey targetParams }
      investigationPlan {
        stepName
        stepConclusion
        cells { cellName query queryId }
      }
      labels { id categoryId name color usageCount }
      skills { id name version }
      link
      href
    }
    total
    limit
    offset
    error { code message }
  }
}
""".strip()

GET_ALERT_EVENTS_QUERY = """
query GetAlertsEvents($alertId: ID!, $limit: Int, $offset: Int) {
  getAlertsEvents(alertId: $alertId, limit: $limit, offset: $offset) {
    total
    limit
    offset
    results
    error { code message }
  }
}
""".strip()

GET_INCIDENT_TIMELINE_QUERY = """
query GetIncidentTimeline($incidentId: ID!, $limit: Int, $offset: Int) {
  getIncidentTimeline(incidentId: $incidentId, limit: $limit, offset: $offset) {
    events {
      id
      timestamp
      summary
      dataSources
      assets
      observables
      alert { alertId name createdAt }
    }
    total
    limit
    offset
    error { code message }
  }
}
""".strip()

SET_DETECTIONS_STATE_MUTATION = """
mutation SetDetectionsState($input: SetDetectionsStateInput!) {
  setDetectionsState(input: $input) { ids }
}
""".strip()

UPDATE_DETECTIONS_MUTATION = """
mutation UpdateDetections($input: UpdateDetectionsInput!) {
  updateDetections(input: $input) {
    results {
      name
      status
      errors { code message field }
      detection {
        id
        name
        severity
        state
        status
        tags
      }
    }
    summary { requested valid invalid committed }
  }
}
""".strip()

UPDATE_ALERTS_MUTATION = """
mutation UpdateAlerts($input: UpdateAlertsInput!) {
  updateAlerts(input: $input) {
    alerts {
      id
      vegaAlertId
      severity
      status
      verdict
      verdictReasoning
      assignee { userId displayName email }
      assignees { userId displayName email }
      comments { text addedBy addedAt }
    }
    error { code message }
  }
}
""".strip()

UPDATE_INCIDENTS_MUTATION = """
mutation UpdateIncidents($input: UpdateIncidentsInput!) {
  updateIncidents(input: $input) {
    incidents {
      incidentId
      incidentName
      status
      assignee { userId displayName email }
      assignees { userId displayName email }
      verdict
      verdictReasoning
      updatedAt
    }
    errors { code message }
  }
}
""".strip()
