"""Shared constants for the Flare - Google SecOps integration."""
from __future__ import annotations

INTEGRATION_NAME = "Flare"
DEVICE_PRODUCT = "Flare"
PRODUCT_NAME = "Flare"
# Distinct marker so SOAR alerts can be verified as connector-sourced.
# Also used as AlertInfo.rule_generator for closed-case remediation lookup.
VENDOR_NAME = "Flare"

# Action script names
PING_SCRIPT_NAME = f"{INTEGRATION_NAME} - Ping"
GET_EVENT_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Event Details"
GET_EVENT_FIELD_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Event Field Details"
GET_EVENT_AI_INSIGHTS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Event AI Insights"
EXECUTE_EVENT_ACTION_SCRIPT_NAME = f"{INTEGRATION_NAME} - Execute Event Action"
EXPLAIN_IDENTIFIER_MATCH_SCRIPT_NAME = f"{INTEGRATION_NAME} - Explain Identifier Match"
SEARCH_GLOBAL_DATA_SCRIPT_NAME = f"{INTEGRATION_NAME} - Search Global Data"
GET_GLOBAL_SEARCH_QUOTA_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Global Search Quota"
LIST_IDENTIFIERS_SCRIPT_NAME = f"{INTEGRATION_NAME} - List Identifiers"
GET_IDENTIFIER_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Identifier Details"
SET_IDENTIFIER_STATUS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Set Identifier Status"
LIST_ALERTS_SCRIPT_NAME = f"{INTEGRATION_NAME} - List Alerts"
GET_ALERT_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Alert Details"
LIST_ALERT_CHANNELS_SCRIPT_NAME = f"{INTEGRATION_NAME} - List Alert Channels"
LIST_ENTITIES_SCRIPT_NAME = f"{INTEGRATION_NAME} - List Entities"
GET_ENTITY_DETAILS_SCRIPT_NAME = f"{INTEGRATION_NAME} - Get Entity Details"

# Connector
THREAT_FINDINGS_CONNECTOR_NAME = "Flare Connector"
CHECKPOINT_PROPERTY_KEY = "flare_ingestion_checkpoint"
REMEDIATION_PROPERTY_KEY = "flare_remediation_state"

# Flare API endpoints
ENDPOINT_EVENTS_SEARCH = "/firework/v4/events/tenant/_search"
ENDPOINT_EVENTS_DETAIL = "/firework/v4/events/"
ENDPOINT_EVENT_ACTIONS = "/firework/v4/events/actions"
ENDPOINT_FILTER_SEVERITIES = "/firework/v4/events/filters/severities"
ENDPOINT_FILTER_TYPES = "/firework/v4/events/filters/types"
ENDPOINT_TENANTS = "/firework/v2/me/tenants"
# Paths below follow the "Target Endpoint" column of the Flare Actions API list
# verbatim. Verify them against https://api.docs.flare.io before release;
# they are centralised here so a correction is a one-line change.
ENDPOINT_EVENTS_EXPAND = "/events/v2/expand"
ENDPOINT_EVENTS_AI_ASSISTANCE = "/events/ai-assistance"
ENDPOINT_EVENTS_EXPLAIN_IDENTIFIER = "/events/explain-identifier"
ENDPOINT_GLOBAL_SEARCH = "/global/_search"
ENDPOINT_GLOBAL_SEARCH_QUOTA = "/global/_search/quota"
ENDPOINT_IDENTIFIERS = "/firework/v4/identifiers/"
ENDPOINT_ALERTS = "/firework/v4/alerts/"
ENDPOINT_ALERT_CHANNELS = "/firework/v4/alerts/channels"
ENDPOINT_ENTITIES_LIST = "/entities/_list"
ENDPOINT_ENTITIES = "/entities/"

# Action inputs
EVENT_ACTION_TYPES = ("remediate", "ignore", "unignore")
MAX_EVENT_ACTION_TARGETS = 10
DEFAULT_MAX_RECORDS = 50
HARD_MAX_RECORDS = 1000
OFFSET_PAGE_SIZE = 100

DEFAULT_FLARE_API_URL = "https://api.flare.io"
DEFAULT_FLARE_APP_URL = "https://app.flare.io"
DEFAULT_FLARE_DOCS_URL = "https://flare.io"
DEFAULT_FLARE_ACTION_BATCH_SIZE = 10
DEFAULT_FLARE_PAGE_SIZE = 10
# (connect timeout seconds, read timeout seconds) for outbound Flare HTTP.
DEFAULT_HTTP_TIMEOUT = (10, 60)
# SOAR SDK HTTP fallbacks (CaseFullDetails, closed-case lookups, etc.).
DEFAULT_SDK_HTTP_TIMEOUT = (10, 60)
MAX_BACKFILL_RANGE_DAYS = 180
MAX_FLARE_PAGE_SIZE = 10
# Package / integration release version (keep defs in sync).
INTEGRATION_VERSION = 2.0
SEVERITY_OPTIONS = ("info", "low", "medium", "high", "critical")
SEVERITY_TO_ALERT_PRIORITY = {
    "critical": 100,
    "high": 80,
    "medium": 60,
    "low": 40,
    "info": 20,
}
TYPE_DISPLAY_NAME = {
    "paste": "Paste site exposure",
    "chat_message": "Chat message exposure",
    "driller": "Source code exposure",
    "service": "Exposed service",
    "forum_post": "Hacker forum post",
    "forum_content": "Hacker forum content",
    "listing": "Dark web marketplace listing",
    "blog_post": "Threat blog post",
    "blog_content": "Threat blog content",
    "bot": "Stealer log / bot exposure",
    "leaked_credential": "Leaked credential",
    "valid_credential": "Valid leaked credential",
    "invalid_credential": "Invalid leaked credential",
    "mitigated_credential": "Mitigated leaked credential",
    "ransomleak": "Ransomware leak",
    "infected_devices": "Infected device",
    "financial_data": "Financial data exposure",
    "social_media": "Social media exposure",
    "source_code": "Source code exposure",
    "buckets": "Cloud bucket exposure",
    "leak": "Data leak",
    "profile": "Profile exposure",
    "google": "Google",
    "domain": "Look-alike Domains",
}

# HTTP status codes
BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
NOT_FOUND = 404
TOO_MANY_REQUESTS = 429
SERVER_ERROR = 500

# https://api.docs.flare.io/concepts/rate-limits-and-quotas
# Limits are per organization. Search and basic are independent buckets.
FLARE_BASIC_REQUESTS_PER_SECOND = 4
FLARE_SEARCH_REQUESTS_PER_SECOND = 1
# Flare: on HTTP 429, wait 10 seconds before retrying.
FLARE_RATE_LIMIT_RETRY_WAIT_SECONDS = 10
FLARE_HTTP_RETRIES = 5

# Operator-facing Flare HTTP messages (shared by manager + utils).
MSG_BAD_REQUEST = (
    "Invalid request to Flare. Check the connector filters and try again."
)
MSG_UNAUTHORIZED = (
    "Invalid API Key. Please check your credentials and try again."
)
MSG_FORBIDDEN = (
    "Access denied for this Flare Tenant ID. "
    "Verify the tenant ID and API key permissions."
)
MSG_NOT_FOUND = (
    "Requested Flare resource was not found. Verify the tenant ID and filters."
)
MSG_RATE_LIMIT = (
    "Flare rate limit reached after retries. The next connector run will try again."
)
MSG_SERVER_ERROR = (
    "Flare service is temporarily unavailable. Please try again later."
)
