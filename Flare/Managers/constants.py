"""Shared constants for the Flare - Google SecOps integration."""

INTEGRATION_NAME = "Flare"
DEVICE_PRODUCT = "Flare"
PRODUCT_NAME = "Flare"
# Distinct marker so SOAR alerts can be verified as connector-sourced.
# Also used as AlertInfo.rule_generator for closed-case remediation lookup.
VENDOR_NAME = "Flare"

# Action script names
PING_SCRIPT_NAME = f"{INTEGRATION_NAME} - Ping"

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
MAX_EVENTS_PER_ALERT = 500
# Package / integration release version (keep defs in sync).
INTEGRATION_VERSION = 1.0
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
MSG_RATE_LIMIT = "Flare rate limit reached. Wait a moment and try again."
MSG_SERVER_ERROR = (
    "Flare service is temporarily unavailable. Please try again later."
)
