"""Helpers shared by the Flare SOAR actions."""

from __future__ import annotations

from .constants import DEFAULT_FLARE_API_URL, INTEGRATION_NAME
from .FlareManager import FlareManager
from .utils import resolve_action_tenant


def build_manager(siemplify, tenant_override=None) -> FlareManager:
    """
    Create a FlareManager from the integration configuration.

    The API key and tenant come from the integration instance; the optional
    ``Tenant ID`` action parameter selects one tenant when several are configured.
    """
    api_key = siemplify.extract_configuration_param(INTEGRATION_NAME, "Flare API Key", is_mandatory=True)
    config_tenant = siemplify.extract_configuration_param(INTEGRATION_NAME, "Flare Tenant ID", is_mandatory=True)
    return FlareManager(
        api_key=api_key,
        tenant_id=resolve_action_tenant(config_tenant, tenant_override),
        api_url=DEFAULT_FLARE_API_URL,
        logger_instance=siemplify.LOGGER,
    )
