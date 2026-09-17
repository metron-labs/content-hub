from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .auth_provider_v1 import AuthProviderV1
from .auth_provider_v2 import AuthProviderV2
from .constants import (
    API_VERSION_V1,
    API_VERSION_V2,
    INTEGRATION_NAME,
    PARAM_API_KEY,
    PARAM_API_VERSION,
    PARAM_CLIENT_ID,
    PARAM_CLIENT_SECRET,
    PARAM_ORG_CODE,
    PARAM_USER_API_KEY,
    SUPPORTED_API_VERSIONS,
)
from .exceptions import DoppelConfigError
from .token_cache import TokenCache


@dataclass(frozen=True)
class IntegrationConfig:
    api_version: str
    api_key: str | None = None
    user_api_key: str | None = None
    org_code: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def resolve_api_version(raw_value: Any) -> str:
    """Resolve a user-entered API version to v1 or v2.

    Missing/blank values default to v1 so existing installs keep working.
    """
    cleaned = _clean(raw_value)
    if not cleaned:
        return API_VERSION_V1

    normalized = cleaned.lower()
    if normalized in {API_VERSION_V1, "1"} or normalized.startswith("v1"):
        return API_VERSION_V1
    if normalized in {API_VERSION_V2, "2"} or normalized.startswith("v2"):
        return API_VERSION_V2
    raise DoppelConfigError(
        f"API Version must be {' or '.join(SUPPORTED_API_VERSIONS)}. Received an unsupported value.",
    )


def validate_config(config: IntegrationConfig) -> IntegrationConfig:
    if config.api_version == API_VERSION_V2:
        if not config.client_id or not config.client_secret:
            raise DoppelConfigError("Client ID and Client Secret are required for API v2")
        return config
    if not config.api_key:
        raise DoppelConfigError("API Key is required for API v1")
    return config


def load_integration_config(siemplify: Any) -> IntegrationConfig:
    api_version = resolve_api_version(
        siemplify.extract_configuration_param(
            provider_name=INTEGRATION_NAME,
            param_name=PARAM_API_VERSION,
        ),
    )
    config = IntegrationConfig(
        api_version=api_version,
        api_key=_clean(
            siemplify.extract_configuration_param(
                provider_name=INTEGRATION_NAME,
                param_name=PARAM_API_KEY,
            ),
        ),
        user_api_key=_clean(
            siemplify.extract_configuration_param(
                provider_name=INTEGRATION_NAME,
                param_name=PARAM_USER_API_KEY,
            ),
        ),
        org_code=_clean(
            siemplify.extract_configuration_param(
                provider_name=INTEGRATION_NAME,
                param_name=PARAM_ORG_CODE,
            ),
        ),
        client_id=_clean(
            siemplify.extract_configuration_param(
                provider_name=INTEGRATION_NAME,
                param_name=PARAM_CLIENT_ID,
            ),
        ),
        client_secret=_clean(
            siemplify.extract_configuration_param(
                provider_name=INTEGRATION_NAME,
                param_name=PARAM_CLIENT_SECRET,
            ),
        ),
    )
    return validate_config(config)


def create_auth_provider(
    config: IntegrationConfig,
    siemplify: Any | None = None,
    session: Any | None = None,
) -> AuthProviderV1 | AuthProviderV2:
    if config.api_version == API_VERSION_V2:
        return AuthProviderV2(
            client_id=config.client_id or "",
            client_secret=config.client_secret or "",
            token_cache=TokenCache(siemplify=siemplify),
            session=session,
        )
    return AuthProviderV1(
        api_key=config.api_key or "",
        user_api_key=config.user_api_key,
        org_code=config.org_code,
    )


def create_manager_from_siemplify(siemplify: Any):
    from .DoppelManager import DoppelManager

    config = load_integration_config(siemplify)
    logger = getattr(siemplify, "LOGGER", None)
    if logger:
        logger.info(f"Using Doppel API {config.api_version}")
    return DoppelManager.from_config(config, siemplify=siemplify)
