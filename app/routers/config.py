"""
UniFi configuration API endpoints for the main dashboard
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from typing import Optional

from shared.database import get_db_session
from shared.models.unifi_config import UniFiConfig
from shared.crypto import encrypt_password, decrypt_password, encrypt_api_key, decrypt_api_key
from shared.unifi_client import UniFiClient

router = APIRouter(prefix="/api/config", tags=["configuration"])


# Pydantic models
class UniFiConfigCreate(BaseModel):
    """
    Request model for UniFi controller configuration
    """
    controller_url: str = Field(..., description="UniFi controller URL")
    username: str = Field(..., description="UniFi admin username")
    password: Optional[str] = Field(None, description="Password for legacy controllers or UniFi OS")
    api_key: Optional[str] = Field(None, description="API key for UniFi OS (UDM, UCG, etc.)")
    site_id: str = Field(default="default", description="UniFi site ID")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificate")
    # Deprecated: is_unifi_os is now auto-detected during connection
    is_unifi_os: Optional[bool] = Field(default=None, description="Deprecated - auto-detected during connection")


class UniFiConfigResponse(BaseModel):
    """
    Response model for UniFi configuration (without password/API key)
    """
    id: int
    controller_url: str
    username: str
    has_api_key: bool
    site_id: str
    verify_ssl: bool
    is_unifi_os: bool
    last_successful_connection: Optional[datetime] = None


class UniFiConnectionTest(BaseModel):
    """
    Response model for UniFi connection test
    """
    connected: bool
    client_count: Optional[int] = None
    site_name: Optional[str] = None
    controller_version: Optional[str] = None
    error: Optional[str] = None


class SuccessResponse(BaseModel):
    """
    Generic success response
    """
    success: bool
    message: Optional[str] = None


class GatewayCheckResponse(BaseModel):
    """
    Response model for gateway availability check
    """
    has_gateway: bool
    supports_ids_ips: bool = False
    gateway_name: Optional[str] = None
    configured: bool
    error: Optional[str] = None
    # IPS settings (when available)
    ips_mode: Optional[str] = None  # "disabled", "ids", "ips", "ipsInline"
    ips_enabled: Optional[bool] = None


@router.post("/unifi", response_model=SuccessResponse)
async def save_unifi_config(
    config: UniFiConfigCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Save UniFi controller configuration
    Supports both legacy (username/password) and UniFi OS (API key) authentication
    """
    import logging
    logger = logging.getLogger(__name__)
    from shared import cache
    from shared.unifi_session import invalidate_shared_client

    try:
        # Validate that either password or API key is provided
        if not config.password and not config.api_key:
            raise HTTPException(
                status_code=400,
                detail="Either password or api_key must be provided"
            )

        # Invalidate cache and shared session since config is changing
        cache.invalidate_all()
        await invalidate_shared_client()

        # Encrypt credentials
        encrypted_password = None
        encrypted_api_key = None

        if config.password:
            logger.debug("Encrypting password...")
            encrypted_password = encrypt_password(config.password)
        if config.api_key:
            logger.debug("Encrypting API key...")
            encrypted_api_key = encrypt_api_key(config.api_key)

        # Check if config already exists
        logger.debug("Checking for existing config...")
        result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
        existing_config = result.scalar_one_or_none()

        # is_unifi_os is auto-detected during connection, default to False for storage
        is_unifi_os = config.is_unifi_os if config.is_unifi_os is not None else False

        if existing_config:
            # Update existing config
            logger.debug("Updating existing config...")
            existing_config.controller_url = config.controller_url
            existing_config.username = config.username
            existing_config.password_encrypted = encrypted_password
            existing_config.api_key_encrypted = encrypted_api_key
            existing_config.site_id = config.site_id
            existing_config.verify_ssl = config.verify_ssl
            existing_config.is_unifi_os = is_unifi_os
        else:
            # Create new config
            logger.debug("Creating new config...")
            new_config = UniFiConfig(
                id=1,
                controller_url=config.controller_url,
                username=config.username,
                password_encrypted=encrypted_password,
                api_key_encrypted=encrypted_api_key,
                site_id=config.site_id,
                verify_ssl=config.verify_ssl,
                is_unifi_os=is_unifi_os
            )
            db.add(new_config)

        logger.debug("Committing to database...")
        await db.commit()
        logger.info("UniFi configuration saved successfully")

        return SuccessResponse(
            success=True,
            message="UniFi configuration saved successfully"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to save UniFi config: {type(e).__name__}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save configuration: {type(e).__name__}: {str(e)}"
        )


@router.get("/unifi", response_model=UniFiConfigResponse)
async def get_unifi_config(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get current UniFi configuration (without password/API key)
    """
    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=404,
            detail="UniFi configuration not found. Please configure your UniFi controller first."
        )

    # Create response with has_api_key indicator
    return UniFiConfigResponse(
        id=config.id,
        controller_url=config.controller_url,
        username=config.username,
        has_api_key=config.api_key_encrypted is not None,
        site_id=config.site_id,
        verify_ssl=config.verify_ssl,
        is_unifi_os=config.is_unifi_os,
        last_successful_connection=config.last_successful_connection
    )


@router.post("/unifi/test", response_model=UniFiConnectionTest)
async def test_unifi_credentials(config: UniFiConfigCreate):
    """
    Test UniFi credentials WITHOUT saving them first.
    Use this to validate credentials before saving.
    """
    # Validate that either password or API key is provided
    if not config.password and not config.api_key:
        return UniFiConnectionTest(
            connected=False,
            error="Either password or api_key must be provided"
        )

    # Create UniFi client with provided credentials
    # is_unifi_os is auto-detected during connection
    client = UniFiClient(
        host=config.controller_url,
        username=config.username,
        password=config.password,
        api_key=config.api_key,
        site=config.site_id,
        verify_ssl=config.verify_ssl
    )

    test_result = await client.test_connection()
    return UniFiConnectionTest(**test_result)


@router.get("/unifi/test", response_model=UniFiConnectionTest)
async def test_saved_unifi_connection(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Test connection using saved UniFi configuration
    """
    # Get config from database
    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    config = result.scalar_one_or_none()

    if not config:
        return UniFiConnectionTest(
            connected=False,
            error="UniFi configuration not found. Please configure your UniFi controller first."
        )

    # Decrypt credentials
    password = None
    api_key = None

    try:
        if config.password_encrypted:
            password = decrypt_password(config.password_encrypted)
        if config.api_key_encrypted:
            api_key = decrypt_api_key(config.api_key_encrypted)
    except Exception as e:
        return UniFiConnectionTest(
            connected=False,
            error=f"Failed to decrypt credentials: {str(e)}"
        )

    # Create UniFi client and test connection
    # is_unifi_os is auto-detected during connection
    client = UniFiClient(
        host=config.controller_url,
        username=config.username,
        password=password,
        api_key=api_key,
        site=config.site_id,
        verify_ssl=config.verify_ssl
    )

    test_result = await client.test_connection()

    # Update last successful connection time if successful
    if test_result.get("connected"):
        config.last_successful_connection = datetime.now(timezone.utc)
        await db.commit()

    return UniFiConnectionTest(**test_result)


@router.get("/gateway-check", response_model=GatewayCheckResponse)
async def check_gateway_availability(
    db: AsyncSession = Depends(get_db_session),
    invalidate: str = None,
    refresh: str = None
):
    """
    Check if a UniFi Gateway is present on the site.
    This is required for Threat Watch (IDS/IPS features).

    This endpoint uses cached data from system-status when available
    to avoid making multiple concurrent connections to the controller.

    Query params:
    - invalidate=1: Clear cache before checking
    - refresh=1: Bypass cache and fetch fresh data

    Note: Legacy controllers (Cloud Key, self-hosted) do NOT expose IDS/IPS
    API endpoints, regardless of what gateway hardware is present.
    """
    from shared import cache
    import logging

    logger = logging.getLogger(__name__)

    # Handle cache invalidation
    if invalidate or refresh:
        logger.debug("Invalidating gateway cache due to request parameter")
        cache.invalidate("gateway_info")
        cache.invalidate("ips_settings")

    # First, check if we have cached gateway info
    cached_info = cache.get_gateway_info()
    cached_ips = cache.get_ips_settings()

    if cached_info is not None:
        logger.debug("Using cached gateway info for gateway-check")
        is_legacy = not cached_info.get("is_unifi_os", True)

        if is_legacy:
            gateway_name = cached_info.get("gateway_name", "Unknown")
            return GatewayCheckResponse(
                has_gateway=cached_info.get("has_gateway", False),
                supports_ids_ips=False,
                gateway_name=f"{gateway_name} (Legacy Controller)",
                configured=True
            )

        # Include IPS settings if available
        ips_mode = cached_ips.get("ips_mode") if cached_ips else None
        ips_enabled = cached_ips.get("ips_enabled") if cached_ips else None

        return GatewayCheckResponse(
            has_gateway=cached_info.get("has_gateway", False),
            supports_ids_ips=cached_info.get("supports_ids_ips", False),
            gateway_name=cached_info.get("gateway_name"),
            configured=True,
            ips_mode=ips_mode,
            ips_enabled=ips_enabled
        )

    # No cache - need to check config and possibly connect
    logger.debug("No cached gateway info, checking config")

    # Get config from database
    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    config = result.scalar_one_or_none()

    if not config:
        return GatewayCheckResponse(
            has_gateway=False,
            configured=False,
            error="UniFi controller not configured"
        )

    # Decrypt credentials
    password = None
    api_key = None

    try:
        if config.password_encrypted:
            password = decrypt_password(config.password_encrypted)
        if config.api_key_encrypted:
            api_key = decrypt_api_key(config.api_key_encrypted)
    except Exception as e:
        return GatewayCheckResponse(
            has_gateway=False,
            configured=True,
            error=f"Failed to decrypt credentials: {str(e)}"
        )

    # Create UniFi client and check for gateway
    # is_unifi_os is auto-detected during connection
    client = UniFiClient(
        host=config.controller_url,
        username=config.username,
        password=password,
        api_key=api_key,
        site=config.site_id,
        verify_ssl=config.verify_ssl
    )

    try:
        # Connect to controller (auto-detects UniFi OS vs legacy)
        connected = await client.connect()
        if not connected:
            return GatewayCheckResponse(
                has_gateway=False,
                supports_ids_ips=False,
                configured=True,
                error="Failed to connect to UniFi controller"
            )

        # Get gateway info including IDS/IPS support
        gateway_info = await client.get_gateway_info()

        # Cache the result for future requests
        cache.set_gateway_info({
            **gateway_info,
            "is_unifi_os": client.is_unifi_os
        })

        # Check if this is a legacy controller (detected during connection)
        # Legacy controllers don't expose IDS/IPS API regardless of gateway hardware
        is_legacy_controller = not client.is_unifi_os

        if is_legacy_controller:
            gateway_name = gateway_info.get("gateway_name", "Unknown")
            return GatewayCheckResponse(
                has_gateway=gateway_info.get("has_gateway", False),
                supports_ids_ips=False,
                gateway_name=f"{gateway_name} (Legacy Controller)",
                configured=True
            )

        # Get IPS settings if gateway supports IDS/IPS
        ips_mode = None
        ips_enabled = None
        if gateway_info.get("has_gateway") and gateway_info.get("supports_ids_ips"):
            ips_settings = await client.get_ips_settings()
            if ips_settings:
                cache.set_ips_settings(ips_settings)
                ips_mode = ips_settings.get("ips_mode")
                ips_enabled = ips_settings.get("ips_enabled")

        return GatewayCheckResponse(
            has_gateway=gateway_info.get("has_gateway", False),
            supports_ids_ips=gateway_info.get("supports_ids_ips", False),
            gateway_name=gateway_info.get("gateway_name"),
            configured=True,
            ips_mode=ips_mode,
            ips_enabled=ips_enabled
        )

    except Exception as e:
        return GatewayCheckResponse(
            has_gateway=False,
            supports_ids_ips=False,
            configured=True,
            error=str(e)
        )
    finally:
        await client.disconnect()
