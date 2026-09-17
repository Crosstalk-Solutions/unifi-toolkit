"""
UniFi configuration API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone

from shared.database import get_db_session
from shared.models.unifi_config import UniFiConfig
from shared.crypto import encrypt_password, decrypt_password, encrypt_api_key, decrypt_api_key
from shared.unifi_client import UniFiClient
from shared.url_validator import validate_controller_url
from tools.wifi_stalker.models import (
    UniFiConfigCreate,
    UniFiConfigResponse,
    UniFiConnectionTest,
    SuccessResponse
)

router = APIRouter(prefix="/api/config", tags=["configuration"])


@router.post("/unifi", response_model=SuccessResponse)
async def save_unifi_config(
    config: UniFiConfigCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Save UniFi controller configuration
    Supports both legacy (username/password) and UniFi OS (API key) authentication
    """
    # Reject SSRF-prone controller URLs (non-http(s) schemes, embedded creds).
    url_ok, url_err = validate_controller_url(config.controller_url)
    if not url_ok:
        raise HTTPException(status_code=400, detail=url_err)

    # Validate that either password or API key is provided
    if not config.password and not config.api_key:
        raise HTTPException(
            status_code=400,
            detail="Either password or api_key must be provided"
        )

    # Encrypt credentials
    encrypted_password = None
    encrypted_api_key = None

    if config.password:
        encrypted_password = encrypt_password(config.password)
    if config.api_key:
        encrypted_api_key = encrypt_api_key(config.api_key)

    # Check if config already exists
    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    existing_config = result.scalar_one_or_none()

    if existing_config:
        # Update existing config
        existing_config.controller_url = config.controller_url
        existing_config.username = config.username
        existing_config.password_encrypted = encrypted_password
        existing_config.api_key_encrypted = encrypted_api_key
        existing_config.site_id = config.site_id
        existing_config.verify_ssl = config.verify_ssl
    else:
        # Create new config
        new_config = UniFiConfig(
            id=1,
            controller_url=config.controller_url,
            username=config.username,
            password_encrypted=encrypted_password,
            api_key_encrypted=encrypted_api_key,
            site_id=config.site_id,
            verify_ssl=config.verify_ssl
        )
        db.add(new_config)

    await db.commit()

    return SuccessResponse(
        success=True,
        message="UniFi configuration saved successfully"
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
        last_successful_connection=config.last_successful_connection
    )


@router.get("/unifi/test", response_model=UniFiConnectionTest)
async def test_unifi_connection(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Test connection to UniFi controller
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


async def get_unifi_client(db: AsyncSession = Depends(get_db_session)) -> UniFiClient:
    """
    Dependency to get a configured UniFi client instance
    """
    # Get config from database
    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=404,
            detail="UniFi configuration not found. Please configure your UniFi controller first."
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
        raise HTTPException(
            status_code=500,
            detail=f"Failed to decrypt UniFi credentials: {str(e)}"
        )

    # Create and return UniFi client
    return UniFiClient(
        host=config.controller_url,
        username=config.username,
        password=password,
        api_key=api_key,
        site=config.site_id,
        verify_ssl=config.verify_ssl
    )
