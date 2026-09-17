"""
UniFi configuration API endpoints for Threat Watch
Reuses shared UniFi configuration but adds Threat Watch specific endpoints
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
from tools.threat_watch.models import SuccessResponse

router = APIRouter(prefix="/api/config", tags=["configuration"])


# Pydantic models for UniFi config (local to avoid circular imports)
from pydantic import BaseModel, Field, field_serializer
from typing import Optional


def serialize_datetime(dt):
    if dt is None:
        return None
    if dt.tzinfo is not None:
        from datetime import timezone as tz
        dt_utc = dt.astimezone(tz.utc)
        return dt_utc.isoformat().replace('+00:00', 'Z')
    return dt.isoformat() + 'Z'


class UniFiConfigCreate(BaseModel):
    controller_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    site_id: str = "default"
    verify_ssl: bool = False


class UniFiConfigResponse(BaseModel):
    id: int
    controller_url: str
    username: Optional[str]
    has_api_key: bool
    site_id: str
    verify_ssl: bool
    last_successful_connection: Optional[datetime]

    @field_serializer('last_successful_connection')
    def serialize_dt(self, dt, _info):
        return serialize_datetime(dt)

    class Config:
        from_attributes = True


class UniFiConnectionTest(BaseModel):
    connected: bool
    client_count: Optional[int] = None
    ap_count: Optional[int] = None
    site: Optional[str] = None
    error: Optional[str] = None
    ips_events_available: Optional[bool] = None


@router.post("/unifi", response_model=SuccessResponse)
async def save_unifi_config(
    config: UniFiConfigCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Save UniFi controller configuration
    """
    # Reject SSRF-prone controller URLs (non-http(s) schemes, embedded creds).
    url_ok, url_err = validate_controller_url(config.controller_url)
    if not url_ok:
        raise HTTPException(status_code=400, detail=url_err)

    if not config.password and not config.api_key:
        raise HTTPException(
            status_code=400,
            detail="Either password or api_key must be provided"
        )

    encrypted_password = None
    encrypted_api_key = None

    if config.password:
        encrypted_password = encrypt_password(config.password)
    if config.api_key:
        encrypted_api_key = encrypt_api_key(config.api_key)

    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    existing_config = result.scalar_one_or_none()

    if existing_config:
        existing_config.controller_url = config.controller_url
        existing_config.username = config.username
        existing_config.password_encrypted = encrypted_password
        existing_config.api_key_encrypted = encrypted_api_key
        existing_config.site_id = config.site_id
        existing_config.verify_ssl = config.verify_ssl
    else:
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
    Test connection to UniFi controller and check IPS events availability
    """
    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    config = result.scalar_one_or_none()

    if not config:
        return UniFiConnectionTest(
            connected=False,
            error="UniFi configuration not found. Please configure your UniFi controller first."
        )

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

    client = UniFiClient(
        host=config.controller_url,
        username=config.username,
        password=password,
        api_key=api_key,
        site=config.site_id,
        verify_ssl=config.verify_ssl
    )

    test_result = await client.test_connection()

    # Also test IPS events availability
    ips_available = False
    if test_result.get("connected"):
        try:
            await client.connect()
            events = await client.get_ips_events(limit=1)
            ips_available = True  # If we get here without error, IPS is available
            await client.disconnect()
        except Exception:
            ips_available = False

        config.last_successful_connection = datetime.now(timezone.utc)
        await db.commit()

    return UniFiConnectionTest(
        connected=test_result.get("connected", False),
        client_count=test_result.get("client_count"),
        ap_count=test_result.get("ap_count"),
        site=test_result.get("site"),
        error=test_result.get("error"),
        ips_events_available=ips_available if test_result.get("connected") else None
    )


async def get_unifi_client(db: AsyncSession = Depends(get_db_session)) -> UniFiClient:
    """
    Dependency to get a configured UniFi client instance
    """
    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(
            status_code=404,
            detail="UniFi configuration not found. Please configure your UniFi controller first."
        )

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

    return UniFiClient(
        host=config.controller_url,
        username=config.username,
        password=password,
        api_key=api_key,
        site=config.site_id,
        verify_ssl=config.verify_ssl
    )
