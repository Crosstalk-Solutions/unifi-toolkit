"""
Shared UniFi session singleton.

Provides a single persistent UniFiClient instance shared across all schedulers
(Threat Watch, Wi-Fi Stalker, Network Pulse) to avoid repeated logins that
trigger fail2ban on username/password auth controllers.

The client initializes lazily on the first scheduler call and reconnects
automatically if the session goes stale. Config changes (via the web UI)
invalidate the shared client so the next poll picks up new credentials.
"""
import logging
from typing import Optional

from sqlalchemy import select

from shared.database import get_database
from shared.models.unifi_config import UniFiConfig
from shared.unifi_client import UniFiClient
from shared.crypto import decrypt_password, decrypt_api_key

logger = logging.getLogger(__name__)

# Singleton client instance
_shared_client: Optional[UniFiClient] = None


async def get_shared_client() -> Optional[UniFiClient]:
    """
    Get the shared UniFi client, creating and connecting it if needed.

    On first call: reads config from DB, decrypts credentials, creates client,
    and connects. On subsequent calls: returns the existing connected client.
    If the session is closed or stale, reconnects automatically.

    Returns:
        Connected UniFiClient, or None if no config or connection fails.
    """
    global _shared_client

    # If we have a client with a live session, return it
    if _shared_client is not None and _shared_client._session is not None and not _shared_client._session.closed:
        return _shared_client

    # Need to create or reconnect
    logger.info("Initializing shared UniFi session...")

    # Clean up stale client if any
    if _shared_client is not None:
        try:
            await _shared_client.disconnect()
        except Exception:
            pass
        _shared_client = None

    # Read config from DB
    db_instance = get_database()
    async for session in db_instance.get_session():
        config_result = await session.execute(
            select(UniFiConfig).where(UniFiConfig.id == 1)
        )
        unifi_config = config_result.scalar_one_or_none()

        if not unifi_config:
            logger.warning("No UniFi configuration found, cannot create shared session")
            return None

        # Decrypt credentials
        password = None
        api_key = None

        try:
            if unifi_config.password_encrypted:
                password = decrypt_password(unifi_config.password_encrypted)
            if unifi_config.api_key_encrypted:
                api_key = decrypt_api_key(unifi_config.api_key_encrypted)
        except Exception as e:
            logger.error(f"Failed to decrypt UniFi credentials: {e}")
            return None

        # Create and connect client
        client = UniFiClient(
            host=unifi_config.controller_url,
            username=unifi_config.username,
            password=password,
            api_key=api_key,
            site=unifi_config.site_id,
            verify_ssl=unifi_config.verify_ssl
        )

        connected = await client.connect()
        if not connected:
            logger.error("Failed to connect shared UniFi session")
            await client.disconnect()
            return None

        _shared_client = client
        logger.info("Shared UniFi session established")
        break  # Exit the async for loop

    return _shared_client


async def invalidate_shared_client():
    """
    Disconnect and clear the shared client.

    Called when UniFi config is saved via the web UI so the next scheduler
    run creates a fresh client with the updated credentials.
    """
    global _shared_client

    if _shared_client is not None:
        logger.info("Invalidating shared UniFi session (config changed)")
        try:
            await _shared_client.disconnect()
        except Exception as e:
            logger.debug(f"Error disconnecting shared client: {e}")
        _shared_client = None


async def close_shared_client():
    """
    Graceful shutdown — disconnect and clear the shared client.

    Called from the app lifespan shutdown handler.
    """
    global _shared_client

    if _shared_client is not None:
        logger.info("Closing shared UniFi session (shutdown)")
        try:
            await _shared_client.disconnect()
        except Exception as e:
            logger.debug(f"Error closing shared client: {e}")
        _shared_client = None
