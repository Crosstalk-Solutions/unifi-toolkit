"""
Background task scheduler for refreshing device status
"""
import asyncio
import logging
from datetime import datetime, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database import get_database
from shared.models.unifi_config import UniFiConfig
from shared.unifi_client import UniFiClient
from shared.crypto import decrypt_password, decrypt_api_key
from shared.config import get_settings
from shared.websocket_manager import get_ws_manager
from shared.webhooks import deliver_webhook
from tools.wifi_stalker.database import TrackedDevice, ConnectionHistory, WebhookConfig

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler: AsyncIOScheduler = None
_last_refresh: datetime = None


def get_scheduler() -> AsyncIOScheduler:
    """
    Get the global scheduler instance
    """
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
    return _scheduler


def get_last_refresh() -> datetime:
    """
    Get the timestamp of the last successful refresh
    """
    return _last_refresh


async def refresh_tracked_devices():
    """
    Background task that runs periodically to update device status

    This is the core tracking logic:
    1. Get all user-added tracked devices from database
    2. Connect to UniFi controller
    3. Get all active clients from UniFi API
    4. For each tracked device:
       - Search for MAC address in active clients list
       - If found (device is online):
         * Update last_seen timestamp
         * Get AP name from UniFi
         * Check if AP changed (roaming event detected)
         * If AP changed, create history entry
       - If not found (device is offline):
         * Set is_connected = False
         * Close any open history entries
    """
    global _last_refresh

    try:
        logger.info("Starting device refresh task")

        # Get database session
        db_instance = get_database()
        async for session in db_instance.get_session():
            # Get UniFi config
            config_result = await session.execute(
                select(UniFiConfig).where(UniFiConfig.id == 1)
            )
            unifi_config = config_result.scalar_one_or_none()

            if not unifi_config:
                logger.warning("No UniFi configuration found, skipping refresh")
                return

            # Get all tracked devices
            devices_result = await session.execute(select(TrackedDevice))
            tracked_devices = devices_result.scalars().all()

            if not tracked_devices:
                logger.info("No devices to track, skipping refresh")
                return

            logger.info(f"Refreshing {len(tracked_devices)} tracked devices")

            # Decrypt UniFi credentials and create client
            password = None
            api_key = None

            try:
                if unifi_config.password_encrypted:
                    password = decrypt_password(unifi_config.password_encrypted)
                if unifi_config.api_key_encrypted:
                    api_key = decrypt_api_key(unifi_config.api_key_encrypted)
            except Exception as e:
                logger.error(f"Failed to decrypt UniFi credentials: {e}")
                return

            # is_unifi_os is auto-detected during connection
            unifi_client = UniFiClient(
                host=unifi_config.controller_url,
                username=unifi_config.username,
                password=password,
                api_key=api_key,
                site=unifi_config.site_id,
                verify_ssl=unifi_config.verify_ssl
            )

            # Connect to UniFi controller
            connected = await unifi_client.connect()
            if not connected:
                logger.error("Failed to connect to UniFi controller")
                return

            try:
                # Get all active clients from UniFi
                active_clients = await unifi_client.get_clients()
                logger.info(f"Retrieved {len(active_clients)} active clients from UniFi")

                # Process each tracked device
                for device in tracked_devices:
                    await process_device(
                        session,
                        device,
                        active_clients,
                        unifi_client
                    )

                # Commit all changes
                await session.commit()
                _last_refresh = datetime.now(timezone.utc)
                logger.info("Device refresh completed successfully")

            finally:
                await unifi_client.disconnect()

            break  # Exit the async for loop after processing

    except Exception as e:
        logger.error(f"Error in refresh task: {e}", exc_info=True)


def _device_to_dict(device: TrackedDevice) -> dict:
    """
    Convert TrackedDevice to dictionary for WebSocket broadcast

    Args:
        device: TrackedDevice instance

    Returns:
        Dictionary with device data
    """
    return {
        'id': device.id,
        'friendly_name': device.friendly_name,
        'mac_address': device.mac_address,
        'is_connected': device.is_connected,
        'is_blocked': device.is_blocked,
        'current_ap_name': device.current_ap_name,
        'current_ap_mac': device.current_ap_mac,
        'current_ip_address': device.current_ip_address,
        'current_signal_strength': device.current_signal_strength,
        'last_seen': device.last_seen.isoformat() if device.last_seen else None,
        'added_at': device.added_at.isoformat() if device.added_at else None,
        # Wired device fields
        'is_wired': device.is_wired,
        'current_switch_mac': device.current_switch_mac,
        'current_switch_name': device.current_switch_name,
        'current_switch_port': device.current_switch_port
    }


async def trigger_webhooks(
    session: AsyncSession,
    event_type: str,
    device: TrackedDevice,
    offline_duration: int = None
):
    """
    Trigger all enabled webhooks for a specific event type

    Args:
        session: Database session
        event_type: Type of event ('connected', 'disconnected', 'roamed', 'blocked', 'unblocked')
        device: TrackedDevice that triggered the event
        offline_duration: Duration in seconds the device was offline (for connected events)
    """
    # Get all enabled webhooks
    result = await session.execute(
        select(WebhookConfig).where(WebhookConfig.enabled == True)
    )
    webhooks = result.scalars().all()

    if not webhooks:
        return

    # Filter webhooks based on event type
    for webhook in webhooks:
        should_trigger = False

        if event_type == 'connected' and webhook.event_device_connected:
            should_trigger = True
        elif event_type == 'disconnected' and webhook.event_device_disconnected:
            should_trigger = True
        elif event_type == 'roamed' and webhook.event_device_roamed:
            should_trigger = True
        elif event_type == 'blocked' and webhook.event_device_blocked:
            should_trigger = True
        elif event_type == 'unblocked' and webhook.event_device_unblocked:
            should_trigger = True

        if should_trigger:
            # Trigger webhook asynchronously (don't wait for response)
            try:
                await deliver_webhook(
                    webhook_url=webhook.url,
                    webhook_type=webhook.webhook_type,
                    event_type=event_type,
                    device_name=device.friendly_name or device.mac_address,
                    device_mac=device.mac_address,
                    ap_name=device.current_ap_name,
                    signal_strength=device.current_signal_strength,
                    offline_duration=offline_duration if event_type == 'connected' else None
                )
                # Update last_triggered timestamp
                webhook.last_triggered = datetime.now(timezone.utc)
            except Exception as e:
                logger.error(f"Error triggering webhook {webhook.name}: {e}")


async def process_device(
    session: AsyncSession,
    device: TrackedDevice,
    active_clients: dict,
    unifi_client: UniFiClient
):
    """
    Process a single tracked device (wireless or wired)

    Args:
        session: Database session
        device: TrackedDevice to process
        active_clients: Dictionary of active clients from UniFi
        unifi_client: UniFi client instance
    """
    # Normalize MAC address for lookup
    mac = device.mac_address.lower()

    # Get WebSocket manager for broadcasting updates
    ws_manager = get_ws_manager()

    # Check if device is in active clients
    client = active_clients.get(mac)

    if client:
        # Device is online
        logger.debug(f"Device {device.mac_address} is online")

        # Update last_seen
        device.last_seen = datetime.now(timezone.utc)

        # Get client data (handle both dict and object formats)
        if isinstance(client, dict):
            ap_mac = client.get('ap_mac')
            ip_address = client.get('ip')
            signal_strength = client.get('rssi')
            is_wired = client.get('is_wired', False)
            sw_mac = client.get('sw_mac')
            sw_port = client.get('sw_port')
        else:
            ap_mac = getattr(client, 'ap_mac', None)
            ip_address = getattr(client, 'ip', None)
            signal_strength = getattr(client, 'rssi', None)
            is_wired = getattr(client, 'is_wired', False)
            sw_mac = getattr(client, 'sw_mac', None)
            sw_port = getattr(client, 'sw_port', None)

        # Update current IP
        device.current_ip_address = ip_address

        # Update wired status
        device.is_wired = is_wired

        if is_wired:
            # Wired device - track switch/port instead of AP
            device.current_signal_strength = None  # No signal for wired

            if sw_mac:
                # Get switch name
                switch_name = await unifi_client.get_switch_name_by_mac(sw_mac)

                # Check if switch or port changed
                if device.current_switch_mac != sw_mac or device.current_switch_port != sw_port:
                    old_location = f"{device.current_switch_name or 'unknown'} port {device.current_switch_port or '?'}"
                    new_location = f"{switch_name} port {sw_port or '?'}"
                    logger.info(
                        f"Wired device {device.mac_address} moved from "
                        f"{old_location} to {new_location}"
                    )

                    # Close previous history entry if exists
                    if device.is_connected and device.current_switch_mac:
                        await close_connection_history(session, device)

                    # Create new history entry for wired device
                    new_history = ConnectionHistory(
                        device_id=device.id,
                        connected_at=datetime.now(timezone.utc),
                        is_wired=True,
                        switch_mac=sw_mac,
                        switch_name=switch_name,
                        switch_port=sw_port
                    )
                    session.add(new_history)

                    # Update device current switch info
                    device.current_switch_mac = sw_mac
                    device.current_switch_name = switch_name
                    device.current_switch_port = sw_port

                    # Clear AP fields for wired devices
                    device.current_ap_mac = None
                    device.current_ap_name = None

                    # Broadcast update via WebSocket
                    await ws_manager.broadcast_device_update(_device_to_dict(device))

                    # Trigger roaming webhooks (port changes are like roaming)
                    await trigger_webhooks(session, 'roamed', device)

        else:
            # Wireless device - track AP
            device.current_signal_strength = signal_strength

            # Clear switch fields for wireless devices
            device.current_switch_mac = None
            device.current_switch_name = None
            device.current_switch_port = None

            if ap_mac:
                # Get AP name
                ap_name = await unifi_client.get_ap_name_by_mac(ap_mac)

                # Check if AP changed (roaming event)
                if device.current_ap_mac != ap_mac:
                    logger.info(
                        f"Device {device.mac_address} roamed from "
                        f"{device.current_ap_name or 'unknown'} to {ap_name}"
                    )

                    # Close previous history entry if exists
                    if device.is_connected and device.current_ap_mac:
                        await close_connection_history(session, device)

                    # Create new history entry
                    new_history = ConnectionHistory(
                        device_id=device.id,
                        ap_mac=ap_mac,
                        ap_name=ap_name,
                        connected_at=datetime.now(timezone.utc),
                        signal_strength=signal_strength,
                        is_wired=False
                    )
                    session.add(new_history)

                    # Update device current AP
                    device.current_ap_mac = ap_mac
                    device.current_ap_name = ap_name

                    # Broadcast roaming event via WebSocket
                    await ws_manager.broadcast_device_update(_device_to_dict(device))

                    # Trigger roaming webhooks
                    await trigger_webhooks(session, 'roamed', device)

        # Mark device as connected
        if not device.is_connected:
            logger.info(f"Device {device.mac_address} came online")
            # Broadcast connection event via WebSocket
            device.is_connected = True
            await ws_manager.broadcast_device_update(_device_to_dict(device))

            # Calculate offline duration for webhook
            # Find the most recent closed history entry (where disconnected_at is set)
            offline_duration = None
            history_result = await session.execute(
                select(ConnectionHistory)
                .where(ConnectionHistory.device_id == device.id)
                .where(ConnectionHistory.disconnected_at.isnot(None))
                .order_by(ConnectionHistory.disconnected_at.desc())
            )
            last_disconnect = history_result.scalars().first()

            if last_disconnect and last_disconnect.disconnected_at:
                # Calculate time since last disconnect
                disconnected_at = last_disconnect.disconnected_at
                if disconnected_at.tzinfo is None:
                    disconnected_at = disconnected_at.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)
                offline_duration = int((now - disconnected_at).total_seconds())
                logger.debug(f"Device {device.mac_address} was offline for {offline_duration} seconds")

            # Trigger connection webhooks with offline duration
            await trigger_webhooks(session, 'connected', device, offline_duration=offline_duration)
        else:
            device.is_connected = True

    else:
        # Device is offline
        if device.is_connected:
            logger.info(f"Device {device.mac_address} went offline")

            # Close any open history entries
            await close_connection_history(session, device)

            # Mark device as disconnected
            device.is_connected = False

            # Broadcast disconnection event via WebSocket
            await ws_manager.broadcast_device_update(_device_to_dict(device))

            # Trigger disconnection webhooks
            await trigger_webhooks(session, 'disconnected', device)

    # Always check blocked status (works for both online and offline devices)
    try:
        is_blocked = await unifi_client.is_client_blocked(mac)
        if device.is_blocked != is_blocked:
            logger.info(f"Device {device.mac_address} blocked status changed to {is_blocked}")
            device.is_blocked = is_blocked
            # Broadcast update via WebSocket
            await ws_manager.broadcast_device_update(_device_to_dict(device))
            # Trigger blocked/unblocked webhooks
            event_type = 'blocked' if is_blocked else 'unblocked'
            await trigger_webhooks(session, event_type, device)
    except Exception as e:
        logger.debug(f"Could not check blocked status for {device.mac_address}: {e}")


async def close_connection_history(session: AsyncSession, device: TrackedDevice):
    """
    Close the most recent open connection history entry for a device

    Args:
        session: Database session
        device: TrackedDevice
    """
    # Find the most recent open history entry
    result = await session.execute(
        select(ConnectionHistory)
        .where(ConnectionHistory.device_id == device.id)
        .where(ConnectionHistory.disconnected_at.is_(None))
        .order_by(ConnectionHistory.connected_at.desc())
    )
    open_history = result.scalars().first()

    if open_history:
        # Close the history entry
        open_history.disconnected_at = datetime.now(timezone.utc)

        # Calculate duration in seconds
        # Handle both naive and timezone-aware datetimes
        connected_at = open_history.connected_at
        disconnected_at = open_history.disconnected_at

        # If connected_at is naive, make it aware (assume UTC)
        if connected_at.tzinfo is None:
            connected_at = connected_at.replace(tzinfo=timezone.utc)

        # If disconnected_at is naive, make it aware (assume UTC)
        if disconnected_at.tzinfo is None:
            disconnected_at = disconnected_at.replace(tzinfo=timezone.utc)

        duration = (disconnected_at - connected_at).total_seconds()
        open_history.duration_seconds = int(duration)

        logger.debug(
            f"Closed history entry for device {device.mac_address}, "
            f"duration: {duration} seconds"
        )


async def refresh_single_device(device_id: int):
    """
    Immediately refresh status for a single device (called when device is first added)

    Args:
        device_id: ID of the device to refresh
    """
    try:
        logger.info(f"Refreshing single device ID: {device_id}")

        # Get database session
        db_instance = get_database()
        async for session in db_instance.get_session():
            # Get the specific device
            device_result = await session.execute(
                select(TrackedDevice).where(TrackedDevice.id == device_id)
            )
            device = device_result.scalar_one_or_none()

            if not device:
                logger.warning(f"Device ID {device_id} not found")
                return

            # Get UniFi config
            config_result = await session.execute(
                select(UniFiConfig).where(UniFiConfig.id == 1)
            )
            unifi_config = config_result.scalar_one_or_none()

            if not unifi_config:
                logger.warning("No UniFi configuration found, skipping refresh")
                return

            # Decrypt UniFi credentials and create client
            password = None
            api_key = None

            try:
                if unifi_config.password_encrypted:
                    password = decrypt_password(unifi_config.password_encrypted)
                if unifi_config.api_key_encrypted:
                    api_key = decrypt_api_key(unifi_config.api_key_encrypted)
            except Exception as e:
                logger.error(f"Failed to decrypt UniFi credentials: {e}")
                return

            # is_unifi_os is auto-detected during connection
            unifi_client = UniFiClient(
                host=unifi_config.controller_url,
                username=unifi_config.username,
                password=password,
                api_key=api_key,
                site=unifi_config.site_id,
                verify_ssl=unifi_config.verify_ssl
            )

            # Connect to UniFi controller
            connected = await unifi_client.connect()
            if not connected:
                logger.error("Failed to connect to UniFi controller")
                return

            try:
                # Get all active clients from UniFi
                active_clients = await unifi_client.get_clients()

                # Process this specific device
                await process_device(
                    session,
                    device,
                    active_clients,
                    unifi_client
                )

                # Commit changes
                await session.commit()
                logger.info(f"Single device refresh completed for ID: {device_id}")

            finally:
                await unifi_client.disconnect()

            break  # Exit the async for loop after processing

    except Exception as e:
        logger.error(f"Error refreshing single device: {e}", exc_info=True)


async def start_scheduler():
    """
    Start the background scheduler
    """
    settings = get_settings()
    scheduler = get_scheduler()

    # Add the refresh job - use stalker_refresh_interval from settings
    scheduler.add_job(
        refresh_tracked_devices,
        trigger=IntervalTrigger(seconds=settings.stalker_refresh_interval),
        id="refresh_tracked_devices",
        name="Refresh tracked device status",
        replace_existing=True,
        misfire_grace_time=None,  # Allow job to run even if late
        max_instances=1  # Prevent overlapping runs
    )

    # Start the scheduler
    scheduler.start()
    logger.info(
        f"Scheduler started with refresh interval: {settings.stalker_refresh_interval} seconds"
    )

    # Run the refresh task immediately on startup
    await refresh_tracked_devices()


async def stop_scheduler():
    """
    Stop the background scheduler
    """
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")
