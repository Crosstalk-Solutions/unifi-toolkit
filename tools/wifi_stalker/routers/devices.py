"""
Device management API endpoints
"""
import asyncio
import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database import get_db_session
from shared.unifi_client import UniFiClient
from tools.wifi_stalker.database import (
    ConnectionHistory,
    HourlyPresence,
    TrackedDevice,
)
from tools.wifi_stalker.models import (
    DeviceCreate,
    DeviceDetailResponse,
    DeviceListResponse,
    DeviceResponse,
    DwellTimeResponse,
    FavoriteAPResponse,
    HistoryListResponse,
    PresencePatternResponse,
    SuccessResponse,
    UniFiClientInfo,
    UniFiClientsResponse,
)
from tools.wifi_stalker.routers.config import get_unifi_client
from tools.wifi_stalker.scheduler import (
    refresh_single_device,
    trigger_webhooks,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.post("", response_model=DeviceResponse, status_code=201)
async def create_device(
    device: DeviceCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Add a new device to track
    """
    # Check if device already exists
    result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.mac_address == device.mac_address)
    )
    existing_device = result.scalar_one_or_none()

    if existing_device:
        raise HTTPException(
            status_code=400,
            detail=f"Device with MAC address {device.mac_address} is already being tracked"
        )

    # Create new device
    new_device = TrackedDevice(
        mac_address=device.mac_address,
        friendly_name=device.friendly_name,
        site_id=device.site_id,
        added_at=datetime.now(timezone.utc),
        is_connected=False
    )

    db.add(new_device)
    await db.commit()
    await db.refresh(new_device)

    # Immediately check device status from UniFi (don't wait for scheduled refresh)
    # Run in background so we can return the response quickly
    asyncio.create_task(refresh_single_device(new_device.id))

    return new_device


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get all tracked devices
    """
    result = await db.execute(
        select(TrackedDevice).order_by(TrackedDevice.added_at.desc())
    )
    devices = result.scalars().all()

    return DeviceListResponse(
        devices=devices,
        total=len(devices)
    )


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: int,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get a specific device by ID
    """
    result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    return device


@router.get("/{device_id}/details", response_model=DeviceDetailResponse)
async def get_device_details(
    device_id: int,
    unifi_client: UniFiClient = Depends(get_unifi_client),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get detailed device information including live UniFi data
    """
    # Get device from database
    result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Prepare response with basic device info
    detail_data = {
        "id": device.id,
        "mac_address": device.mac_address,
        "friendly_name": device.friendly_name,
        "added_at": device.added_at,
        "last_seen": device.last_seen,
        "current_ap_mac": device.current_ap_mac,
        "current_ap_name": device.current_ap_name,
        "current_ssid": device.current_ssid,
        "current_ip_address": device.current_ip_address,
        "current_signal_strength": device.current_signal_strength,
        "is_connected": device.is_connected,
        "site_id": device.site_id,
        "is_blocked": False,  # Default, will be updated from UniFi
        # Wired device fields
        "is_wired": device.is_wired,
        "current_switch_mac": device.current_switch_mac,
        "current_switch_name": device.current_switch_name,
        "current_switch_port": device.current_switch_port,
    }

    # Always try to get blocked status and live data from UniFi
    try:
        connected = await unifi_client.connect()
        if not connected:
            logger.warning(f"Could not connect to UniFi for device details {device_id}")
            return DeviceDetailResponse(**detail_data)
        try:
            mac_normalized = device.mac_address.lower()

            # Always check blocked status (works even for disconnected devices).
            # None = the read failed; keep the stored value rather than
            # presenting an unknown as "not blocked".
            live_blocked = await unifi_client.is_client_blocked(mac_normalized)
            if live_blocked is not None:
                detail_data["is_blocked"] = live_blocked

            # Get live data if device is connected
            if device.is_connected:
                clients = await unifi_client.get_clients()
                client = clients.get(mac_normalized)

                if client:
                    # Extract UniFi data (handle both dict and object formats)
                    live_fields = [
                        "hostname", "tx_rate", "rx_rate", "channel",
                        "radio", "uptime", "tx_bytes", "rx_bytes"
                    ]
                    for field in live_fields:
                        if isinstance(client, dict):
                            detail_data[field] = client.get(field)
                        else:
                            detail_data[field] = getattr(client, field, None)
                    # Map essid to current_ssid
                    if isinstance(client, dict):
                        detail_data["current_ssid"] = client.get("essid")
                    else:
                        detail_data["current_ssid"] = getattr(client, "essid", None)
                    # Get manufacturer from UniFi's OUI data
                    if isinstance(client, dict):
                        detail_data["manufacturer"] = client.get("oui")
                    else:
                        detail_data["manufacturer"] = getattr(client, "oui", None)

        finally:
            await unifi_client.disconnect()
    except Exception:
        # If we can't get live data, just return basic info with default blocked status
        pass

    return DeviceDetailResponse(**detail_data)


@router.delete("/{device_id}", response_model=SuccessResponse)
async def delete_device(
    device_id: int,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Remove a device from tracking
    """
    result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    await db.delete(device)
    await db.commit()

    return SuccessResponse(
        success=True,
        message=f"Device {device.mac_address} removed from tracking"
    )


@router.get("/{device_id}/history", response_model=HistoryListResponse)
async def get_device_history(
    device_id: int,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get roaming history for a specific device
    """
    # Check if device exists
    device_result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = device_result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get history entries
    history_result = await db.execute(
        select(ConnectionHistory)
        .where(ConnectionHistory.device_id == device_id)
        .order_by(ConnectionHistory.connected_at.desc())
        .limit(limit)
        .offset(offset)
    )
    history_entries = history_result.scalars().all()

    # Get total count
    count_result = await db.execute(
        select(func.count()).where(ConnectionHistory.device_id == device_id)
    )
    total = count_result.scalar()

    return HistoryListResponse(
        device_id=device_id,
        history=history_entries,
        total=total
    )


@router.post("/{device_id}/block", response_model=SuccessResponse)
async def block_device(
    device_id: int,
    unifi_client: UniFiClient = Depends(get_unifi_client),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Block a device in UniFi
    """
    # Get device from database
    result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Connect to UniFi and block the device
    connected = await unifi_client.connect()
    if not connected:
        raise HTTPException(status_code=503, detail="Failed to connect to UniFi controller")
    try:
        success = await unifi_client.block_client(device.mac_address)
        if success:
            # Update blocked status in database
            device.is_blocked = True
            await db.commit()

            # Trigger blocked webhook
            await trigger_webhooks(db, 'blocked', device)

            return SuccessResponse(
                success=True,
                message=f"Device {device.mac_address} blocked successfully"
            )
        else:
            raise HTTPException(status_code=500, detail="Failed to block device in UniFi")
    finally:
        await unifi_client.disconnect()


@router.post("/{device_id}/unblock", response_model=SuccessResponse)
async def unblock_device(
    device_id: int,
    unifi_client: UniFiClient = Depends(get_unifi_client),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Unblock a device in UniFi
    """
    # Get device from database
    result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Connect to UniFi and unblock the device
    connected = await unifi_client.connect()
    if not connected:
        raise HTTPException(status_code=503, detail="Failed to connect to UniFi controller")
    try:
        success = await unifi_client.unblock_client(device.mac_address)
        if success:
            # Update blocked status in database
            device.is_blocked = False
            await db.commit()

            # Trigger unblocked webhook
            await trigger_webhooks(db, 'unblocked', device)

            return SuccessResponse(
                success=True,
                message=f"Device {device.mac_address} unblocked successfully"
            )
        else:
            raise HTTPException(status_code=500, detail="Failed to unblock device in UniFi")
    finally:
        await unifi_client.disconnect()


@router.put("/{device_id}/unifi-name", response_model=SuccessResponse)
async def update_unifi_name(
    device_id: int,
    name: str = Query(..., description="New friendly name"),
    unifi_client: UniFiClient = Depends(get_unifi_client),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Update device friendly name in UniFi
    """
    # Get device from database
    result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Connect to UniFi and update the name
    connected = await unifi_client.connect()
    if not connected:
        raise HTTPException(status_code=503, detail="Failed to connect to UniFi controller")
    try:
        success = await unifi_client.set_client_name(device.mac_address, name)
        if success:
            # Also update in our database
            device.friendly_name = name
            await db.commit()

            return SuccessResponse(
                success=True,
                message=f"Device name updated to '{name}' in UniFi and Wi-Fi Stalker"
            )
        else:
            raise HTTPException(status_code=500, detail="Failed to update device name in UniFi")
    finally:
        await unifi_client.disconnect()


@router.get("/discover/unifi", response_model=UniFiClientsResponse)
async def discover_unifi_clients(
    unifi_client: UniFiClient = Depends(get_unifi_client),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get all connected clients from UniFi controller

    Returns list of clients with their MAC address, name (friendly name or hostname),
    and whether they are already being tracked.
    """
    try:
        # Get all tracked devices to mark which ones are already tracked
        tracked_result = await db.execute(select(TrackedDevice))
        tracked_devices = tracked_result.scalars().all()
        tracked_macs = {device.mac_address.lower() for device in tracked_devices}

        # Connect to UniFi and get clients
        connected = await unifi_client.connect()
        if not connected:
            raise HTTPException(status_code=503, detail="Failed to connect to UniFi controller")
        try:
            clients_dict = await unifi_client.get_clients()

            # Build response list
            client_list = []
            for mac, client in clients_dict.items():
                friendly_name = client.get('name') or client.get('friendly_name')
                hostname = client.get('hostname')

                # Use friendly name if exists, otherwise use hostname
                display_name = friendly_name or hostname
                # Only show hostname separately if it differs from the display name
                show_hostname = hostname if friendly_name and friendly_name != hostname else None

                client_list.append(UniFiClientInfo(
                    mac_address=mac.upper(),
                    name=display_name,
                    hostname=show_hostname,
                    is_tracked=mac.lower() in tracked_macs,
                ))

            # Sort by name (tracked devices first, then alphabetically)
            client_list.sort(key=lambda c: (not c.is_tracked, c.name or c.mac_address))

            return UniFiClientsResponse(
                clients=client_list,
                total=len(client_list)
            )

        finally:
            await unifi_client.disconnect()

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get UniFi clients: {str(e)}"
        )


@router.get("/{device_id}/history/export")
async def export_device_history(
    device_id: int,
    start_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="End date (ISO format)"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Export device connection history as CSV
    """
    # Get device from database
    result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Build query for history
    query = select(ConnectionHistory).where(
        ConnectionHistory.device_id == device_id
    )

    # Apply date filters if provided
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.where(ConnectionHistory.connected_at >= start_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_date format")

    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.where(ConnectionHistory.connected_at <= end_dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_date format")

    # Order by connected_at descending (most recent first)
    query = query.order_by(ConnectionHistory.connected_at.desc())

    # Execute query
    result = await db.execute(query)
    history_entries = result.scalars().all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'Device Name',
        'MAC Address',
        'Connection Type',
        'AP/Switch Name',
        'AP/Switch MAC',
        'SSID',
        'Switch Port',
        'Connected At',
        'Disconnected At',
        'Duration (seconds)',
        'Signal Strength (dBm)'
    ])

    # Write data rows
    for entry in history_entries:
        # Determine connection type and location
        connection_type = 'Wired' if entry.is_wired else 'Wireless'
        location_name = entry.switch_name if entry.is_wired else entry.ap_name
        location_mac = entry.switch_mac if entry.is_wired else entry.ap_mac
        switch_port = entry.switch_port if entry.is_wired else '-'

        writer.writerow([
            device.friendly_name or 'Unnamed Device',
            device.mac_address,
            connection_type,
            location_name or '-',
            location_mac or '-',
            entry.ssid or '-',
            switch_port,
            entry.connected_at.isoformat() if entry.connected_at else '-',
            entry.disconnected_at.isoformat() if entry.disconnected_at else '-',
            entry.duration_seconds if entry.duration_seconds else '-',
            entry.signal_strength if entry.signal_strength else '-'
        ])

    # Prepare response
    output.seek(0)
    filename = f"device-history-{device.mac_address.replace(':', '')}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# Analytics Endpoints

@router.get("/{device_id}/analytics/dwell-time", response_model=DwellTimeResponse)
async def get_dwell_time(
    device_id: int,
    window: str = Query(default="7d", pattern="^(24h|7d|30d|all)$"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get dwell time analytics for a device.
    Shows time spent on each AP within the specified time window.

    Args:
        device_id: ID of the device
        window: Time window - "24h", "7d", "30d", or "all"
    """
    # Check if device exists
    device_result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = device_result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Calculate time window
    now = datetime.now(timezone.utc)
    if window == "24h":
        start_time = now - timedelta(hours=24)
    elif window == "7d":
        start_time = now - timedelta(days=7)
    elif window == "30d":
        start_time = now - timedelta(days=30)
    else:  # "all"
        start_time = None

    # Build query for connection history (wireless only)
    query = select(ConnectionHistory).where(
        ConnectionHistory.device_id == device_id,
        ConnectionHistory.is_wired == False,
        ConnectionHistory.ap_name.isnot(None)
    )

    if start_time:
        query = query.where(ConnectionHistory.connected_at >= start_time)

    result = await db.execute(query)
    history_entries = result.scalars().all()

    # Aggregate time by AP
    ap_times = {}
    for entry in history_entries:
        ap_name = entry.ap_name
        if not ap_name:
            continue

        # Calculate duration
        if entry.duration_seconds:
            duration_minutes = entry.duration_seconds // 60
        elif entry.disconnected_at:
            duration = (entry.disconnected_at - entry.connected_at).total_seconds()
            duration_minutes = int(duration // 60)
        else:
            # Still connected - calculate from connected_at to now
            connected_at = entry.connected_at
            if connected_at.tzinfo is None:
                connected_at = connected_at.replace(tzinfo=timezone.utc)
            duration = (now - connected_at).total_seconds()
            duration_minutes = int(duration // 60)

        if ap_name in ap_times:
            ap_times[ap_name] += duration_minutes
        else:
            ap_times[ap_name] = duration_minutes

    total_minutes = sum(ap_times.values())

    return DwellTimeResponse(
        ap_times=ap_times,
        total_minutes=total_minutes,
        window=window
    )


@router.get("/{device_id}/analytics/favorite-ap", response_model=FavoriteAPResponse)
async def get_favorite_ap(
    device_id: int,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get the favorite AP for a device (most time spent over 30 days).
    Uses most recent connection as tie-breaker.
    """
    # Check if device exists
    device_result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = device_result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Calculate 30-day window
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=30)

    # Get connection history for 30 days (wireless only)
    result = await db.execute(
        select(ConnectionHistory).where(
            ConnectionHistory.device_id == device_id,
            ConnectionHistory.is_wired == False,
            ConnectionHistory.ap_name.isnot(None),
            ConnectionHistory.connected_at >= start_time
        )
    )
    history_entries = result.scalars().all()

    if not history_entries:
        return FavoriteAPResponse(
            ap_name=None,
            total_hours=0.0,
            has_data=False
        )

    # Aggregate time by AP, tracking most recent connection
    ap_data = {}  # ap_name -> {"minutes": int, "last_seen": datetime}

    for entry in history_entries:
        ap_name = entry.ap_name
        if not ap_name:
            continue

        # Calculate duration
        if entry.duration_seconds:
            duration_minutes = entry.duration_seconds // 60
        elif entry.disconnected_at:
            duration = (entry.disconnected_at - entry.connected_at).total_seconds()
            duration_minutes = int(duration // 60)
        else:
            # Still connected
            connected_at = entry.connected_at
            if connected_at.tzinfo is None:
                connected_at = connected_at.replace(tzinfo=timezone.utc)
            duration = (now - connected_at).total_seconds()
            duration_minutes = int(duration // 60)

        if ap_name not in ap_data:
            ap_data[ap_name] = {"minutes": 0, "last_seen": entry.connected_at}

        ap_data[ap_name]["minutes"] += duration_minutes
        if entry.connected_at > ap_data[ap_name]["last_seen"]:
            ap_data[ap_name]["last_seen"] = entry.connected_at

    if not ap_data:
        return FavoriteAPResponse(
            ap_name=None,
            total_hours=0.0,
            has_data=False
        )

    # Find favorite AP (max minutes, with most recent as tie-breaker)
    favorite = max(
        ap_data.items(),
        key=lambda x: (x[1]["minutes"], x[1]["last_seen"])
    )

    return FavoriteAPResponse(
        ap_name=favorite[0],
        total_hours=round(favorite[1]["minutes"] / 60, 1),
        has_data=True
    )


@router.get("/{device_id}/analytics/presence-pattern", response_model=PresencePatternResponse)
async def get_presence_pattern(
    device_id: int,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get presence pattern heat map data for a device.
    Returns a 24x7 matrix showing average minutes connected per hour slot.
    """
    # Check if device exists
    device_result = await db.execute(
        select(TrackedDevice).where(TrackedDevice.id == device_id)
    )
    device = device_result.scalar_one_or_none()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get all hourly presence data for this device
    result = await db.execute(
        select(HourlyPresence).where(HourlyPresence.device_id == device_id)
    )
    presence_records = result.scalars().all()

    # Calculate days of data based on device added_at timestamp
    now = datetime.now(timezone.utc)
    # Ensure added_at is timezone-aware for comparison
    added_at = device.added_at
    if added_at.tzinfo is None:
        added_at = added_at.replace(tzinfo=timezone.utc)
    days_of_data = (now - added_at).days

    # Build 24x7 matrix (hours as rows, days as columns)
    # Initialize with zeros
    data = [[0 for _ in range(7)] for _ in range(24)]

    for record in presence_records:
        hour = record.hour_of_day
        day = record.day_of_week

        # Calculate average minutes for this slot
        if record.sample_count > 0:
            avg_minutes = record.total_minutes_connected // record.sample_count
        else:
            avg_minutes = 0

        data[hour][day] = avg_minutes

    # Require at least 7 days of data for meaningful patterns
    has_sufficient_data = days_of_data >= 7

    return PresencePatternResponse(
        data=data,
        has_sufficient_data=has_sufficient_data,
        days_of_data=days_of_data
    )
