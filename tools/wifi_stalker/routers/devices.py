"""
Device management API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from datetime import datetime, timezone
import asyncio
import csv
import io

from shared.database import get_db_session
from shared.unifi_client import UniFiClient
from tools.wifi_stalker.database import TrackedDevice, ConnectionHistory, WebhookConfig
from tools.wifi_stalker.models import (
    DeviceCreate,
    DeviceResponse,
    DeviceListResponse,
    DeviceDetailResponse,
    HistoryEntry,
    HistoryListResponse,
    SuccessResponse,
    UniFiClientInfo,
    UniFiClientsResponse,
    SystemStatus
)
from tools.wifi_stalker.routers.config import get_unifi_client
from tools.wifi_stalker.scheduler import refresh_single_device, get_last_refresh, trigger_webhooks
from shared.config import get_settings

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
        await unifi_client.connect()
        try:
            mac_normalized = device.mac_address.lower()

            # Always check blocked status (works even for disconnected devices)
            detail_data["is_blocked"] = await unifi_client.is_client_blocked(mac_normalized)

            # Get live data if device is connected
            if device.is_connected:
                clients = await unifi_client.get_clients()
                client = clients.get(mac_normalized)

                if client:
                    # Extract UniFi data (handle both dict and object formats)
                    if isinstance(client, dict):
                        detail_data["hostname"] = client.get("hostname")
                        detail_data["tx_rate"] = client.get("tx_rate")
                        detail_data["rx_rate"] = client.get("rx_rate")
                        detail_data["channel"] = client.get("channel")
                        detail_data["radio"] = client.get("radio")
                        detail_data["uptime"] = client.get("uptime")
                        detail_data["tx_bytes"] = client.get("tx_bytes")
                        detail_data["rx_bytes"] = client.get("rx_bytes")
                        # Get manufacturer from UniFi's OUI data
                        detail_data["manufacturer"] = client.get("oui")
                    else:
                        detail_data["hostname"] = getattr(client, "hostname", None)
                        detail_data["tx_rate"] = getattr(client, "tx_rate", None)
                        detail_data["rx_rate"] = getattr(client, "rx_rate", None)
                        detail_data["channel"] = getattr(client, "channel", None)
                        detail_data["radio"] = getattr(client, "radio", None)
                        detail_data["uptime"] = getattr(client, "uptime", None)
                        detail_data["tx_bytes"] = getattr(client, "tx_bytes", None)
                        detail_data["rx_bytes"] = getattr(client, "rx_bytes", None)
                        # Get manufacturer from UniFi's OUI data
                        detail_data["manufacturer"] = getattr(client, "oui", None)

        finally:
            await unifi_client.disconnect()
    except Exception as e:
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
    await unifi_client.connect()
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
    await unifi_client.connect()
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
    await unifi_client.connect()
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
        await unifi_client.connect()
        try:
            clients_dict = await unifi_client.get_clients()

            # Build response list
            client_list = []
            for mac, client in clients_dict.items():
                # Handle both dict (UniFi OS) and object (aiounifi) formats
                if isinstance(client, dict):
                    friendly_name = client.get('name') or client.get('friendly_name')
                    hostname = client.get('hostname')
                else:
                    friendly_name = getattr(client, 'name', None) or getattr(client, 'friendly_name', None)
                    hostname = getattr(client, 'hostname', None)

                # Use friendly name if exists, otherwise use hostname
                # Don't duplicate - if friendly_name == hostname, only show once
                display_name = None
                if friendly_name and hostname and friendly_name != hostname:
                    display_name = friendly_name
                elif friendly_name:
                    display_name = friendly_name
                elif hostname:
                    display_name = hostname

                client_list.append(UniFiClientInfo(
                    mac_address=mac.upper(),  # Display in uppercase for consistency
                    name=display_name,
                    hostname=hostname if friendly_name and friendly_name != hostname else None,
                    is_tracked=mac.lower() in tracked_macs
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
