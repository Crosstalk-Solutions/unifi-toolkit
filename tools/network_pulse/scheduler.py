"""
Background task scheduler for refreshing network stats
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from shared.database import get_database
from shared.config import get_settings
from shared.websocket_manager import get_ws_manager
from shared.unifi_session import get_shared_client, invalidate_shared_client
from tools.network_pulse.models import (
    DashboardData,
    GatewayStats,
    WanHealth,
    DeviceCounts,
    APStatus,
    TopClient,
    NetworkHealth,
    ChartData
)

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler: AsyncIOScheduler = None
_last_refresh: datetime = None
_last_error: Optional[str] = None

# In-memory cache for dashboard data
_cached_data: Optional[DashboardData] = None


def get_scheduler() -> AsyncIOScheduler:
    """Get the global scheduler instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
    return _scheduler


def get_last_refresh() -> Optional[datetime]:
    """Get the timestamp of the last successful refresh"""
    return _last_refresh


def get_last_error() -> Optional[str]:
    """Get the last error message if any"""
    return _last_error


def get_cached_data() -> Optional[DashboardData]:
    """Get the cached dashboard data"""
    return _cached_data


def get_radio_band_name(radio: str, is_wired: bool) -> Optional[str]:
    """Convert UniFi radio code to friendly band name"""
    if is_wired:
        return None  # Wired clients don't have a radio band
    if not radio:
        return None

    radio_lower = radio.lower()
    if radio_lower in ('ng', '2g', 'b', 'g'):
        return "2.4 GHz"
    elif radio_lower in ('na', '5g', 'a', 'ac', 'ax'):
        return "5 GHz"
    elif radio_lower in ('6e', '6g'):
        return "6 GHz"
    return None  # Unknown radio type


async def refresh_network_stats():
    """
    Background task that runs periodically to update network statistics.

    Fetches:
    - Gateway health (CPU, RAM, uptime, WAN status)
    - Network health by subsystem
    - Hourly bandwidth history
    - AP status and client counts
    - Top clients by bandwidth
    """
    global _last_refresh, _last_error, _cached_data

    try:
        logger.info("Starting network stats refresh")

        # Get shared UniFi client (reuses persistent session)
        unifi_client = await get_shared_client()
        if not unifi_client:
            logger.warning("No UniFi connection available, skipping refresh")
            _last_error = "No UniFi connection available"
            return

        logger.info("Using shared UniFi session, fetching data...")

        # Fetch all data in parallel where possible
        system_info_task = unifi_client.get_system_info()
        health_task = unifi_client.get_health()
        ap_details_task = unifi_client.get_ap_details()
        top_clients_task = unifi_client.get_top_clients(limit=10)

        # Await all tasks
        system_info, health, ap_details, top_clients = await asyncio.gather(
            system_info_task,
            health_task,
            ap_details_task,
            top_clients_task
        )

        # Build dashboard data
        settings = get_settings()

        # Gateway stats
        gateway = GatewayStats(
            model=system_info.get('gateway_model'),
            name=system_info.get('gateway_name'),
            version=system_info.get('gateway_version'),
            uptime=system_info.get('uptime'),
            cpu_utilization=system_info.get('cpu_utilization'),
            mem_utilization=system_info.get('mem_utilization'),
            wan_status=system_info.get('wan_status'),
            wan_ip=system_info.get('wan_ip')
        )

        # WAN health
        wan_health_data = health.get('wan', {})
        wan = WanHealth(
            status=wan_health_data.get('status', 'unknown'),
            wan_ip=wan_health_data.get('wan_ip'),
            isp_name=wan_health_data.get('isp_name'),
            availability=wan_health_data.get('availability'),
            latency=health.get('www', {}).get('latency'),
            tx_bytes_rate=wan_health_data.get('tx_bytes', 0),
            rx_bytes_rate=wan_health_data.get('rx_bytes', 0)
        )

        # Device counts
        clients = await unifi_client.get_clients()
        wired_count = sum(1 for c in clients.values() if c.get('is_wired', False))
        wireless_count = len(clients) - wired_count

        devices = DeviceCounts(
            clients=len(clients),
            wired_clients=wired_count,
            wireless_clients=wireless_count,
            aps=system_info.get('ap_count', 0),
            switches=system_info.get('switch_count', 0)
        )

        # AP status list
        access_points = [
            APStatus(
                mac=ap.get('mac', ''),
                name=ap.get('name', 'Unknown'),
                model=ap.get('model', 'Unknown'),
                model_code=ap.get('model_code'),
                num_sta=ap.get('num_sta', 0),
                user_num_sta=ap.get('user_num_sta', 0),
                guest_num_sta=ap.get('guest_num_sta', 0),
                channels=ap.get('channels'),
                state=ap.get('state', 0),
                uptime=ap.get('uptime', 0),
                satisfaction=ap.get('satisfaction'),
                tx_bytes=ap.get('tx_bytes', 0),
                rx_bytes=ap.get('rx_bytes', 0)
            )
            for ap in ap_details
        ]

        # Top clients (top 10 for display)
        top_clients_list = [
            TopClient(
                mac=client.get('mac', ''),
                name=client.get('name', 'Unknown'),
                hostname=client.get('hostname'),
                ip=client.get('ip'),
                tx_bytes=client.get('tx_bytes', 0),
                rx_bytes=client.get('rx_bytes', 0),
                total_bytes=client.get('total_bytes', 0),
                rssi=client.get('rssi'),
                is_wired=client.get('is_wired', False),
                uptime=client.get('uptime'),
                essid=client.get('essid'),
                network=client.get('network'),
                radio=get_radio_band_name(client.get('radio', ''), client.get('is_wired', False)),
                ap_mac=client.get('ap_mac')
            )
            for client in top_clients
        ]

        # All clients list (for AP detail pages)
        all_clients_list = []
        clients_by_band: Dict[str, int] = {}
        clients_by_ssid: Dict[str, int] = {}

        for client_data in clients.values():
            is_wired = client_data.get('is_wired', False)
            radio_band = get_radio_band_name(client_data.get('radio', ''), is_wired)
            essid = client_data.get('essid')

            # Handle None values for bytes
            tx_bytes = client_data.get('tx_bytes') or 0
            rx_bytes = client_data.get('rx_bytes') or 0

            # Build client object
            client_obj = TopClient(
                mac=client_data.get('mac', ''),
                name=client_data.get('name') or client_data.get('hostname') or 'Unknown',
                hostname=client_data.get('hostname'),
                ip=client_data.get('ip'),
                tx_bytes=tx_bytes,
                rx_bytes=rx_bytes,
                total_bytes=tx_bytes + rx_bytes,
                rssi=client_data.get('rssi'),
                is_wired=is_wired,
                uptime=client_data.get('uptime'),
                essid=essid,
                network=client_data.get('network'),
                radio=radio_band,
                ap_mac=client_data.get('ap_mac')
            )
            all_clients_list.append(client_obj)

            # Aggregate by band
            if is_wired:
                band_key = "Wired"
            elif radio_band:
                band_key = radio_band
            else:
                band_key = "Unknown"
            clients_by_band[band_key] = clients_by_band.get(band_key, 0) + 1

            # Aggregate by SSID
            if essid:
                clients_by_ssid[essid] = clients_by_ssid.get(essid, 0) + 1
            elif is_wired:
                clients_by_ssid["Wired"] = clients_by_ssid.get("Wired", 0) + 1

        # Sort all_clients by total bandwidth descending
        all_clients_list.sort(key=lambda c: c.total_bytes, reverse=True)

        # Build chart data
        chart_data = ChartData(
            clients_by_band=clients_by_band,
            clients_by_ssid=clients_by_ssid
        )

        # Network health
        network_health = NetworkHealth(
            wan=health.get('wan'),
            wan2=health.get('wan2'),
            lan=health.get('lan'),
            wlan=health.get('wlan'),
            vpn=health.get('vpn'),
            www=health.get('www')
        )

        # Build complete dashboard data
        _cached_data = DashboardData(
            gateway=gateway,
            wan=wan,
            devices=devices,
            current_tx_rate=wan_health_data.get('tx_bytes', 0),
            current_rx_rate=wan_health_data.get('rx_bytes', 0),
            access_points=access_points,
            top_clients=top_clients_list,
            all_clients=all_clients_list,
            chart_data=chart_data,
            health=network_health,
            last_refresh=datetime.now(timezone.utc),
            refresh_interval=60
        )

        _last_refresh = datetime.now(timezone.utc)
        _last_error = None

        logger.info(
            f"Network stats refresh completed: "
            f"{devices.clients} clients, {devices.aps} APs"
        )

        # Broadcast update via WebSocket
        ws_manager = get_ws_manager()
        await ws_manager.broadcast({
            "type": "stats_update",
            "data": _cached_data.model_dump()
        })

    except Exception as e:
        logger.error(f"Error in network stats refresh: {e}", exc_info=True)
        _last_error = str(e)
        # Invalidate shared session so next cycle reconnects (handles session expiry)
        await invalidate_shared_client()


async def start_scheduler():
    """Start the background scheduler"""
    scheduler = get_scheduler()

    # Add the refresh job - 60 second interval
    scheduler.add_job(
        refresh_network_stats,
        trigger=IntervalTrigger(seconds=60),
        id="refresh_network_stats",
        name="Refresh network statistics",
        replace_existing=True,
        misfire_grace_time=None,
        max_instances=1
    )

    # Start the scheduler
    scheduler.start()
    logger.info("Network Pulse scheduler started with 60 second refresh interval")

    # Run the refresh task immediately on startup
    await refresh_network_stats()


async def stop_scheduler():
    """Stop the background scheduler"""
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Network Pulse scheduler stopped")
