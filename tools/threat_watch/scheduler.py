"""
Background task scheduler for polling IDS/IPS events
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database import get_database
from shared.config import get_settings
from shared.websocket_manager import get_ws_manager
from shared.webhooks import deliver_webhook
from shared.unifi_session import get_shared_client, invalidate_shared_client
from tools.threat_watch.database import ThreatEvent, ThreatWebhookConfig, ThreatIgnoreRule

logger = logging.getLogger(__name__)

# Global scheduler instance
_scheduler: AsyncIOScheduler = None
_last_refresh: datetime = None

# Default refresh interval (seconds)
DEFAULT_REFRESH_INTERVAL = 60


def get_scheduler() -> AsyncIOScheduler:
    """Get the global scheduler instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
    return _scheduler


def get_last_refresh() -> datetime:
    """Get the timestamp of the last successful refresh"""
    return _last_refresh


def parse_unifi_event(event: dict) -> dict:
    """
    Parse a raw UniFi IPS event into our database format.

    Supports both:
    - Legacy format (stat/ips/event endpoint, pre-Network 10.x)
    - v2 format (traffic-flows endpoint, Network 10.x+)

    Args:
        event: Raw event dictionary from UniFi API

    Returns:
        Dictionary with fields mapped to our ThreatEvent model
    """
    # Detect v2 format by presence of 'ips' object
    if 'ips' in event:
        return _parse_v2_traffic_flow(event)
    else:
        return _parse_legacy_ips_event(event)


def _parse_v2_traffic_flow(event: dict) -> dict:
    """
    Parse a v2 traffic-flows event (Network 10.x+) into our database format.

    The v2 format has IPS data nested in an 'ips' object and source/destination
    info in 'source' and 'destination' objects.
    """
    # Parse timestamp - v2 uses 'time' in milliseconds
    timestamp = None
    if 'time' in event:
        try:
            ts_ms = event['time']
            timestamp = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        except (ValueError, TypeError):
            pass
    if not timestamp:
        timestamp = datetime.now(timezone.utc)

    # Extract IPS data
    ips = event.get('ips', {})
    source = event.get('source', {})
    destination = event.get('destination', {})

    # Map risk level to severity (v2 uses 'risk': low/medium/high)
    risk = event.get('risk', 'low')
    severity_map = {'high': 1, 'medium': 2, 'low': 3}
    severity = severity_map.get(risk, 3)

    # Map action (v2 uses 'action': allowed/blocked)
    action = event.get('action', 'alert')
    if action == 'blocked':
        action = 'block'
    elif action == 'allowed':
        action = 'alert'

    # Build signature message from IPS data
    signature = ips.get('signature', '')
    message = ips.get('advanced_information', '') or signature

    return {
        'unifi_event_id': event.get('id') or str(event.get('time', '')),
        'flow_id': ips.get('session_id'),
        'timestamp': timestamp,

        # Alert info from ips object
        'signature': signature,
        'signature_id': ips.get('signature_id'),
        'severity': severity,
        'category': ips.get('category_name'),
        'action': action,
        'message': message,

        # Network - from source/destination objects
        'src_ip': source.get('ip'),
        'src_port': source.get('port'),
        'src_mac': source.get('mac'),
        'dest_ip': destination.get('ip'),
        'dest_port': destination.get('port'),
        'dest_mac': destination.get('mac'),
        'protocol': event.get('protocol'),
        'app_protocol': event.get('service'),
        'interface': None,  # Not available in v2

        # Geo - v2 doesn't include geolocation data
        'src_country': None,
        'src_city': None,
        'src_latitude': None,
        'src_longitude': None,
        'src_asn': None,
        'src_org': None,

        'dest_country': None,
        'dest_city': None,
        'dest_latitude': None,
        'dest_longitude': None,
        'dest_asn': None,
        'dest_org': None,

        # Meta
        'site_id': None,  # Not directly available in v2
        'archived': False,
        'raw_data': json.dumps(event)
    }


def _parse_legacy_ips_event(event: dict) -> dict:
    """
    Parse a legacy stat/ips/event response (pre-Network 10.x) into our database format.
    """
    # Parse timestamp - UniFi uses milliseconds
    timestamp = None
    if 'timestamp' in event:
        try:
            ts_ms = event['timestamp']
            timestamp = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        except (ValueError, TypeError):
            pass
    if not timestamp and 'time' in event:
        try:
            ts_ms = event['time']
            timestamp = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        except (ValueError, TypeError):
            pass
    if not timestamp:
        timestamp = datetime.now(timezone.utc)

    # Extract geolocation data
    src_geo = event.get('source_ip_geo') or event.get('src_ip_geo') or {}
    dest_geo = event.get('dest_ip_geo') or event.get('dst_ip_geo') or {}

    return {
        'unifi_event_id': event.get('_id') or event.get('unique_alertid') or str(event.get('timestamp', '')),
        'flow_id': event.get('flow_id'),
        'timestamp': timestamp,

        # Alert info
        'signature': event.get('inner_alert_signature') or event.get('msg'),
        'signature_id': event.get('inner_alert_signature_id'),
        'severity': event.get('inner_alert_severity'),
        'category': event.get('inner_alert_category') or event.get('catname'),
        'action': event.get('inner_alert_action'),
        'message': event.get('msg'),

        # Network
        'src_ip': event.get('src_ip'),
        'src_port': event.get('src_port'),
        'src_mac': event.get('src_mac'),
        'dest_ip': event.get('dest_ip'),
        'dest_port': event.get('dest_port'),
        'dest_mac': event.get('dst_mac'),
        'protocol': event.get('proto'),
        'app_protocol': event.get('app_proto'),
        'interface': event.get('in_iface'),

        # Geo - Source
        'src_country': event.get('src_ip_country') or src_geo.get('country_code'),
        'src_city': src_geo.get('city'),
        'src_latitude': src_geo.get('latitude'),
        'src_longitude': src_geo.get('longitude'),
        'src_asn': event.get('src_ip_asn') or src_geo.get('asn'),
        'src_org': src_geo.get('organization'),

        # Geo - Destination
        'dest_country': event.get('dest_ip_country') or dest_geo.get('country_code'),
        'dest_city': dest_geo.get('city'),
        'dest_latitude': dest_geo.get('latitude'),
        'dest_longitude': dest_geo.get('longitude'),
        'dest_asn': event.get('dst_ip_asn') or dest_geo.get('asn'),
        'dest_org': dest_geo.get('organization'),

        # Meta
        'site_id': event.get('site_id'),
        'archived': event.get('archived', False),
        'raw_data': json.dumps(event)
    }


async def trigger_threat_webhooks(
    session: AsyncSession,
    event_data: dict,
    action: str
):
    """
    Trigger webhooks for a threat event

    Args:
        session: Database session
        event_data: Parsed event data
        action: Event action (alert, block)
    """
    severity = event_data.get('severity') or 3  # Default to low if not specified

    # Get all enabled webhooks
    result = await session.execute(
        select(ThreatWebhookConfig).where(ThreatWebhookConfig.enabled == True)
    )
    webhooks = result.scalars().all()

    for webhook in webhooks:
        # Check severity threshold
        if severity > webhook.min_severity:
            continue  # Skip if severity is lower than threshold (higher number = lower severity)

        # Check action type
        if action == 'alert' and not webhook.event_alert:
            continue
        if action == 'block' and not webhook.event_block:
            continue

        try:
            # Build message for webhook
            severity_labels = {1: "🔴 High", 2: "🟠 Medium", 3: "🟡 Low"}
            severity_label = severity_labels.get(severity, f"Severity {severity}")

            message = f"**Threat Detected** ({severity_label})\n"
            message += f"**Signature:** {event_data.get('signature', 'Unknown')}\n"
            message += f"**Category:** {event_data.get('category', 'Unknown')}\n"
            message += f"**Action:** {action.upper()}\n"
            message += f"**Source:** {event_data.get('src_ip', '?')}:{event_data.get('src_port', '?')}"
            if event_data.get('src_country'):
                message += f" ({event_data['src_country']})"
            message += f"\n**Destination:** {event_data.get('dest_ip', '?')}:{event_data.get('dest_port', '?')}\n"

            await deliver_webhook(
                webhook_url=webhook.url,
                webhook_type=webhook.webhook_type,
                event_type='threat',
                device_name=event_data.get('signature', 'Unknown Threat'),
                device_mac=event_data.get('src_mac', ''),
                ap_name=None,
                signal_strength=None,
                custom_message=message
            )

            webhook.last_triggered = datetime.now(timezone.utc)
            logger.info(f"Triggered webhook '{webhook.name}' for threat event")

        except Exception as e:
            logger.error(f"Error triggering webhook {webhook.name}: {e}")


async def check_ignore_rules(session: AsyncSession, event_data: dict) -> tuple[bool, int | None]:
    """
    Check if an event should be ignored based on configured rules.

    Args:
        session: Database session
        event_data: Parsed event data

    Returns:
        Tuple of (should_ignore, rule_id) - rule_id is None if not ignored
    """
    src_ip = event_data.get('src_ip')
    dest_ip = event_data.get('dest_ip')
    severity = event_data.get('severity') or 3  # Default to low

    # Get all enabled ignore rules
    result = await session.execute(
        select(ThreatIgnoreRule).where(ThreatIgnoreRule.enabled == True)
    )
    rules = result.scalars().all()

    for rule in rules:
        ip_match = False

        # Check source IP match
        if rule.match_source and src_ip == rule.ip_address:
            ip_match = True
        # Check destination IP match
        if rule.match_destination and dest_ip == rule.ip_address:
            ip_match = True

        if not ip_match:
            continue

        # Check severity match
        should_ignore = False
        if severity == 1 and rule.ignore_high:
            should_ignore = True
        elif severity == 2 and rule.ignore_medium:
            should_ignore = True
        elif severity == 3 and rule.ignore_low:
            should_ignore = True

        if should_ignore:
            # Update rule stats
            rule.events_ignored += 1
            rule.last_matched = datetime.now(timezone.utc)
            logger.debug(f"Event matched ignore rule {rule.id} ({rule.ip_address})")
            return True, rule.id

    return False, None


async def refresh_threat_events():
    """
    Background task that polls for new IDS/IPS events

    This fetches events from UniFi and stores new ones in our database.
    """
    global _last_refresh

    try:
        logger.info("Starting threat events refresh task")

        # Get shared UniFi client (reuses persistent session)
        unifi_client = await get_shared_client()
        if not unifi_client:
            logger.warning("No UniFi connection available, skipping refresh")
            return

        db_instance = get_database()
        async for session in db_instance.get_session():
            # Get the most recent event timestamp from our database
            latest_result = await session.execute(
                select(func.max(ThreatEvent.timestamp))
            )
            latest_timestamp = latest_result.scalar()

            # Calculate start time for query
            # If we have events, get from last event time; otherwise get last 24 hours
            if latest_timestamp:
                # Add 1 second to avoid duplicates
                start_ms = int((latest_timestamp.timestamp() + 1) * 1000)
            else:
                # First run - get last 24 hours
                start_ms = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp() * 1000)

            # Fetch events from UniFi
            logger.debug(f"Fetching IPS events starting from timestamp: {start_ms}")
            raw_events = await unifi_client.get_ips_events(start=start_ms)
            logger.info(f"Retrieved {len(raw_events)} IPS events from UniFi")

            # Log if no events returned for debugging
            if not raw_events:
                logger.debug("No IPS events returned from UniFi API - this may be normal if no threats detected")

            # Process and store new events
            new_count = 0
            ignored_count = 0
            for raw_event in raw_events:
                event_data = parse_unifi_event(raw_event)

                # Check if event already exists
                existing = await session.execute(
                    select(ThreatEvent).where(
                        ThreatEvent.unifi_event_id == event_data['unifi_event_id']
                    )
                )
                if existing.scalar_one_or_none():
                    continue  # Skip duplicate

                # Check ignore rules
                should_ignore, ignore_rule_id = await check_ignore_rules(session, event_data)

                # Create new event with ignored flag
                new_event = ThreatEvent(
                    **event_data,
                    ignored=should_ignore,
                    ignored_by_rule_id=ignore_rule_id
                )
                session.add(new_event)
                new_count += 1

                if should_ignore:
                    ignored_count += 1
                    continue  # Skip webhooks for ignored events

                # Trigger webhooks only for non-ignored events
                action = event_data.get('action') or 'alert'
                await trigger_threat_webhooks(session, event_data, action)

            await session.commit()
            _last_refresh = datetime.now(timezone.utc)

            if new_count > 0:
                if ignored_count > 0:
                    logger.info(f"Stored {new_count} new threat events ({ignored_count} ignored)")
                else:
                    logger.info(f"Stored {new_count} new threat events")

                # Broadcast update via WebSocket
                ws_manager = get_ws_manager()
                await ws_manager.broadcast({
                    'type': 'threat_update',
                    'new_events': new_count
                })
            else:
                logger.debug("No new threat events")

            break  # Exit the async for loop

    except Exception as e:
        logger.error(f"Error in threat refresh task: {e}", exc_info=True)
        # Invalidate shared session so next cycle reconnects (handles session expiry)
        await invalidate_shared_client()


async def start_scheduler():
    """Start the background scheduler"""
    scheduler = get_scheduler()

    # Add the refresh job
    scheduler.add_job(
        refresh_threat_events,
        trigger=IntervalTrigger(seconds=DEFAULT_REFRESH_INTERVAL),
        id="refresh_threat_events",
        name="Refresh IDS/IPS threat events",
        replace_existing=True,
        misfire_grace_time=None,
        max_instances=1
    )

    # Start the scheduler
    scheduler.start()
    logger.info(f"Threat Watch scheduler started with refresh interval: {DEFAULT_REFRESH_INTERVAL} seconds")

    # Run immediately on startup
    await refresh_threat_events()


async def stop_scheduler():
    """Stop the background scheduler"""
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Threat Watch scheduler stopped")
