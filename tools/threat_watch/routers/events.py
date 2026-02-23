"""
API routes for threat events
"""
import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, asc, desc, and_, or_
from datetime import datetime, timezone, timedelta
from typing import Optional

from shared.database import get_db_session
from tools.threat_watch.database import ThreatEvent, ThreatIgnoreRule

logger = logging.getLogger(__name__)
from tools.threat_watch.models import (
    ThreatEventResponse,
    ThreatEventDetail,
    ThreatEventsListResponse,
    ThreatStatsResponse,
    ThreatTimelineResponse,
    SeverityCount,
    CategoryCount,
    CountryCount,
    TopAttacker,
    TimelinePoint,
    IgnoreRuleResponse,
    SuccessResponse
)

router = APIRouter(prefix="/api/events", tags=["events"])

SEVERITY_LABELS = {
    1: "High",
    2: "Medium",
    3: "Low"
}

TIME_RANGE_MAP = {
    "24h": timedelta(days=1),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


@router.get("", response_model=ThreatEventsListResponse)
async def get_events(
    start_time: Optional[datetime] = Query(None, description="Filter events after this time"),
    end_time: Optional[datetime] = Query(None, description="Filter events before this time"),
    time_range: Optional[str] = Query(None, pattern="^(24h|7d|30d)$", description="Time range shortcut (24h, 7d, 30d)"),
    severity: Optional[int] = Query(None, ge=1, le=3, description="Filter by severity (1=high, 2=medium, 3=low)"),
    category: Optional[str] = Query(None, description="Filter by category"),
    action: Optional[str] = Query(None, description="Filter by action (alert, block)"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dest_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    search: Optional[str] = Query(None, description="Search in signature/message"),
    include_ignored: bool = Query(False, description="Include events that match ignore rules"),
    sort: Optional[str] = Query(None, description="Column to sort by"),
    sort_direction: Optional[str] = Query(None, pattern="^(asc|desc)$", description="Sort direction (asc or desc)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Events per page"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get paginated list of threat events with optional filtering
    """
    # Build query
    query = select(ThreatEvent)
    count_query = select(func.count(ThreatEvent.id))

    # Apply filters
    filters = []

    # By default, exclude ignored events unless include_ignored is True
    if not include_ignored:
        filters.append(ThreatEvent.ignored == False)

    # time_range shortcut overrides start_time
    if time_range and time_range in TIME_RANGE_MAP:
        cutoff = datetime.now(timezone.utc) - TIME_RANGE_MAP[time_range]
        filters.append(ThreatEvent.timestamp >= cutoff)
    elif start_time:
        filters.append(ThreatEvent.timestamp >= start_time)
    if end_time:
        filters.append(ThreatEvent.timestamp <= end_time)
    if severity:
        filters.append(ThreatEvent.severity == severity)
    if category:
        filters.append(ThreatEvent.category == category)
    if action:
        filters.append(ThreatEvent.action == action)
    if src_ip:
        filters.append(ThreatEvent.src_ip == src_ip)
    if dest_ip:
        filters.append(ThreatEvent.dest_ip == dest_ip)
    if search:
        search_filter = or_(
            ThreatEvent.signature.ilike(f"%{search}%"),
            ThreatEvent.message.ilike(f"%{search}%")
        )
        filters.append(search_filter)

    if filters:
        query = query.where(and_(*filters))
        count_query = count_query.where(and_(*filters))

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply sorting
    sortable_columns = {
        'timestamp': ThreatEvent.timestamp,
        'severity': ThreatEvent.severity,
        'action': ThreatEvent.action,
        'category': ThreatEvent.category,
        'src_ip': ThreatEvent.src_ip,
        'dest_ip': ThreatEvent.dest_ip,
        'signature': ThreatEvent.signature,
    }
    sort_col = sortable_columns.get(sort, ThreatEvent.timestamp)
    sort_fn = asc if sort_direction == 'asc' else desc

    # Apply pagination and ordering
    offset = (page - 1) * page_size
    query = query.order_by(sort_fn(sort_col)).offset(offset).limit(page_size)

    # Execute query
    result = await db.execute(query)
    events = result.scalars().all()

    has_more = (offset + len(events)) < total

    return ThreatEventsListResponse(
        events=[ThreatEventResponse.model_validate(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more
    )


@router.get("/stats", response_model=ThreatStatsResponse)
async def get_stats(
    time_range: Optional[str] = Query(None, pattern="^(24h|7d|30d)$", description="Time range shortcut (24h, 7d, 30d)"),
    include_ignored: bool = Query(False, description="Include ignored events in stats"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get threat statistics overview, scoped to the selected time range
    """
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)

    # Count of ignored events (always returned, not scoped to time range)
    ignored_result = await db.execute(
        select(func.count(ThreatEvent.id)).where(ThreatEvent.ignored == True)
    )
    ignored_count = ignored_result.scalar() or 0

    # Base filters
    base_filters = []

    # Exclude ignored events unless include_ignored is True
    if not include_ignored:
        base_filters.append(ThreatEvent.ignored == False)

    # Apply time range filter to all stats
    if time_range and time_range in TIME_RANGE_MAP:
        cutoff = now - TIME_RANGE_MAP[time_range]
        base_filters.append(ThreatEvent.timestamp >= cutoff)

    # Total events (within time range)
    total_query = select(func.count(ThreatEvent.id))
    if base_filters:
        total_query = total_query.where(*base_filters)
    total_result = await db.execute(total_query)
    total_events = total_result.scalar() or 0

    # Events in last 24 hours
    query_24h = select(func.count(ThreatEvent.id)).where(ThreatEvent.timestamp >= day_ago)
    if not include_ignored:
        query_24h = query_24h.where(ThreatEvent.ignored == False)
    result_24h = await db.execute(query_24h)
    events_24h = result_24h.scalar() or 0

    # Events in last 7 days
    query_7d = select(func.count(ThreatEvent.id)).where(ThreatEvent.timestamp >= week_ago)
    if not include_ignored:
        query_7d = query_7d.where(ThreatEvent.ignored == False)
    result_7d = await db.execute(query_7d)
    events_7d = result_7d.scalar() or 0

    # Blocked vs Alert counts (within time range)
    blocked_query = select(func.count(ThreatEvent.id)).where(ThreatEvent.action == "block")
    if base_filters:
        blocked_query = blocked_query.where(*base_filters)
    blocked_result = await db.execute(blocked_query)
    blocked_count = blocked_result.scalar() or 0

    alert_query = select(func.count(ThreatEvent.id)).where(ThreatEvent.action == "alert")
    if base_filters:
        alert_query = alert_query.where(*base_filters)
    alert_result = await db.execute(alert_query)
    alert_count = alert_result.scalar() or 0

    # By severity (within time range)
    severity_query = (
        select(ThreatEvent.severity, func.count(ThreatEvent.id))
        .where(ThreatEvent.severity.isnot(None))
    )
    if base_filters:
        severity_query = severity_query.where(*base_filters)
    severity_query = severity_query.group_by(ThreatEvent.severity).order_by(ThreatEvent.severity)
    severity_result = await db.execute(severity_query)
    by_severity = [
        SeverityCount(
            severity=sev,
            label=SEVERITY_LABELS.get(sev, f"Severity {sev}"),
            count=count
        )
        for sev, count in severity_result.all()
    ]

    # By category (top 10, within time range)
    category_query = (
        select(ThreatEvent.category, func.count(ThreatEvent.id))
        .where(ThreatEvent.category.isnot(None))
    )
    if base_filters:
        category_query = category_query.where(*base_filters)
    category_query = category_query.group_by(ThreatEvent.category).order_by(desc(func.count(ThreatEvent.id))).limit(10)
    category_result = await db.execute(category_query)
    by_category = [
        CategoryCount(category=cat or "Unknown", count=count)
        for cat, count in category_result.all()
    ]

    # By source country (top 10, within time range)
    country_query = (
        select(ThreatEvent.src_country, func.count(ThreatEvent.id))
        .where(ThreatEvent.src_country.isnot(None))
    )
    if base_filters:
        country_query = country_query.where(*base_filters)
    country_query = country_query.group_by(ThreatEvent.src_country).order_by(desc(func.count(ThreatEvent.id))).limit(10)
    country_result = await db.execute(country_query)
    by_country = [
        CountryCount(country=country or "Unknown", country_code=country, count=count)
        for country, count in country_result.all()
    ]

    # Top attackers (top 10 source IPs, within time range)
    attackers_query = (
        select(
            ThreatEvent.src_ip,
            func.count(ThreatEvent.id).label('count'),
            func.max(ThreatEvent.src_country).label('country'),
            func.max(ThreatEvent.src_org).label('org'),
            func.max(ThreatEvent.timestamp).label('last_seen')
        )
        .where(ThreatEvent.src_ip.isnot(None))
    )
    if base_filters:
        attackers_query = attackers_query.where(*base_filters)
    attackers_query = attackers_query.group_by(ThreatEvent.src_ip).order_by(desc(func.count(ThreatEvent.id))).limit(10)
    attackers_result = await db.execute(attackers_query)
    top_attackers = [
        TopAttacker(
            ip=row.src_ip,
            count=row.count,
            country=row.country,
            org=row.org,
            last_seen=row.last_seen
        )
        for row in attackers_result.all()
    ]

    return ThreatStatsResponse(
        total_events=total_events,
        events_24h=events_24h,
        events_7d=events_7d,
        blocked_count=blocked_count,
        alert_count=alert_count,
        ignored_count=ignored_count,
        by_severity=by_severity,
        by_category=by_category,
        by_country=by_country,
        top_attackers=top_attackers
    )


@router.get("/timeline", response_model=ThreatTimelineResponse)
async def get_timeline(
    interval: str = Query("hour", pattern="^(hour|day)$", description="Time interval (hour or day)"),
    days: int = Query(7, ge=1, le=30, description="Number of days to include"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get threat event counts over time for charting
    """
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(days=days)

    # Get all events in range
    result = await db.execute(
        select(ThreatEvent.timestamp)
        .where(ThreatEvent.timestamp >= start_time)
        .order_by(ThreatEvent.timestamp)
    )
    timestamps = [row[0] for row in result.all()]

    # Bucket by interval
    buckets = {}
    for ts in timestamps:
        if interval == "hour":
            bucket = ts.replace(minute=0, second=0, microsecond=0)
        else:  # day
            bucket = ts.replace(hour=0, minute=0, second=0, microsecond=0)

        if bucket not in buckets:
            buckets[bucket] = 0
        buckets[bucket] += 1

    # Convert to list sorted by time
    data = [
        TimelinePoint(timestamp=ts, count=count)
        for ts, count in sorted(buckets.items())
    ]

    return ThreatTimelineResponse(interval=interval, data=data)


@router.get("/categories")
async def get_categories(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get list of all threat categories
    """
    result = await db.execute(
        select(ThreatEvent.category)
        .where(ThreatEvent.category.isnot(None))
        .distinct()
        .order_by(ThreatEvent.category)
    )
    categories = [row[0] for row in result.all()]
    return {"categories": categories}


@router.get("/{event_id}", response_model=ThreatEventDetail)
async def get_event(
    event_id: int,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get detailed information for a single threat event
    """
    result = await db.execute(
        select(ThreatEvent).where(ThreatEvent.id == event_id)
    )
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    return ThreatEventDetail.model_validate(event)


@router.post("/{event_id}/ignore", response_model=IgnoreRuleResponse)
async def ignore_event_ip(
    event_id: int,
    ignore_high: bool = Query(False, description="Ignore high severity events"),
    ignore_medium: bool = Query(True, description="Ignore medium severity events"),
    ignore_low: bool = Query(True, description="Ignore low severity events"),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Create an ignore rule from an event's source IP.
    Quick way to add an IP to the ignore list directly from an event.
    """
    # Get the event
    result = await db.execute(
        select(ThreatEvent).where(ThreatEvent.id == event_id)
    )
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    if not event.src_ip:
        raise HTTPException(status_code=400, detail="Event has no source IP")

    # At least one severity must be selected
    if not (ignore_high or ignore_medium or ignore_low):
        raise HTTPException(
            status_code=400,
            detail="At least one severity level must be selected to ignore."
        )

    # Check if rule already exists for this IP
    existing = await db.execute(
        select(ThreatIgnoreRule).where(ThreatIgnoreRule.ip_address == event.src_ip)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail=f"Ignore rule already exists for {event.src_ip}"
        )

    # Create new ignore rule
    new_rule = ThreatIgnoreRule(
        ip_address=event.src_ip,
        description=f"Quick-ignore from event {event_id}",
        ignore_high=ignore_high,
        ignore_medium=ignore_medium,
        ignore_low=ignore_low,
        match_source=True,
        match_destination=False,
        enabled=True
    )

    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)

    return IgnoreRuleResponse.model_validate(new_rule)


@router.get("/ip/{ip_address}")
async def get_events_by_ip(
    ip_address: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db_session)
):
    """
    Get all events for a specific IP address (source or destination)
    """
    # Build query for events where IP is source or destination
    query = select(ThreatEvent).where(
        or_(
            ThreatEvent.src_ip == ip_address,
            ThreatEvent.dest_ip == ip_address
        )
    )
    count_query = select(func.count(ThreatEvent.id)).where(
        or_(
            ThreatEvent.src_ip == ip_address,
            ThreatEvent.dest_ip == ip_address
        )
    )

    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply pagination and ordering
    offset = (page - 1) * page_size
    query = query.order_by(desc(ThreatEvent.timestamp)).offset(offset).limit(page_size)

    # Execute query
    result = await db.execute(query)
    events = result.scalars().all()

    has_more = (offset + len(events)) < total

    return ThreatEventsListResponse(
        events=[ThreatEventResponse.model_validate(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more
    )


@router.get("/debug/test-fetch")
async def debug_test_fetch(
    db: AsyncSession = Depends(get_db_session)
):
    """
    Debug endpoint to test IPS event fetching from UniFi.

    This endpoint connects to UniFi, attempts to fetch IPS events using both
    the v2 traffic-flows API (Network 10.x+) and legacy stat/ips/event API,
    and returns diagnostic information about the responses.
    """
    from shared.models.unifi_config import UniFiConfig
    from shared.unifi_client import UniFiClient
    from shared.crypto import decrypt_password, decrypt_api_key
    import time

    # Get UniFi config
    result = await db.execute(select(UniFiConfig).where(UniFiConfig.id == 1))
    unifi_config = result.scalar_one_or_none()

    if not unifi_config:
        return {
            "success": False,
            "error": "No UniFi configuration found",
            "hint": "Configure UniFi controller in dashboard settings"
        }

    # Decrypt credentials
    password = None
    api_key = None
    try:
        if unifi_config.password_encrypted:
            password = decrypt_password(unifi_config.password_encrypted)
        if unifi_config.api_key_encrypted:
            api_key = decrypt_api_key(unifi_config.api_key_encrypted)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to decrypt credentials: {str(e)}"
        }

    # Create client
    client = UniFiClient(
        host=unifi_config.controller_url,
        username=unifi_config.username,
        password=password,
        api_key=api_key,
        site=unifi_config.site_id,
        verify_ssl=unifi_config.verify_ssl
    )

    try:
        # Connect
        connected = await client.connect()
        if not connected:
            return {
                "success": False,
                "error": "Failed to connect to UniFi controller",
                "controller_url": unifi_config.controller_url,
                "site": unifi_config.site_id
            }

        # Get gateway info
        gateway_info = await client.get_gateway_info()
        ips_settings = await client.get_ips_settings()

        # Calculate time range (last 24 hours)
        now_ms = int(time.time() * 1000)
        day_ago_ms = now_ms - (24 * 60 * 60 * 1000)

        # Test both APIs separately for diagnostics
        v2_events = []
        legacy_events = []
        v2_error = None
        legacy_error = None

        # Test v2 traffic-flows API (Network 10.x+)
        if client.is_unifi_os:
            try:
                v2_events = await client.get_traffic_flows(
                    timestamp_from=day_ago_ms,
                    timestamp_to=now_ms,
                    page_size=25,
                    max_events=25
                )
            except Exception as e:
                v2_error = str(e)

        # Test legacy stat/ips/event API
        try:
            if client.is_unifi_os:
                url = f"{client.host}/proxy/network/api/s/{client.site}/stat/ips/event"
            else:
                url = f"{client.host}/api/s/{client.site}/stat/ips/event"

            payload = {
                "start": day_ago_ms,
                "end": now_ms,
                "_limit": 10
            }

            async with client._session.post(url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    legacy_events = data.get('data', [])
                else:
                    legacy_error = f"HTTP {resp.status}"
        except Exception as e:
            legacy_error = str(e)

        # Determine which API is working
        working_api = None
        if v2_events:
            working_api = "v2_traffic_flows"
        elif legacy_events:
            working_api = "legacy_stat_ips_event"

        # Build diagnostic response
        response = {
            "success": True,
            "connection": {
                "controller_url": unifi_config.controller_url,
                "site": unifi_config.site_id,
                "is_unifi_os": client.is_unifi_os,
                "detected_type": client._detected_type
            },
            "gateway": gateway_info,
            "ips_settings": ips_settings,
            "api_tests": {
                "v2_traffic_flows": {
                    "available": client.is_unifi_os,
                    "events_returned": len(v2_events),
                    "error": v2_error,
                    "payload_format": "v2_filtered" if client._v2_uses_new_payload else "legacy_pagination" if client._v2_uses_new_payload is False else "unknown",
                    "sample_event_keys": list(v2_events[0].keys()) if v2_events else None,
                    "sample_event": v2_events[0] if v2_events else None,
                    "endpoint": "/proxy/network/v2/api/site/{site}/traffic-flows"
                },
                "legacy_stat_ips_event": {
                    "available": True,
                    "events_returned": len(legacy_events),
                    "error": legacy_error,
                    "sample_event_keys": list(legacy_events[0].keys()) if legacy_events else None,
                    "sample_event": legacy_events[0] if legacy_events else None,
                    "endpoint": "/proxy/network/api/s/{site}/stat/ips/event"
                }
            },
            "working_api": working_api,
            "total_events": len(v2_events) + len(legacy_events)
        }

        # Check for common issues
        issues = []
        if not gateway_info.get("has_gateway"):
            issues.append("No gateway device found")
        if not gateway_info.get("supports_ids_ips"):
            issues.append(f"Gateway ({gateway_info.get('gateway_name')}) does not support IDS/IPS")
        if ips_settings and not ips_settings.get("ips_enabled"):
            issues.append(f"IDS/IPS is disabled (mode: {ips_settings.get('ips_mode')})")
        if not client.is_unifi_os:
            issues.append("Legacy controller detected - v2 API not available")
        if len(v2_events) == 0 and len(legacy_events) == 0:
            issues.append("No events returned from either API - this may be normal if no threats detected in last 24 hours")
        if v2_events and not legacy_events:
            issues.append("Only v2 API returned events - using Network 10.x traffic-flows endpoint")
        if legacy_events and not v2_events and client.is_unifi_os:
            issues.append("Only legacy API returned events - v2 traffic-flows may not be available on this firmware")

        if issues:
            response["issues"] = issues

        return response

    except Exception as e:
        logger.exception("Debug test fetch failed")
        return {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__
        }
    finally:
        await client.disconnect()
