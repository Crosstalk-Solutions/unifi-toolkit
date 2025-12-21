"""
Webhook delivery system for sending device event notifications
"""
import aiohttp
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def format_duration(seconds: Optional[int]) -> Optional[str]:
    """
    Format a duration in seconds to a human-readable string

    Args:
        seconds: Duration in seconds (can be None)

    Returns:
        Formatted string like "1h 21m" or "2d 5h" or None if input is None
    """
    if seconds is None:
        return None

    if seconds < 60:
        return f"{seconds}s"

    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"

    hours = minutes // 60
    remaining_minutes = minutes % 60

    if hours < 24:
        if remaining_minutes > 0:
            return f"{hours}h {remaining_minutes}m"
        return f"{hours}h"

    days = hours // 24
    remaining_hours = hours % 24

    if remaining_hours > 0:
        return f"{days}d {remaining_hours}h"
    return f"{days}d"


async def deliver_webhook(
    webhook_url: str,
    webhook_type: str,
    event_type: str,
    device_name: str,
    device_mac: str,
    ap_name: Optional[str] = None,
    signal_strength: Optional[int] = None,
    offline_duration: Optional[int] = None
):
    """
    Deliver a webhook notification

    Args:
        webhook_url: The webhook URL to send to
        webhook_type: Type of webhook ('slack', 'discord', 'n8n')
        event_type: Type of event ('connected', 'disconnected', 'roamed', 'blocked', 'unblocked')
        device_name: Friendly name of the device
        device_mac: MAC address of the device
        ap_name: Name of the AP (for connected/roamed events)
        signal_strength: Signal strength in dBm (for connected/roamed events)
        offline_duration: Duration in seconds the device was offline (for connected events)
    """
    try:
        # Format message based on webhook type
        if webhook_type == 'slack':
            payload = format_slack_message(event_type, device_name, device_mac, ap_name, signal_strength, offline_duration)
        elif webhook_type == 'discord':
            payload = format_discord_message(event_type, device_name, device_mac, ap_name, signal_strength, offline_duration)
        elif webhook_type == 'n8n':
            payload = format_generic_message(event_type, device_name, device_mac, ap_name, signal_strength, offline_duration)
        else:
            logger.error(f"Unknown webhook type: {webhook_type}")
            return False

        # Send webhook
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload, timeout=10) as response:
                if response.status in [200, 204]:
                    logger.info(f"Webhook delivered successfully to {webhook_type}: {event_type} for {device_name}")
                    return True
                else:
                    logger.error(f"Webhook delivery failed: {response.status} - {await response.text()}")
                    return False

    except Exception as e:
        logger.error(f"Error delivering webhook: {e}", exc_info=True)
        return False


def format_slack_message(
    event_type: str,
    device_name: str,
    device_mac: str,
    ap_name: Optional[str],
    signal_strength: Optional[int],
    offline_duration: Optional[int] = None
) -> dict:
    """
    Format a message for Slack webhook

    Args:
        event_type: Type of event ('connected', 'disconnected', 'roamed', 'blocked', 'unblocked')
        device_name: Friendly name of the device
        device_mac: MAC address of the device
        ap_name: Name of the AP
        signal_strength: Signal strength in dBm
        offline_duration: Duration in seconds the device was offline (for connected events)

    Returns:
        Dictionary with Slack message payload
    """
    # Determine emoji and color based on event type
    if event_type == 'connected':
        emoji = ':white_check_mark:'
        color = 'good'
        title = f"{device_name} Connected"
        text = f"Device connected to {ap_name}"
    elif event_type == 'disconnected':
        emoji = ':x:'
        color = 'danger'
        title = f"{device_name} Disconnected"
        text = "Device went offline"
    elif event_type == 'blocked':
        emoji = ':no_entry:'
        color = '#FF5722'
        title = f"{device_name} Blocked"
        text = "Device has been blocked from the network"
    elif event_type == 'unblocked':
        emoji = ':unlock:'
        color = '#8BC34A'
        title = f"{device_name} Unblocked"
        text = "Device has been unblocked and can reconnect"
    else:  # roamed
        emoji = ':arrows_counterclockwise:'
        color = '#2196F3'
        title = f"{device_name} Roamed"
        text = f"Device moved to {ap_name}"

    # Build fields
    fields = [
        {
            "title": "Device",
            "value": device_name,
            "short": True
        },
        {
            "title": "MAC Address",
            "value": device_mac,
            "short": True
        }
    ]

    if ap_name and event_type != 'disconnected':
        fields.append({
            "title": "Access Point",
            "value": ap_name,
            "short": True
        })

    if signal_strength is not None and event_type != 'disconnected':
        fields.append({
            "title": "Signal",
            "value": f"{signal_strength} dBm",
            "short": True
        })

    # Add offline duration for connected events
    if event_type == 'connected':
        duration_str = format_duration(offline_duration) if offline_duration else "n/a"
        fields.append({
            "title": "Offline for",
            "value": duration_str,
            "short": True
        })

    return {
        "attachments": [
            {
                "color": color,
                "title": f"{emoji} {title}",
                "text": text,
                "fields": fields,
                "footer": "Wi-Fi Stalker | UI Toolkit",
                "ts": int(datetime.now(timezone.utc).timestamp())
            }
        ]
    }


def format_discord_message(
    event_type: str,
    device_name: str,
    device_mac: str,
    ap_name: Optional[str],
    signal_strength: Optional[int],
    offline_duration: Optional[int] = None
) -> dict:
    """
    Format a message for Discord webhook

    Args:
        event_type: Type of event ('connected', 'disconnected', 'roamed', 'blocked', 'unblocked')
        device_name: Friendly name of the device
        device_mac: MAC address of the device
        ap_name: Name of the AP
        signal_strength: Signal strength in dBm
        offline_duration: Duration in seconds the device was offline (for connected events)

    Returns:
        Dictionary with Discord message payload
    """
    # Determine color and description based on event type
    if event_type == 'connected':
        color = 0x4CAF50  # Green
        title = "✅ Device Connected"
        description = f"**{device_name}** connected to {ap_name}"
    elif event_type == 'disconnected':
        color = 0xF44336  # Red
        title = "❌ Device Disconnected"
        description = f"**{device_name}** went offline"
    elif event_type == 'blocked':
        color = 0xFF5722  # Deep Orange
        title = "🚫 Device Blocked"
        description = f"**{device_name}** has been blocked from the network"
    elif event_type == 'unblocked':
        color = 0x8BC34A  # Light Green
        title = "🔓 Device Unblocked"
        description = f"**{device_name}** has been unblocked and can reconnect"
    else:  # roamed
        color = 0x2196F3  # Blue
        title = "🔄 Device Roamed"
        description = f"**{device_name}** moved to {ap_name}"

    # Build fields
    fields = [
        {
            "name": "MAC Address",
            "value": device_mac,
            "inline": True
        }
    ]

    if ap_name and event_type != 'disconnected':
        fields.append({
            "name": "Access Point",
            "value": ap_name,
            "inline": True
        })

    if signal_strength is not None and event_type != 'disconnected':
        fields.append({
            "name": "Signal Strength",
            "value": f"{signal_strength} dBm",
            "inline": True
        })

    # Add offline duration for connected events
    if event_type == 'connected':
        duration_str = format_duration(offline_duration) if offline_duration else "n/a"
        fields.append({
            "name": "Offline for",
            "value": duration_str,
            "inline": True
        })

    return {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {
                    "text": "Wi-Fi Stalker | UI Toolkit"
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]
    }


def format_generic_message(
    event_type: str,
    device_name: str,
    device_mac: str,
    ap_name: Optional[str],
    signal_strength: Optional[int],
    offline_duration: Optional[int] = None
) -> dict:
    """
    Format a message for generic/n8n webhook

    Args:
        event_type: Type of event ('connected', 'disconnected', 'roamed', 'blocked', 'unblocked')
        device_name: Friendly name of the device
        device_mac: MAC address of the device
        ap_name: Name of the AP
        signal_strength: Signal strength in dBm
        offline_duration: Duration in seconds the device was offline (for connected events)

    Returns:
        Dictionary with generic JSON payload
    """
    payload = {
        "event_type": event_type,
        "device": {
            "name": device_name,
            "mac_address": device_mac
        },
        "access_point": ap_name,
        "signal_strength": signal_strength,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "unifi-toolkit"
    }

    # Add offline duration for connected events
    if event_type == 'connected':
        payload["offline_duration_seconds"] = offline_duration
        payload["offline_duration_formatted"] = format_duration(offline_duration) if offline_duration else None

    return payload


async def deliver_threat_webhook(
    webhook_url: str,
    webhook_type: str,
    threat_message: str,
    severity: int,
    action: str,
    src_ip: str,
    dest_ip: Optional[str] = None,
    category: Optional[str] = None,
    is_test: bool = False
) -> bool:
    """
    Deliver a threat notification webhook

    Args:
        webhook_url: The webhook URL to send to
        webhook_type: Type of webhook ('slack', 'discord', 'n8n')
        threat_message: Description of the threat
        severity: Severity level (1=High, 2=Medium, 3=Low)
        action: Action taken ('block' or 'alert')
        src_ip: Source IP address
        dest_ip: Destination IP address
        category: Threat category
        is_test: Whether this is a test notification
    """
    try:
        # Format message based on webhook type
        if webhook_type == 'slack':
            payload = format_slack_threat_message(
                threat_message, severity, action, src_ip, dest_ip, category, is_test
            )
        elif webhook_type == 'discord':
            payload = format_discord_threat_message(
                threat_message, severity, action, src_ip, dest_ip, category, is_test
            )
        elif webhook_type == 'n8n':
            payload = format_generic_threat_message(
                threat_message, severity, action, src_ip, dest_ip, category, is_test
            )
        else:
            logger.error(f"Unknown webhook type: {webhook_type}")
            return False

        # Send webhook
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=payload, timeout=10) as response:
                if response.status in [200, 204]:
                    logger.info(f"Threat webhook delivered successfully to {webhook_type}")
                    return True
                else:
                    logger.error(f"Threat webhook delivery failed: {response.status} - {await response.text()}")
                    return False

    except Exception as e:
        logger.error(f"Error delivering threat webhook: {e}", exc_info=True)
        return False


def get_severity_info(severity: int) -> tuple:
    """Get severity label, emoji and color"""
    if severity == 1:
        return "High", "🔴", "#dc3545", 0xdc3545
    elif severity == 2:
        return "Medium", "🟠", "#fd7e14", 0xfd7e14
    else:
        return "Low", "🟡", "#ffc107", 0xffc107


def format_slack_threat_message(
    threat_message: str,
    severity: int,
    action: str,
    src_ip: str,
    dest_ip: Optional[str],
    category: Optional[str],
    is_test: bool
) -> dict:
    """Format a threat message for Slack webhook"""
    severity_label, emoji, color, _ = get_severity_info(severity)
    action_text = "Blocked" if action == "block" else "Detected"

    title = f"{emoji} Threat {action_text}" + (" (TEST)" if is_test else "")

    fields = [
        {"title": "Threat", "value": threat_message, "short": False},
        {"title": "Severity", "value": severity_label, "short": True},
        {"title": "Action", "value": action_text, "short": True},
        {"title": "Source IP", "value": src_ip, "short": True}
    ]

    if dest_ip:
        fields.append({"title": "Destination IP", "value": dest_ip, "short": True})

    if category:
        fields.append({"title": "Category", "value": category, "short": True})

    return {
        "attachments": [
            {
                "color": color,
                "title": title,
                "fields": fields,
                "footer": "Threat Watch | UI Toolkit",
                "ts": int(datetime.now(timezone.utc).timestamp())
            }
        ]
    }


def format_discord_threat_message(
    threat_message: str,
    severity: int,
    action: str,
    src_ip: str,
    dest_ip: Optional[str],
    category: Optional[str],
    is_test: bool
) -> dict:
    """Format a threat message for Discord webhook"""
    severity_label, emoji, _, color = get_severity_info(severity)
    action_text = "Blocked" if action == "block" else "Detected"

    title = f"{emoji} Threat {action_text}" + (" (TEST)" if is_test else "")
    description = f"**{threat_message}**"

    fields = [
        {"name": "Severity", "value": severity_label, "inline": True},
        {"name": "Action", "value": action_text, "inline": True},
        {"name": "Source IP", "value": src_ip, "inline": True}
    ]

    if dest_ip:
        fields.append({"name": "Destination IP", "value": dest_ip, "inline": True})

    if category:
        fields.append({"name": "Category", "value": category, "inline": True})

    return {
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "footer": {"text": "Threat Watch | UI Toolkit"},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]
    }


def format_generic_threat_message(
    threat_message: str,
    severity: int,
    action: str,
    src_ip: str,
    dest_ip: Optional[str],
    category: Optional[str],
    is_test: bool
) -> dict:
    """Format a threat message for generic/n8n webhook"""
    severity_labels = {1: "high", 2: "medium", 3: "low"}

    return {
        "event_type": "threat_detected",
        "is_test": is_test,
        "threat": {
            "message": threat_message,
            "severity": severity_labels.get(severity, "unknown"),
            "severity_level": severity,
            "action": action,
            "category": category
        },
        "source_ip": src_ip,
        "destination_ip": dest_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "unifi-toolkit"
    }
