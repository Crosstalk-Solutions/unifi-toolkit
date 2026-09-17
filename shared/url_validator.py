"""
URL validation utilities to prevent SSRF attacks

This module provides functions to validate webhook URLs and block
potentially dangerous destinations like internal networks, localhost,
and cloud metadata endpoints.
"""
import ipaddress
import logging
import socket
from urllib.parse import urlparse
from typing import Tuple

logger = logging.getLogger(__name__)

# Private/internal IP ranges that should be blocked
BLOCKED_IP_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),        # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),     # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),    # Private Class C
    ipaddress.ip_network('127.0.0.0/8'),       # Loopback
    ipaddress.ip_network('169.254.0.0/16'),    # Link-local (includes cloud metadata)
    ipaddress.ip_network('0.0.0.0/8'),         # "This" network
    ipaddress.ip_network('224.0.0.0/4'),       # Multicast
    ipaddress.ip_network('240.0.0.0/4'),       # Reserved
    ipaddress.ip_network('100.64.0.0/10'),     # Carrier-grade NAT
    ipaddress.ip_network('192.0.0.0/24'),      # IETF Protocol Assignments
    ipaddress.ip_network('192.0.2.0/24'),      # TEST-NET-1
    ipaddress.ip_network('198.51.100.0/24'),   # TEST-NET-2
    ipaddress.ip_network('203.0.113.0/24'),    # TEST-NET-3
    ipaddress.ip_network('fc00::/7'),          # IPv6 Unique Local
    ipaddress.ip_network('fe80::/10'),         # IPv6 Link-Local
    ipaddress.ip_network('::1/128'),           # IPv6 Loopback
]

# Blocked hostnames (case-insensitive)
BLOCKED_HOSTNAMES = [
    'localhost',
    'localhost.localdomain',
    'metadata.google.internal',      # GCP metadata
    'metadata.goog',                 # GCP metadata alternative
]

# Cloud metadata IP (special case - always block)
CLOUD_METADATA_IP = '169.254.169.254'


def is_ip_blocked(ip_str: str) -> bool:
    """
    Check if an IP address is in a blocked range.

    Args:
        ip_str: IP address as string

    Returns:
        True if the IP is blocked, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for blocked_range in BLOCKED_IP_RANGES:
            if ip in blocked_range:
                return True
        return False
    except ValueError:
        # Invalid IP address format
        return False


def resolve_hostname(hostname: str) -> list:
    """
    Resolve hostname to IP addresses.

    Args:
        hostname: Hostname to resolve

    Returns:
        List of IP addresses, or empty list if resolution fails
    """
    try:
        # Get all IP addresses for the hostname
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(set(result[4][0] for result in results))
        return ips
    except socket.gaierror:
        return []


def validate_webhook_url(url: str) -> Tuple[bool, str]:
    """
    Validate a webhook URL to prevent SSRF attacks.

    Checks:
    1. URL scheme is http or https
    2. Hostname is not in blocked list
    3. Resolved IP addresses are not in blocked ranges

    Args:
        url: The webhook URL to validate

    Returns:
        Tuple of (is_valid, error_message)
        If valid, error_message will be empty string
    """
    if not url:
        return False, "URL is required"

    # Parse the URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        logger.warning(f"Failed to parse URL: {url} - {e}")
        return False, "Invalid URL format"

    # Check scheme
    if parsed.scheme not in ('http', 'https'):
        return False, "URL must use http or https scheme"

    # Get hostname
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must include a hostname"

    hostname_lower = hostname.lower()

    # Check against blocked hostnames
    if hostname_lower in BLOCKED_HOSTNAMES:
        logger.warning(f"Blocked webhook URL with hostname: {hostname}")
        return False, "This hostname is not allowed for webhooks"

    # Check if hostname is an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if is_ip_blocked(str(ip)):
            logger.warning(f"Blocked webhook URL with private/reserved IP: {hostname}")
            return False, "Private, reserved, or internal IP addresses are not allowed"
        # Valid public IP
        return True, ""
    except ValueError:
        # Not an IP address, it's a hostname - resolve it
        pass

    # Resolve hostname and check all IPs
    resolved_ips = resolve_hostname(hostname)

    if not resolved_ips:
        # Can't resolve - allow it (DNS might resolve at delivery time)
        # This is a trade-off: we could block unresolvable hostnames,
        # but legitimate webhooks might use hostnames that aren't resolvable
        # from this server's network
        logger.debug(f"Could not resolve hostname: {hostname}")
        return True, ""

    # Check all resolved IPs
    for ip in resolved_ips:
        if is_ip_blocked(ip):
            logger.warning(f"Blocked webhook URL: {url} resolves to blocked IP: {ip}")
            return False, f"URL resolves to a private or reserved IP address"

    return True, ""


def is_safe_webhook_url(url: str) -> bool:
    """
    Simple boolean check if a webhook URL is safe.

    Args:
        url: The webhook URL to check

    Returns:
        True if safe, False otherwise
    """
    is_valid, _ = validate_webhook_url(url)
    return is_valid


def validate_controller_url(url: str) -> Tuple[bool, str]:
    """
    Validate a user-supplied UniFi controller URL before we connect to it.

    Unlike webhook URLs, a controller legitimately lives on a private IP, so we
    do NOT block private ranges here. We only close the SSRF vectors that have
    no business in a controller URL:

    1. Scheme must be http or https (blocks file://, gopher://, etc.).
    2. No embedded credentials (userinfo before the host).
    3. A host must actually be present.

    Returns (is_valid, error_message); error_message is "" when valid.
    """
    if not url or not url.strip():
        return False, "Controller URL is required"
    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Invalid controller URL"
    if parsed.scheme not in ("http", "https"):
        return False, "Controller URL must use http or https"
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return False, "Controller URL must not contain embedded credentials"
    if not parsed.hostname:
        return False, "Controller URL must include a host"
    return True, ""
