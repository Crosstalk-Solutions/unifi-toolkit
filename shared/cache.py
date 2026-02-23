"""
Simple in-memory cache for UniFi data to avoid repeated API calls.

The cache stores gateway info, IPS settings, and other data that doesn't
change frequently. Data is cached with a TTL and refreshed on demand.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Cache TTL in seconds (how long before data is considered stale)
CACHE_TTL_SECONDS = 30

# Update check TTL — 1 hour to avoid GitHub API rate limits
UPDATE_CHECK_TTL_SECONDS = 3600

# Global cache storage
_cache: Dict[str, Dict[str, Any]] = {}


def _is_expired(cache_entry: Dict[str, Any]) -> bool:
    """Check if a cache entry has expired."""
    if not cache_entry or "timestamp" not in cache_entry:
        return True

    age = datetime.now(timezone.utc) - cache_entry["timestamp"]
    return age.total_seconds() > CACHE_TTL_SECONDS


def get_gateway_info() -> Optional[Dict]:
    """
    Get cached gateway info.

    Returns:
        Gateway info dict if cached and not expired, None otherwise
    """
    entry = _cache.get("gateway_info")
    if entry and not _is_expired(entry):
        logger.debug("Returning cached gateway info")
        return entry.get("data")
    return None


def set_gateway_info(data: Dict):
    """
    Cache gateway info.

    Args:
        data: Gateway info dict from get_gateway_info()
    """
    _cache["gateway_info"] = {
        "data": data,
        "timestamp": datetime.now(timezone.utc)
    }
    logger.debug(f"Cached gateway info: {data.get('gateway_name', 'Unknown')}")


def get_ips_settings() -> Optional[Dict]:
    """
    Get cached IPS settings.

    Returns:
        IPS settings dict if cached and not expired, None otherwise
    """
    entry = _cache.get("ips_settings")
    if entry and not _is_expired(entry):
        logger.debug("Returning cached IPS settings")
        return entry.get("data")
    return None


def set_ips_settings(data: Dict):
    """
    Cache IPS settings.

    Args:
        data: IPS settings dict from get_ips_settings()
    """
    _cache["ips_settings"] = {
        "data": data,
        "timestamp": datetime.now(timezone.utc)
    }
    logger.debug(f"Cached IPS settings: mode={data.get('ips_mode', 'unknown')}")


def get_system_status() -> Optional[Dict]:
    """
    Get cached system status (full status including health).

    Returns:
        System status dict if cached and not expired, None otherwise
    """
    entry = _cache.get("system_status")
    if entry and not _is_expired(entry):
        logger.debug("Returning cached system status")
        return entry.get("data")
    return None


def set_system_status(data: Dict):
    """
    Cache full system status.

    Args:
        data: System status response dict
    """
    _cache["system_status"] = {
        "data": data,
        "timestamp": datetime.now(timezone.utc)
    }
    logger.debug("Cached system status")


def _is_expired_custom(cache_entry: Dict[str, Any], ttl_seconds: int) -> bool:
    """Check if a cache entry has expired with a custom TTL."""
    if not cache_entry or "timestamp" not in cache_entry:
        return True
    age = datetime.now(timezone.utc) - cache_entry["timestamp"]
    return age.total_seconds() > ttl_seconds


def get_update_check() -> Optional[Dict]:
    """Get cached update check result (1-hour TTL)."""
    entry = _cache.get("update_check")
    if entry and not _is_expired_custom(entry, UPDATE_CHECK_TTL_SECONDS):
        logger.debug("Returning cached update check")
        return entry.get("data")
    return None


def set_update_check(data: Dict):
    """Cache update check result."""
    _cache["update_check"] = {
        "data": data,
        "timestamp": datetime.now(timezone.utc)
    }
    logger.debug(f"Cached update check: update_available={data.get('update_available')}")


def invalidate_all():
    """
    Invalidate all cached data.
    Call this after config changes or on errors.
    """
    global _cache
    _cache = {}
    logger.debug("Cache invalidated")


def invalidate(key: str):
    """
    Invalidate a specific cache entry.

    Args:
        key: Cache key to invalidate (e.g., "gateway_info", "ips_settings")
    """
    if key in _cache:
        del _cache[key]
        logger.debug(f"Cache entry '{key}' invalidated")


def get_cache_age(key: str) -> Optional[float]:
    """
    Get the age of a cache entry in seconds.

    Args:
        key: Cache key to check

    Returns:
        Age in seconds, or None if not cached
    """
    entry = _cache.get(key)
    if entry and "timestamp" in entry:
        age = datetime.now(timezone.utc) - entry["timestamp"]
        return age.total_seconds()
    return None
