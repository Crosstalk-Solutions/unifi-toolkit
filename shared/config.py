"""
Configuration management for UI Toolkit
"""
from pydantic_settings import BaseSettings
from typing import Optional


class ToolkitSettings(BaseSettings):
    """
    UI Toolkit settings loaded from environment variables
    """
    # Required
    encryption_key: str

    # Deployment settings
    deployment_type: str = "local"  # "local" or "production"
    domain: Optional[str] = None
    # Extra Host header values to accept, comma-separated, for the anti-DNS-
    # rebinding check (see RebindingProtectionMiddleware). IP literals,
    # localhost, *.local/.lan/.internal/.home[.arpa], and `domain` are always
    # allowed; set this for a reverse-proxy hostname (e.g. Tailscale/*.ts.net)
    # not covered by those. "*" disables the check entirely.
    allowed_hosts: Optional[str] = None
    auth_username: str = "admin"
    auth_password_hash: Optional[str] = None

    # Database
    database_url: str = "sqlite+aiosqlite:///./data/unifi_toolkit.db"

    # Logging
    log_level: str = "INFO"

    # UniFi Controller (optional - can be configured via UI)
    unifi_controller_url: Optional[str] = None
    unifi_username: Optional[str] = None
    unifi_password: Optional[str] = None
    unifi_api_key: Optional[str] = None
    unifi_site_id: str = "default"
    unifi_verify_ssl: bool = False

    # Webhooks: allow private/LAN webhook targets (Home Assistant, n8n, ntfy,
    # etc. on your own network). Off by default so a toolkit exposed beyond
    # the LAN can't be used to probe it; cloud-metadata and link-local
    # addresses stay blocked even when this is on.
    webhook_allow_private_ips: bool = False

    # Tool-specific settings
    stalker_refresh_interval: int = 60

    # Server settings
    app_port: int = 8000

    class Config:
        env_file = ".env"
        extra = "ignore"


_settings: Optional[ToolkitSettings] = None


def get_settings() -> ToolkitSettings:
    """
    Get the global settings instance (singleton pattern)
    """
    global _settings
    if _settings is None:
        _settings = ToolkitSettings()
    return _settings
