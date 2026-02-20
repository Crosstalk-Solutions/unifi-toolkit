"""
Pydantic models for API requests and responses
"""
from pydantic import BaseModel, Field, field_validator, field_serializer
from typing import Optional, Dict, List
from datetime import datetime, timezone
import re


def normalize_mac_address(mac: str) -> str:
    """
    Normalize MAC address to lowercase colon-separated format

    Args:
        mac: MAC address in any common format

    Returns:
        Normalized MAC address (e.g., "aa:bb:cc:dd:ee:ff")
    """
    # Remove all non-alphanumeric characters
    mac_clean = re.sub(r'[^a-fA-F0-9]', '', mac)

    # Validate length
    if len(mac_clean) != 12:
        raise ValueError("Invalid MAC address length")

    # Format as colon-separated lowercase
    mac_formatted = ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])
    return mac_formatted.lower()


def serialize_datetime(dt: Optional[datetime]) -> Optional[str]:
    """
    Serialize datetime to ISO format string with UTC timezone indicator

    Args:
        dt: datetime object (timezone-aware or naive)

    Returns:
        ISO format string with 'Z' suffix, or None if input is None
    """
    if dt is None:
        return None

    # If datetime is timezone-aware
    if dt.tzinfo is not None:
        # Convert to UTC if not already
        dt_utc = dt.astimezone(timezone.utc)
        # Return ISO format with 'Z' instead of '+00:00'
        return dt_utc.isoformat().replace('+00:00', 'Z')

    # If naive, assume it's UTC and add 'Z'
    return dt.isoformat() + 'Z'


# Device Models

class DeviceCreate(BaseModel):
    """
    Request model for creating a new tracked device
    """
    mac_address: str = Field(..., description="MAC address of the device")
    friendly_name: Optional[str] = Field(None, description="Friendly name for the device")
    site_id: str = Field(default="default", description="UniFi site ID")

    @field_validator('mac_address')
    @classmethod
    def validate_mac_address(cls, v: str) -> str:
        """Validate and normalize MAC address"""
        try:
            return normalize_mac_address(v)
        except ValueError as e:
            raise ValueError(f"Invalid MAC address: {e}")


class DeviceResponse(BaseModel):
    """
    Response model for device information
    """
    id: int
    mac_address: str
    friendly_name: Optional[str]
    added_at: datetime
    last_seen: Optional[datetime]
    current_ap_mac: Optional[str]
    current_ap_name: Optional[str]
    current_ssid: Optional[str] = None
    current_ip_address: Optional[str]
    current_signal_strength: Optional[int]
    current_radio: Optional[str] = None  # "ng" (2.4GHz), "na" (5GHz), "6e" (6GHz)
    is_connected: bool
    is_blocked: bool = False
    site_id: str
    # Wired device fields
    is_wired: bool = False
    current_switch_mac: Optional[str] = None
    current_switch_name: Optional[str] = None
    current_switch_port: Optional[int] = None

    @field_serializer('added_at', 'last_seen')
    def serialize_dt(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_datetime(dt)

    class Config:
        from_attributes = True


class DeviceListResponse(BaseModel):
    """
    Response model for list of devices
    """
    devices: list[DeviceResponse]
    total: int


# History Models

class HistoryEntry(BaseModel):
    """
    Response model for a single history entry
    """
    id: int
    device_id: int
    ap_mac: Optional[str]
    ap_name: Optional[str]
    ssid: Optional[str] = None
    connected_at: datetime
    disconnected_at: Optional[datetime]
    duration_seconds: Optional[int]
    signal_strength: Optional[int]
    # Wired device fields
    is_wired: bool = False
    switch_mac: Optional[str] = None
    switch_name: Optional[str] = None
    switch_port: Optional[int] = None

    @field_serializer('connected_at', 'disconnected_at')
    def serialize_dt(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_datetime(dt)

    class Config:
        from_attributes = True


class HistoryListResponse(BaseModel):
    """
    Response model for device history
    """
    device_id: int
    history: list[HistoryEntry]
    total: int


# UniFi Configuration Models

class UniFiConfigCreate(BaseModel):
    """
    Request model for UniFi controller configuration
    Supports both legacy (username/password) and UniFi OS (API key) authentication
    """
    controller_url: str = Field(..., description="UniFi controller URL")

    # Legacy auth (optional if using API key)
    username: Optional[str] = Field(None, description="UniFi username (legacy auth)")
    password: Optional[str] = Field(None, description="UniFi password (legacy auth)")

    # UniFi OS auth (optional if using username/password)
    api_key: Optional[str] = Field(None, description="UniFi API key (UniFi OS auth)")

    site_id: str = Field(default="default", description="UniFi site ID")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificates")


class UniFiConfigResponse(BaseModel):
    """
    Response model for UniFi configuration (without password/API key)
    """
    id: int
    controller_url: str
    username: Optional[str]  # May be None if using API key
    has_api_key: bool  # Indicates if API key is configured
    site_id: str
    verify_ssl: bool
    last_successful_connection: Optional[datetime]

    @field_serializer('last_successful_connection')
    def serialize_dt(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_datetime(dt)

    class Config:
        from_attributes = True


class UniFiConnectionTest(BaseModel):
    """
    Response model for UniFi connection test
    """
    connected: bool
    client_count: Optional[int] = None
    ap_count: Optional[int] = None
    site: Optional[str] = None
    error: Optional[str] = None


# Status Models

class SystemStatus(BaseModel):
    """
    Response model for system status
    """
    last_refresh: Optional[datetime]
    tracked_devices: int
    connected_devices: int
    refresh_interval_seconds: int

    @field_serializer('last_refresh')
    def serialize_dt(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_datetime(dt)


# Device Details Models

class DeviceDetailResponse(BaseModel):
    """
    Detailed response model for device information including live UniFi data
    """
    # Basic device info
    id: int
    mac_address: str
    friendly_name: Optional[str]
    added_at: datetime
    last_seen: Optional[datetime]
    current_ap_mac: Optional[str]
    current_ap_name: Optional[str]
    current_ssid: Optional[str] = None
    current_ip_address: Optional[str]
    current_signal_strength: Optional[int]
    is_connected: bool
    site_id: str
    # Wired device fields
    is_wired: bool = False
    current_switch_mac: Optional[str] = None
    current_switch_name: Optional[str] = None
    current_switch_port: Optional[int] = None

    # Live UniFi data (from current connection)
    hostname: Optional[str] = None
    manufacturer: Optional[str] = None
    tx_rate: Optional[float] = None  # Connection speed (Mbps)
    rx_rate: Optional[float] = None  # Connection speed (Mbps)
    channel: Optional[int] = None
    radio: Optional[str] = None  # "na" (5GHz), "ng" (2.4GHz), "6e" (6GHz)
    uptime: Optional[int] = None  # Seconds connected
    tx_bytes: Optional[int] = None
    rx_bytes: Optional[int] = None
    is_blocked: Optional[bool] = False

    @field_serializer('added_at', 'last_seen')
    def serialize_dt(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_datetime(dt)

    class Config:
        from_attributes = True


# UniFi Client Discovery Models

class UniFiClientInfo(BaseModel):
    """
    Response model for UniFi client information
    """
    mac_address: str
    name: Optional[str] = None  # Friendly name from UniFi (or hostname if no friendly name)
    hostname: Optional[str] = None
    is_tracked: bool = False


class UniFiClientsResponse(BaseModel):
    """
    Response model for list of UniFi clients
    """
    clients: list[UniFiClientInfo]
    total: int


# Generic Response Models

class SuccessResponse(BaseModel):
    """
    Generic success response
    """
    success: bool
    message: Optional[str] = None


class ErrorResponse(BaseModel):
    """
    Generic error response
    """
    error: str
    details: Optional[str] = None


# Webhook Models

class WebhookCreate(BaseModel):
    """
    Request model for creating a webhook
    """
    name: str
    webhook_type: str  # 'slack', 'discord', 'n8n'
    url: str
    event_device_connected: bool = True
    event_device_disconnected: bool = True
    event_device_roamed: bool = True
    event_device_blocked: bool = True
    event_device_unblocked: bool = True
    enabled: bool = True


class WebhookUpdate(BaseModel):
    """
    Request model for updating a webhook
    """
    name: Optional[str] = None
    url: Optional[str] = None
    event_device_connected: Optional[bool] = None
    event_device_disconnected: Optional[bool] = None
    event_device_roamed: Optional[bool] = None
    event_device_blocked: Optional[bool] = None
    event_device_unblocked: Optional[bool] = None
    enabled: Optional[bool] = None


class WebhookResponse(BaseModel):
    """
    Response model for webhook information
    """
    id: int
    name: str
    webhook_type: str
    url: str
    event_device_connected: bool
    event_device_disconnected: bool
    event_device_roamed: bool
    event_device_blocked: bool
    event_device_unblocked: bool
    enabled: bool
    created_at: datetime
    last_triggered: Optional[datetime] = None

    @field_serializer('created_at', 'last_triggered')
    def serialize_dt(self, dt: Optional[datetime], _info) -> Optional[str]:
        return serialize_datetime(dt)

    class Config:
        from_attributes = True


class WebhooksListResponse(BaseModel):
    """
    Response model for list of webhooks
    """
    webhooks: list[WebhookResponse]
    total: int


# Analytics Models

class DwellTimeResponse(BaseModel):
    """
    Response model for dwell time analytics.
    Shows time spent on each AP within the specified time window.
    """
    ap_times: Dict[str, int]  # ap_name -> minutes
    total_minutes: int
    window: str  # "24h", "7d", "30d", "all"


class FavoriteAPResponse(BaseModel):
    """
    Response model for favorite AP detection.
    Shows the AP where the device spends the most time (30-day window).
    """
    ap_name: Optional[str] = None
    total_hours: float = 0.0
    has_data: bool = False


class PresencePatternResponse(BaseModel):
    """
    Response model for presence pattern heat map.
    Returns a 24x7 matrix of minutes connected for each hour slot.
    """
    # 24 rows (hours 0-23), 7 columns (Mon-Sun)
    # Each value is average minutes connected during that hour slot
    data: List[List[int]]
    has_sufficient_data: bool
    days_of_data: int
