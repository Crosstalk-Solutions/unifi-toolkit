"""
Database models for Wi-Fi Stalker
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey, LargeBinary, UniqueConstraint
from sqlalchemy.orm import relationship
from shared.models.base import Base


class TrackedDevice(Base):
    """
    Represents a device that the user wants to track (wireless or wired)
    """
    __tablename__ = "stalker_tracked_devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String, unique=True, nullable=False, index=True)
    friendly_name = Column(String, nullable=True)
    added_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime, nullable=True)
    current_ap_mac = Column(String, nullable=True)
    current_ap_name = Column(String, nullable=True)
    current_ssid = Column(String, nullable=True)
    current_ip_address = Column(String, nullable=True)
    current_signal_strength = Column(Integer, nullable=True)
    current_radio = Column(String, nullable=True)  # "ng" (2.4GHz), "na" (5GHz), "6e" (6GHz)
    is_connected = Column(Boolean, default=False, nullable=False)
    is_blocked = Column(Boolean, default=False, nullable=False)
    site_id = Column(String, nullable=False)
    # Wired device support
    is_wired = Column(Boolean, default=False, nullable=False)
    current_switch_mac = Column(String, nullable=True)
    current_switch_name = Column(String, nullable=True)
    current_switch_port = Column(Integer, nullable=True)

    # Relationship to connection history
    history = relationship("ConnectionHistory", back_populates="device", cascade="all, delete-orphan")
    # Relationship to hourly presence data
    hourly_presence = relationship("HourlyPresence", back_populates="device", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<TrackedDevice(mac={self.mac_address}, name={self.friendly_name}, connected={self.is_connected})>"


class ConnectionHistory(Base):
    """
    Tracks roaming events - when devices connect/disconnect or move between APs/switches
    """
    __tablename__ = "stalker_connection_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("stalker_tracked_devices.id"), nullable=False, index=True)
    ap_mac = Column(String, nullable=True)
    ap_name = Column(String, nullable=True)
    ssid = Column(String, nullable=True)
    connected_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    disconnected_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    signal_strength = Column(Integer, nullable=True)
    # Wired device support
    is_wired = Column(Boolean, default=False, nullable=False)
    switch_mac = Column(String, nullable=True)
    switch_name = Column(String, nullable=True)
    switch_port = Column(Integer, nullable=True)

    # Relationship to device
    device = relationship("TrackedDevice", back_populates="history")

    def __repr__(self):
        return f"<ConnectionHistory(device_id={self.device_id}, ap={self.ap_name}, connected={self.connected_at})>"


class WebhookConfig(Base):
    """
    Stores webhook configurations for sending device event notifications
    Supports Slack, Discord, and generic/n8n webhooks
    """
    __tablename__ = "stalker_webhook_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    webhook_type = Column(String, nullable=False)  # 'slack', 'discord', 'n8n'
    url = Column(String, nullable=False)

    # Event triggers
    event_device_connected = Column(Boolean, default=True, nullable=False)
    event_device_disconnected = Column(Boolean, default=True, nullable=False)
    event_device_roamed = Column(Boolean, default=True, nullable=False)
    event_device_blocked = Column(Boolean, default=True, nullable=False)
    event_device_unblocked = Column(Boolean, default=True, nullable=False)

    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_triggered = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<WebhookConfig(name={self.name}, type={self.webhook_type}, enabled={self.enabled})>"


class HourlyPresence(Base):
    """
    Aggregated hourly presence data for analytics.
    One row per device per hour of week (168 possible slots: 24 hours × 7 days).
    Used for presence pattern heat maps.
    """
    __tablename__ = "stalker_hourly_presence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("stalker_tracked_devices.id"), nullable=False, index=True)
    day_of_week = Column(Integer, nullable=False)  # 0=Monday, 6=Sunday
    hour_of_day = Column(Integer, nullable=False)  # 0-23

    # Aggregated stats (updated hourly)
    total_minutes_connected = Column(Integer, default=0, nullable=False)
    sample_count = Column(Integer, default=0, nullable=False)  # Number of times this hour slot was sampled
    last_updated = Column(DateTime, nullable=True)

    # Unique constraint: one row per device per hour-slot
    __table_args__ = (
        UniqueConstraint('device_id', 'day_of_week', 'hour_of_day', name='uix_device_hour_slot'),
    )

    # Relationship to device
    device = relationship("TrackedDevice", back_populates="hourly_presence")

    def __repr__(self):
        return f"<HourlyPresence(device_id={self.device_id}, day={self.day_of_week}, hour={self.hour_of_day})>"
