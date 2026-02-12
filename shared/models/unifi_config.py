"""
UniFi Controller configuration model (shared across all tools)
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, Integer, String, DateTime, LargeBinary, CheckConstraint
from shared.models.base import Base


class UniFiConfig(Base):
    """
    Stores UniFi controller configuration (single row)
    Supports both legacy (username/password) and UniFi OS (API key) authentication
    """
    __tablename__ = "unifi_config"
    __table_args__ = (CheckConstraint("id = 1", name="single_row_check"),)

    id = Column(Integer, primary_key=True)
    controller_url = Column(String, nullable=False)

    # Legacy auth (optional if using API key)
    username = Column(String, nullable=True)
    password_encrypted = Column(LargeBinary, nullable=True)

    # UniFi OS auth (optional if using username/password)
    api_key_encrypted = Column(LargeBinary, nullable=True)

    site_id = Column(String, default="default", nullable=False)
    verify_ssl = Column(Boolean, default=False, nullable=False)
    is_unifi_os = Column(Boolean, default=False, nullable=False)  # True for UDM/UDR/UCG/UX devices
    last_successful_connection = Column(DateTime, nullable=True)

    def __repr__(self):
        auth_type = "API Key" if self.api_key_encrypted else "Username/Password"
        return f"<UniFiConfig(url={self.controller_url}, site={self.site_id}, auth={auth_type})>"
