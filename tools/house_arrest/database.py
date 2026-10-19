"""
Database models for House Arrest.

Everything else House Arrest knows lives on the controller (the policies ARE
the state). The one exception is the user's list of DNS servers: names,
kinds and admin links the controller has nowhere to keep. A stale row here
can never make the tool claim protection it isn't delivering, because the
DNS Lockdown itself is still read from the firewall rules.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String
from shared.models.base import Base


class DnsServer(Base):
    """One DNS server the user has added on the DNS tab."""
    __tablename__ = "house_arrest_dns_servers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String, nullable=False, unique=True, index=True)
    name = Column(String, nullable=False)
    # "pihole" | "adguard" | "generic". Cosmetic: picks the logo and the
    # default admin link, never changes what rules are written.
    kind = Column(String, nullable=False, default="generic")
    admin_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
