"""
Pydantic models for House Arrest API requests and responses.
"""
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ZoneInfo(BaseModel):
    """A zone-based firewall zone."""
    id: str
    name: str


class NetworkInfo(BaseModel):
    """A configured network (VLAN), as read for the Inspection report."""
    id: Optional[str] = None
    name: str
    vlan: Optional[int] = None
    isolation_enabled: Optional[bool] = None
    mdns_enabled: Optional[bool] = None
    purpose: Optional[str] = None


class ClientInfo(BaseModel):
    """A client the controller knows about, for the device picker."""
    mac: str
    name: str = ""
    ip: Optional[str] = None
    network: Optional[str] = None
    online: bool = False
    fixed_ip: Optional[str] = None
    locally_administered: bool = False


class PolicyHealth(BaseModel):
    """
    Whether a House Arrest policy still matches a real client.

    status: "ok" | "rotated" | "broken". Anything other than "ok" means the
    policy is enforcing nothing and must not be shown as active.
    """
    policy_id: Optional[str] = None
    name: Optional[str] = None
    macs: List[str] = Field(default_factory=list)
    status: str
    missing: List[str] = Field(default_factory=list)
    suggestion: Optional[str] = None


class BlockedFlow(BaseModel):
    """One piece of traffic the gateway stopped, attributed to our policy."""
    time_ms: Optional[int] = None
    destination: str = "unknown"
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    count: int = 1
    policy: Optional[str] = None
    network: Optional[str] = None
    direction: Optional[str] = None


class ArrestSummary(BaseModel):
    """One locked-down device, assembled from the policies targeting it."""
    label: str
    macs: List[str] = Field(default_factory=list)
    preset: Optional[str] = None
    policy_ids: List[str] = Field(default_factory=list)
    status: str = "ok"
    suggestion: Optional[str] = None
    # Attempts this lockdown actually stopped in the last 24h. Proof that the
    # rule is doing something, rather than merely existing.
    blocked_count: int = 0


class PrecedenceWarning(BaseModel):
    """
    A custom ALLOW policy that evaluates before one of our BLOCK policies and
    could therefore override a lockdown.
    """
    policy_id: Optional[str] = None
    name: Optional[str] = None
    index: Optional[int] = None
    blocks_at: Optional[int] = None


class StateResponse(BaseModel):
    """Everything the dashboard needs in one call."""
    connected: bool
    error: Optional[str] = None
    zones: List[ZoneInfo] = Field(default_factory=list)
    internal_zone_id: Optional[str] = None
    external_zone_id: Optional[str] = None
    arrests: List[ArrestSummary] = Field(default_factory=list)
    health: List[PolicyHealth] = Field(default_factory=list)
    custom_policy_count: int = 0
    total_policy_count: int = 0
    precedence_warnings: List[PrecedenceWarning] = Field(default_factory=list)


class InspectionFinding(BaseModel):
    """One line of the Inspection report."""
    severity: str  # "info" | "warn"
    network: str
    finding: str
    detail: Optional[str] = None


class InspectionResponse(BaseModel):
    connected: bool
    error: Optional[str] = None
    networks: List[NetworkInfo] = Field(default_factory=list)
    findings: List[InspectionFinding] = Field(default_factory=list)
    allow_all_index: Optional[int] = None


class LockdownRequest(BaseModel):
    """Apply a lockdown preset to one or more devices."""
    preset: str
    macs: List[str]
    label: str = ""
    # Required for presets that move the device (Quarantine). The target is an
    # existing network's `_id`; House Arrest never creates a VLAN.
    network_id: Optional[str] = None
    dry_run: bool = True


class LockdownResponse(BaseModel):
    dry_run: bool
    created: List[Dict] = Field(default_factory=list)
    payloads: List[Dict] = Field(default_factory=list)
    # Set when the preset also moves the device into another VLAN.
    moved_to: Optional[str] = None
    error: Optional[str] = None


class ReleaseRequest(BaseModel):
    """Remove House Arrest policies. Only ever touches marked policies."""
    policy_ids: List[str] = Field(default_factory=list)
    label: Optional[str] = None
    dry_run: bool = True


class ReleaseResponse(BaseModel):
    dry_run: bool
    deleted: List[str] = Field(default_factory=list)
    would_delete: List[Dict] = Field(default_factory=list)
    refused: List[Dict] = Field(default_factory=list)
    error: Optional[str] = None


class SystemStatus(BaseModel):
    version: str
    connected: bool
    arrests_active: int = 0
    policies_broken: int = 0
