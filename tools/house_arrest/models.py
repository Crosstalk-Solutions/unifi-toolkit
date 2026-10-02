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
    # What DHCP hands out on this network. Carried here so the DNS tab can
    # show it beside the resolver picker — deciding which networks to force
    # onto a resolver means knowing what they currently advertise, and that
    # used to require switching tabs.
    dhcp_dns: List[str] = Field(default_factory=list)


class ClientInfo(BaseModel):
    """A client the controller knows about, for the device picker."""
    mac: str
    name: str = ""
    ip: Optional[str] = None
    network: Optional[str] = None
    online: bool = False
    fixed_ip: Optional[str] = None
    locally_administered: bool = False
    # How well switch ACLs could separate this device from its neighbours,
    # shown before the neighbour block is applied. covered|partial|none|unknown.
    neighbour_coverage: Optional[str] = None
    neighbour_coverage_note: Optional[str] = None
    # Same-VLAN DNS servers the neighbour block keeps reachable (or why it can't).
    neighbour_dns_note: Optional[str] = None
    # Network-wide settings on this device's network (Networks tab). These
    # apply whatever the device lockdown says, so the Devices tab reads them
    # to avoid promising access the network has already taken away.
    network_isolated: Optional[bool] = None
    network_internet_off: Optional[bool] = None
    network_device_isolation: Optional[bool] = None
    # Custom ALLOW rules that get through that network's isolation (the
    # Networks tab lists them). >0 means "blocked by its network" is not total.
    network_isolation_exceptions: int = 0
    # Wireless context, so the Devices tab can say when an SSID's Client
    # Isolation already covers the same-VLAN path the diagram shows as open.
    essid: Optional[str] = None
    is_wired: Optional[bool] = None


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
    # How many distinct destination ports were folded into this row, and how
    # many separate flow records. A chatty device hits one peer on dozens of
    # ephemeral ports, which is one fact, not dozens.
    port_count: int = 1
    flow_count: int = 1
    # "connection" = TCP, or UDP aimed at a service port. "return_traffic" =
    # UDP aimed at an ephemeral port, which is the far side of someone else's
    # conversation rather than this device reaching out.
    kind: str = "connection"
    # "ours" = a live House Arrest policy stopped this. "stale" = a policy that
    # carried our name for this device but is no longer on the controller (the
    # leftover of an earlier lockdown). "other" = somebody else's rule.
    attribution: str = "ours"
    protocol: Optional[str] = None
    count: int = 1
    policy: Optional[str] = None
    network: Optional[str] = None
    direction: Optional[str] = None


class ArrestSummary(BaseModel):
    """One locked-down device, assembled from the policies targeting it."""
    label: str
    macs: List[str] = Field(default_factory=list)
    ip: Optional[str] = None
    network: Optional[str] = None
    # "live" (from the current client list) or "observed" (from blocked
    # traffic, when the controller has no current IP for the device).
    location_source: Optional[str] = None
    preset: Optional[str] = None
    policy_ids: List[str] = Field(default_factory=list)
    # "ok" | "rotated" | "broken" | "pending_move"
    status: str = "ok"
    suggestion: Optional[str] = None
    # Attempts this lockdown actually stopped. Proof that the rule is doing
    # something, rather than merely existing. Window is blocked_window_hours.
    blocked_count: int = 0
    blocked_window_hours: int = 24
    # Neighbour block (switch ACL pair): None = not requested, else
    # "ok" | "broken" | "disabled". Coverage is a verdict, not a promise:
    # covered | partial | none | unknown, plus one plain sentence.
    neighbours: Optional[str] = None
    neighbours_coverage: Optional[str] = None
    neighbours_note: Optional[str] = None
    neighbours_dns_note: Optional[str] = None


class PrecedenceWarning(BaseModel):
    """
    A custom ALLOW policy that evaluates before one of our BLOCK policies and
    could therefore override a lockdown.
    """
    policy_id: Optional[str] = None
    name: Optional[str] = None
    index: Optional[int] = None
    blocks_at: Optional[int] = None


class IsolatedNetwork(BaseModel):
    """
    A network isolated via UniFi's own settings.

    Read from the native flags rather than from policies we wrote, so this
    always matches what the UniFi UI shows.
    """
    label: str
    network_id: Optional[str] = None
    preset: Optional[str] = None


class IsolateRequest(BaseModel):
    """Isolate a whole network. Same dry-run-first discipline as a lockdown."""
    preset: str
    network_id: str
    dry_run: bool = True


class IsolateResponse(BaseModel):
    dry_run: bool
    # {field: desired value} — only the settings that actually need changing.
    changes: Dict[str, bool] = Field(default_factory=dict)
    note: Optional[str] = None
    error: Optional[str] = None


class DnsLockdownRequest(BaseModel):
    """Force chosen networks onto approved resolvers only."""
    network_ids: List[str] = Field(default_factory=list)
    resolver_ips: List[str] = Field(default_factory=list)
    block_dot: bool = False
    dry_run: bool = True


class DnsLockdownResponse(BaseModel):
    dry_run: bool
    created: List[Dict] = Field(default_factory=list)
    payloads: List[Dict] = Field(default_factory=list)
    caveats: List[str] = Field(default_factory=list)
    # What applying also did to existing device lockdowns (re-created behind
    # the new allow, or couldn't be). Kept apart from caveats so the page can
    # show it in the result instead of losing it in the preview text.
    notices: List[str] = Field(default_factory=list)
    notices_failed: bool = False
    error: Optional[str] = None


class DnsLockdownEntry(BaseModel):
    """A network currently under DNS lockdown."""
    label: str
    resolvers: List[str] = Field(default_factory=list)
    policy_ids: List[str] = Field(default_factory=list)
    blocks_dot: bool = False
    # Which networks this covers, so the picker can mark them before the user
    # selects one and hits the duplicate guard as an error.
    network_ids: List[str] = Field(default_factory=list)
    # Rules in this set toggled off in the UniFi UI. Anything above zero means
    # the lockdown is NOT fully enforcing and the row must not show green.
    disabled_count: int = 0


class StateResponse(BaseModel):
    """Everything the dashboard needs in one call."""
    connected: bool
    error: Optional[str] = None
    zones: List[ZoneInfo] = Field(default_factory=list)
    internal_zone_id: Optional[str] = None
    external_zone_id: Optional[str] = None
    arrests: List[ArrestSummary] = Field(default_factory=list)
    isolated_networks: List[IsolatedNetwork] = Field(default_factory=list)
    # Policies from the earlier implementation, surfaced for cleanup.
    legacy_network_policies: List[Dict] = Field(default_factory=list)
    dns_lockdowns: List[DnsLockdownEntry] = Field(default_factory=list)
    health: List[PolicyHealth] = Field(default_factory=list)
    custom_policy_count: int = 0
    total_policy_count: int = 0
    precedence_warnings: List[PrecedenceWarning] = Field(default_factory=list)
    # Gateway-level DNS interception (CyberSecure). None = could not read,
    # which the UI must treat as unknown, never as off.
    # Does any switch on the site support switch ACLs? None = could not read.
    # False disables the neighbour block and Device Isolation in the UI.
    switch_acl_supported: Optional[bool] = None
    encrypted_dns_on: Optional[bool] = None
    ad_blocking_on: Optional[bool] = None
    content_filtered_network_ids: List[str] = Field(default_factory=list)


class InspectionFinding(BaseModel):
    """One line of the Inspection report."""
    severity: str  # "info" | "warn"
    network: str
    finding: str
    detail: Optional[str] = None


class MatrixColumn(BaseModel):
    """One attribute column in the isolation matrix."""
    key: str
    label: str
    help: str = ""


class MatrixCell(BaseModel):
    """
    One network/attribute intersection.

    `state` drives the colour: "good" (isolating), "warn" (open), "neutral"
    (informational), "na" (not applicable to this network).
    `detail` is the explanation shown on hover, and is the only place the raw
    API field name appears — the cell itself stays readable.
    """
    state: str = "neutral"
    label: str = "—"
    detail: str = ""
    # Whether this particular cell can be changed from the table. Decided on
    # the server so the UI can never offer a switch the controller will ignore,
    # and so editability can depend on more than the column (site state, the
    # network's own purpose) without the browser having to know any of it.
    editable: bool = False


class MatrixRow(BaseModel):
    id: Optional[str] = None
    name: str
    vlan: Optional[int] = None
    purpose: Optional[str] = None
    cells: Dict[str, MatrixCell] = Field(default_factory=dict)


class IsolationMatrix(BaseModel):
    columns: List[MatrixColumn] = Field(default_factory=list)
    rows: List[MatrixRow] = Field(default_factory=list)


class InspectionResponse(BaseModel):
    connected: bool
    error: Optional[str] = None
    networks: List[NetworkInfo] = Field(default_factory=list)
    findings: List[InspectionFinding] = Field(default_factory=list)
    matrix: Optional[IsolationMatrix] = None
    allow_all_index: Optional[int] = None


class LockdownRequest(BaseModel):
    """Apply a lockdown preset to one or more devices."""
    preset: str
    macs: List[str]
    label: str = ""
    # Required for presets that move the device (Quarantine). The target is an
    # existing network's `_id`; House Arrest never creates a VLAN.
    network_id: Optional[str] = None
    # Keep the device reachable from your other networks. Blocks the device
    # from initiating outward, but lets it answer when you contact it.
    allow_inbound: bool = True
    # Optional per-device switch-ACL pair that also cuts same-network
    # neighbours (Full lockdown / Internet only only). Off by default.
    block_neighbours: bool = False
    dry_run: bool = True


class LockdownResponse(BaseModel):
    dry_run: bool
    created: List[Dict] = Field(default_factory=list)
    payloads: List[Dict] = Field(default_factory=list)
    # Honest scoping notes, e.g. rules scoped to a non-Internal zone, or other
    # LAN zones the blocks do not cover. Shown with the review.
    caveats: List[str] = Field(default_factory=list)
    # Set when the preset also moves the device into another VLAN.
    moved_to: Optional[str] = None
    # Set when the override was saved but the device has not actually moved.
    move_note: Optional[str] = None
    error: Optional[str] = None


class ReleaseRequest(BaseModel):
    """Remove House Arrest policies. Only ever touches marked policies."""
    policy_ids: List[str] = Field(default_factory=list)
    label: Optional[str] = None
    # "device" or "network". A device and a network could share a label, and
    # releasing the wrong one would be a silent surprise.
    kind: Optional[str] = None
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


class NetworkSettingRequest(BaseModel):
    """One boolean network setting, flipped from the inspection matrix."""
    network_id: str
    column: str = Field(..., description="Matrix column key, e.g. 'mdns'")
    value: bool


class DhcpDnsRequest(BaseModel):
    """Point a network's DHCP name servers at the approved resolvers."""
    network_ids: List[str]
    resolver_ips: List[str]
    dry_run: bool = True


class DhcpDnsChange(BaseModel):
    """What one network's DHCP name servers would go from, and to."""
    network_id: str
    label: str
    current: List[str] = []
    proposed: List[str] = []
    applied: bool = False
    error: Optional[str] = None


class DhcpDnsResponse(BaseModel):
    dry_run: bool = True
    changes: List[DhcpDnsChange] = []
    error: Optional[str] = None


class WlanInfo(BaseModel):
    """
    One SSID and whether its clients can reach each other.

    `client_count` is what makes the trade-off concrete: isolation applies to
    every client on the SSID, so the number of devices about to lose local
    connectivity belongs next to the switch.
    """
    id: str
    name: str
    enabled: bool = True
    isolated: bool = False
    client_count: int = 0
    network_id: Optional[str] = None


class WlanIsolationRequest(BaseModel):
    wlan_id: str
    enabled: bool
