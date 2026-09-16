"""
House Arrest policy builder.

Pure functions — no network calls, no I/O. Everything here turns a lockdown
request into UniFi zone-based firewall policy payloads, so the payload shapes
can be tested without touching a live console.

Payload shape is mirrored from a policy created by hand in the UniFi UI and
read back from the v2 API (see docs/house-arrest-design.md).

Two rules this module exists to enforce:

  1. Every policy we create carries MARKER in its description. Revert deletes
     exactly the policies carrying it and nothing else.
  2. We never emit a policy with `predefined: True`, and callers must never
     delete one.
"""
from typing import Dict, List, Optional

# Marker lives in `description`, not `name` — users rename things.
MARKER = "[HouseArrest]"

# Custom policies must evaluate before the predefined allow-all, which sits at
# index 2147483647. Anything at/above BASE_INDEX does.
BASE_INDEX = 10000
PREDEFINED_ALLOW_ALL_INDEX = 2147483647

# Presets
FULL_LOCKDOWN = "full_lockdown"
INTERNET_ONLY = "internet_only"
LAN_ONLY = "lan_only"
QUARANTINE = "quarantine"

PRESETS = (FULL_LOCKDOWN, INTERNET_ONLY, LAN_ONLY, QUARANTINE)

PRESET_LABELS = {
    FULL_LOCKDOWN: "Full lockdown",
    INTERNET_ONLY: "Internet only",
    LAN_ONLY: "LAN only",
    QUARANTINE: "Quarantine + VLAN move",
}

# What each preset actually does to the three traffic paths a device has.
#
# This is the source of truth the UI renders from, rather than hand-written
# copy in the template — if a preset changes here, the interface cannot go on
# describing the old behaviour.
#
# Same-VLAN traffic never reaches the GATEWAY, so no zone-based firewall policy
# can touch it — and House Arrest only writes firewall policies, so `peers` is
# never "block" here. Note the precise scope: UniFi *can* block same-VLAN peers
# via switch-level Device Isolation (ACL) or per-SSID Client Isolation. Those
# are per-network/per-SSID toggles affecting every device on that network, not
# per-client, so they are out of scope for a per-device tool — but the UI must
# not claim the traffic is unblockable in general.
#
# Quarantine is "moved": relocating the device changes WHICH peers it has, it
# does not cut peer traffic. Claiming otherwise would be the exact lie this
# tool exists to avoid.
PRESET_EFFECTS = {
    FULL_LOCKDOWN: {
        "internet": "block",
        "networks": "block",
        "peers": "allow",
        "summary": "Cut off from the internet and every other network.",
    },
    INTERNET_ONLY: {
        "internet": "allow",
        "networks": "block",
        "peers": "allow",
        "summary": "Can reach the internet, nothing else on your network.",
    },
    LAN_ONLY: {
        "internet": "block",
        "networks": "allow",
        "peers": "allow",
        "summary": "Can reach local devices, but never phones home.",
    },
    QUARANTINE: {
        "internet": "block",
        "networks": "block",
        "peers": "moved",
        "summary": "Full lockdown, plus moved into a VLAN you pick.",
        "requires_network": True,
    },
}

# Paths that survive a lockdown, measured against a real device on 2026-09-15.
# Both are consequences of where the firewall can and cannot act, not bugs —
# but a tool that says "cut off from the internet" while name resolution still
# works upstream has to say so out loud.
LOCKDOWN_CAVEATS = [
    "Connections already open keep running. Measured: a download in progress "
    "continued after the lockdown was applied, while new connections failed "
    "immediately. The gateway's connection tracking lets established sessions "
    "finish, so a streaming device won't stop mid-stream — reconnect it, or "
    "wait for the session to end.",
    "Your gateway stays reachable — DHCP and the gateway's own services are "
    "not blocked, so the device keeps its address and stays on the network.",
    "DNS keeps working if your resolver is on the device's own VLAN. Verified "
    "on a locked-down device: names still resolved through a same-VLAN "
    "resolver, which forwards upstream — so a determined device still has a "
    "path out over DNS.",
]


def caveats_for(preset: str) -> List[str]:
    """
    Caveats worth showing for a preset. Only presets that claim to cut
    internet access need them; the others don't make that claim.
    """
    effects = PRESET_EFFECTS.get(preset, {})
    if effects.get("internet") == "block":
        return list(LOCKDOWN_CAVEATS)
    return []


def requires_network(preset: str) -> bool:
    """True if the preset cannot be applied without a target network."""
    return bool(PRESET_EFFECTS.get(preset, {}).get("requires_network"))


PATH_LABELS = {
    "internet": "The internet",
    "networks": "Your other networks",
    "peers": "Devices on its own VLAN",
    "inbound": "You reaching in to it",
}


def preset_catalog() -> List[Dict]:
    """
    Presets as the UI should render them: value, label, effects, policy count.
    """
    return [
        {
            "value": value,
            "label": PRESET_LABELS[value],
            "effects": PRESET_EFFECTS[value],
            "policy_count": policy_count(value),
            "requires_network": requires_network(value),
            "caveats": caveats_for(value),
        }
        for value in PRESETS
    ]


# ----------------------------------------------------------------------
# Network-scoped isolation
#
# CORRECTED 2026-09-16. This was first built as marked firewall policies with
# a NETWORK source, to preserve the "release deletes exactly what we created"
# guarantee. That was the wrong call, for two measured reasons:
#
#   1. UniFi's own "Isolate Network" checkbox generates three predefined BLOCK
#      policies — one per destination zone (Internal, Hotspot, DMZ), matching
#      the network by subnet. Our version only covered Internal, so it was
#      strictly less complete.
#   2. The checkbox sets `network_isolation_enabled` on the network. Our
#      policies did not, so the tool's own matrix read "isolation: Off" for a
#      network it had just isolated. The tool contradicted itself.
#
# So network isolation now uses the native flags. The revert story turns out
# to be clean without any stored state, because we only ever act in one
# direction: if a flag is already at the target value we do nothing and say
# so, otherwise we flip it and release flips it back. There is no case where
# release guesses at a previous value.
# ----------------------------------------------------------------------

# Native per-network flags, and the value each preset needs them at.
NET_FLAG_ISOLATION = "network_isolation_enabled"
NET_FLAG_INTERNET = "internet_access_enabled"


def network_flags_for(preset: str) -> Dict[str, bool]:
    """The native network flags a preset needs, as {field: desired value}."""
    if preset == NET_ISOLATE_NETWORKS:
        return {NET_FLAG_ISOLATION: True}
    if preset == NET_NO_INTERNET:
        return {NET_FLAG_INTERNET: False}
    if preset == NET_FULL:
        return {NET_FLAG_ISOLATION: True, NET_FLAG_INTERNET: False}
    raise ValueError(f"Unknown network preset: {preset!r}")


def network_flags_to_release() -> Dict[str, bool]:
    """Undoing isolation: back to reachable, with internet."""
    return {NET_FLAG_ISOLATION: False, NET_FLAG_INTERNET: True}


def network_changes_needed(network: Dict, preset: str) -> Dict[str, bool]:
    """
    Only the flags that actually need changing.

    A flag already at the target value is left alone and reported as such, so
    releasing never switches off something the user had set themselves.
    """
    wanted = network_flags_for(preset)
    return {
        k: v for k, v in wanted.items()
        if bool((network or {}).get(k)) != bool(v)
    }

NETWORK_MARKER = "[Network]"

NET_ISOLATE_NETWORKS = "isolate_networks"
NET_NO_INTERNET = "no_internet"
NET_FULL = "full_isolation"

NETWORK_PRESETS = (NET_ISOLATE_NETWORKS, NET_NO_INTERNET, NET_FULL)

NETWORK_PRESET_LABELS = {
    NET_ISOLATE_NETWORKS: "Isolate from other networks",
    NET_NO_INTERNET: "No internet",
    NET_FULL: "Full isolation",
}

NETWORK_PRESET_EFFECTS = {
    NET_ISOLATE_NETWORKS: {
        "internet": "allow", "networks": "block", "peers": "allow",
        "summary": "Devices here keep internet access but can't reach your "
                   "other networks.",
    },
    NET_NO_INTERNET: {
        "internet": "block", "networks": "allow", "peers": "allow",
        "summary": "Local-only. Nothing here can phone home.",
    },
    NET_FULL: {
        "internet": "block", "networks": "block", "peers": "allow",
        "summary": "Cut off from the internet and every other network.",
    },
}


def network_preset_catalog() -> List[Dict]:
    return [
        {
            "value": v,
            "label": NETWORK_PRESET_LABELS[v],
            "effects": NETWORK_PRESET_EFFECTS[v],
            "policy_count": network_policy_count(v),
            "caveats": caveats_for_network(v),
        }
        for v in NETWORK_PRESETS
    ]


def caveats_for_network(preset: str) -> List[str]:
    """
    Network isolation carries the same measured caveats as a device lockdown,
    plus the one that only applies at network scope.
    """
    base = []
    if NETWORK_PRESET_EFFECTS.get(preset, {}).get("internet") == "block":
        base = list(LOCKDOWN_CAVEATS)
    base.append(
        "Devices on this network can still talk to each other. That traffic "
        "never passes the gateway, so no firewall policy reaches it — use the "
        "network's own Device Isolation setting in UniFi if you need that too."
    )
    return base


def network_policy_count(preset: str) -> int:
    if preset == NET_FULL:
        return 2
    if preset in (NET_ISOLATE_NETWORKS, NET_NO_INTERNET):
        return 1
    raise ValueError(f"Unknown network preset: {preset!r}")


def describe_network(note: str) -> str:
    """
    Tagged description for a network-scoped policy.

    Retained only so leftover policies from the previous implementation can
    still be recognised and removed. Network isolation no longer writes
    policies — it uses UniFi's native per-network flags.
    """
    return f"{MARKER}{NETWORK_MARKER} {note}".strip()


def is_network_policy(policy: Dict) -> bool:
    """True for a House Arrest policy that isolates a network, not a device."""
    if not is_house_arrest(policy):
        return False
    return NETWORK_MARKER in (policy.get("description") or "")


def network_label_from_policy(policy: Dict) -> str:
    """Recover the network name from a network-scoped policy's description."""
    desc = (policy.get("description") or "")
    desc = desc.replace(MARKER, "").replace(NETWORK_MARKER, "").strip()
    if " for " in desc:
        return desc.rsplit(" for ", 1)[1].strip()
    return ""


def normalize_mac(mac: str) -> str:
    """Lowercase, colon-separated. Raises ValueError on anything else."""
    if not mac:
        raise ValueError("MAC address is required")
    cleaned = mac.strip().lower().replace("-", ":")
    parts = cleaned.split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        raise ValueError(f"Not a MAC address: {mac!r}")
    for p in parts:
        int(p, 16)  # raises ValueError on non-hex
    return cleaned


def is_locally_administered(mac: str) -> bool:
    """
    True if the locally-administered bit is set.

    This is a soft note only. It does NOT mean the address rotates — static
    hand-set MACs on VMs and containers set the same bit. Rotation is detected
    at runtime by watching for the MAC leaving the client list, never predicted
    from this bit. See design decision 2.
    """
    try:
        return bool(int(normalize_mac(mac).split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def describe(note: str) -> str:
    """Build a tagged description. Always used for policies we create."""
    return f"{MARKER} {note}".strip()


def is_house_arrest(policy: Dict) -> bool:
    """
    True only for a custom policy carrying our marker.

    Deliberately strict: a predefined policy is never ours, no matter what its
    description says.
    """
    if not isinstance(policy, dict):
        return False
    if policy.get("predefined"):
        return False
    return MARKER in (policy.get("description") or "")


def next_free_index(existing: List[Dict], count: int = 1) -> List[int]:
    """
    Pick `count` policy indexes that are free and evaluate before the
    predefined allow-all.

    NOTE (measured 2026-09-15): the controller does not honour these. Indexes
    sent as 10004/10005 came back stored as 10000/10003, colliding with an
    existing custom rule. The value is still sent because the API requires the
    field and the result reliably lands well below the predefined allow-all,
    but it is a request, not a placement. Use check_precedence() on the
    stored policies to find out where they actually ended up.

    Args:
        existing: all policies currently on the console
        count: how many indexes are needed

    Returns:
        A list of `count` unused indexes, ascending, starting at BASE_INDEX.
    """
    if count < 1:
        return []
    used = set()
    for p in existing or []:
        idx = p.get("index")
        if isinstance(idx, int):
            used.add(idx)

    free = []
    candidate = BASE_INDEX
    while len(free) < count:
        if candidate not in used and candidate < PREDEFINED_ALLOW_ALL_INDEX:
            free.append(candidate)
        candidate += 1
    return free


def _base_policy(
    name: str,
    action: str,
    index: int,
    source: Dict,
    destination: Dict,
    description: str,
    enabled: bool = True,
    allow_respond: bool = False,
) -> Dict:
    """
    The common envelope, mirrored from a UI-created policy read back from v2.
    """
    return {
        "action": action,
        "connection_state_type": "ALL",
        "connection_states": [],
        "create_allow_respond": allow_respond,
        "description": description,
        "destination": destination,
        "enabled": enabled,
        "icmp_typename": "ANY",
        "icmp_v6_typename": "ANY",
        "index": index,
        "ip_version": "BOTH",
        "logging": False,
        "match_ip_sec": False,
        "match_opposite_protocol": False,
        "name": name,
        "predefined": False,
        "protocol": "all",
        "schedule": {"mode": "ALWAYS"},
        "source": source,
    }


def client_source(macs: List[str], zone_id: str) -> Dict:
    """
    Source block matching specific clients by MAC.

    `client_macs` is an array, so one policy can cover several devices — this
    is why a locked-down device needs no DHCP reservation.
    """
    if not macs:
        raise ValueError("At least one MAC is required")
    if not zone_id:
        raise ValueError("zone_id is required")
    return {
        "matching_target": "CLIENT",
        "client_macs": [normalize_mac(m) for m in macs],
        "match_opposite_ports": False,
        "port_matching_type": "ANY",
        "zone_id": zone_id,
    }


def zone_destination(zone_id: str) -> Dict:
    """Destination block matching everything in a zone."""
    if not zone_id:
        raise ValueError("zone_id is required")
    return {
        "matching_target": "ANY",
        "match_opposite_ports": False,
        "port_matching_type": "ANY",
        "zone_id": zone_id,
    }


def ip_destination(
    ips: List[str],
    zone_id: str,
    port: Optional[str] = None,
) -> Dict:
    """
    Destination block matching specific IPs, optionally on one port.

    IP is the only way to name a device as a destination — the API has no
    CLIENT option on this side. That is why inbound exceptions need a DHCP
    reservation on the target.
    """
    if not ips:
        raise ValueError("At least one IP is required")
    if not zone_id:
        raise ValueError("zone_id is required")
    dest = {
        "matching_target": "IP",
        "matching_target_type": "SPECIFIC",
        "ips": list(ips),
        "match_opposite_ips": False,
        "match_opposite_ports": False,
        "zone_id": zone_id,
    }
    if port:
        dest["port"] = str(port)
        dest["port_matching_type"] = "SPECIFIC"
    else:
        dest["port_matching_type"] = "ANY"
    return dest


def build_lockdown(
    preset: str,
    macs: List[str],
    device_label: str,
    client_zone_id: str,
    external_zone_id: str,
    indexes: List[int],
    allow_inbound: bool = True,
) -> List[Dict]:
    """
    Build the policy set for a lockdown preset.

    Args:
        preset: one of PRESETS
        macs: MACs of the devices to lock down (policy source)
        device_label: human name used in policy names, e.g. "Front Door Cam"
        client_zone_id: zone the device sits in (usually Internal)
        external_zone_id: the WAN/External zone
        indexes: pre-allocated free indexes, from next_free_index()
        allow_inbound: keep the device reachable FROM your other networks.

    On `allow_inbound` (default True):

    A BLOCK policy stops traffic in the direction it matches. Because the
    locked-down device is the SOURCE, a block with no reply handling also kills
    the replies to connections someone else started — so you would lose the
    ability to reach the device yourself, from another VLAN, without any
    warning that it had happened.

    `create_allow_respond` is how UniFi expresses "block this direction but let
    replies through", and UniFi's own Isolate Network setting sets it (measured
    2026-09-16: its generated rules carry create_allow_respond=true). Matching
    that is both the safer default and the one that fits the name: a device
    under house arrest cannot go out, but you can still visit it.

    Set it False for absolute isolation, where nothing may cross in either
    direction.

    Returns:
        List of policy payloads, ready to POST.
    """
    if preset not in PRESETS:
        raise ValueError(f"Unknown preset: {preset!r}")

    src = client_source(macs, client_zone_id)
    label = device_label or "device"
    needed = policy_count(preset)
    if len(indexes) < needed:
        raise ValueError(
            f"Preset {preset!r} needs {needed} indexes, got {len(indexes)}"
        )

    block_internet = _base_policy(
        name=f"House Arrest: {label} — no internet",
        action="BLOCK",
        index=indexes[0],
        source=src,
        destination=zone_destination(external_zone_id),
        description=describe(f"{PRESET_LABELS[preset]} for {label}"),
        allow_respond=allow_inbound,
    )
    block_lan = _base_policy(
        name=f"House Arrest: {label} — no LAN",
        action="BLOCK",
        index=indexes[-1],
        source=src,
        destination=zone_destination(client_zone_id),
        description=describe(f"{PRESET_LABELS[preset]} for {label}"),
        allow_respond=allow_inbound,
    )

    if preset in (FULL_LOCKDOWN, QUARANTINE):
        return [block_internet, block_lan]
    if preset == INTERNET_ONLY:
        return [block_lan]
    if preset == LAN_ONLY:
        return [block_internet]
    raise ValueError(f"Unhandled preset: {preset!r}")  # pragma: no cover


def policy_count(preset: str) -> int:
    """How many policies a preset writes. Used to pre-allocate indexes."""
    if preset in (FULL_LOCKDOWN, QUARANTINE):
        return 2
    if preset in (INTERNET_ONLY, LAN_ONLY):
        return 1
    raise ValueError(f"Unknown preset: {preset!r}")


def build_exception(
    macs: List[str],
    device_label: str,
    client_zone_id: str,
    dest_ips: List[str],
    dest_zone_id: str,
    index: int,
    port: Optional[str] = None,
    note: str = "",
) -> Dict:
    """
    Build an ALLOW policy carving a hole in a lockdown.

    `create_allow_respond` is set so the reply path works without opening the
    reverse direction as its own initiation.
    """
    label = device_label or "device"
    where = note or (dest_ips[0] if dest_ips else "exception")
    return _base_policy(
        name=f"House Arrest: {label} — allow {where}",
        action="ALLOW",
        index=index,
        source=client_source(macs, client_zone_id),
        destination=ip_destination(dest_ips, dest_zone_id, port=port),
        description=describe(f"Exception for {label}: {where}"),
        allow_respond=True,
    )


def build_inbound_exception(
    device_ips: List[str],
    device_label: str,
    device_zone_id: str,
    source_zone_id: str,
    index: int,
    port: Optional[str] = None,
    note: str = "",
) -> Dict:
    """
    Build an ALLOW policy letting the LAN reach a locked-down device.

    The device is the DESTINATION here, which the API can only express as an
    IP — so the caller must ensure the device holds a DHCP reservation. A
    reservation is keyed on MAC, so this is only reliable for devices with a
    burned-in vendor MAC (cameras, printers, NAS). Do not offer this for a
    device whose MAC is locally administered without warning first.
    """
    label = device_label or "device"
    where = note or "LAN access"
    return _base_policy(
        name=f"House Arrest: {label} — allow {where} inbound",
        action="ALLOW",
        index=index,
        source=zone_destination(source_zone_id),
        destination=ip_destination(device_ips, device_zone_id, port=port),
        description=describe(f"Inbound exception for {label}: {where}"),
        allow_respond=True,
    )


def find_ours(policies: List[Dict]) -> List[Dict]:
    """Filter a policy list down to the ones House Arrest created."""
    return [p for p in policies or [] if is_house_arrest(p)]


def summarize_blocked(flows: List[Dict], our_policy_ids: set) -> List[Dict]:
    """
    Reduce raw blocked traffic flows to what a person needs to see.

    Only flows attributed to one of OUR policies are kept. Attribution is by
    policy `id`, not name: a user can rename a policy in the UniFi UI, and
    counting someone else's block as proof that House Arrest is working would
    be the same class of lie as showing a dead rule as green.

    Returns:
        Newest first, each: time_ms, destination, port, protocol, count,
        policy (name), network (destination network), direction.
    """
    out = []
    for f in flows or []:
        attributed = [
            p for p in (f.get("policies") or [])
            if p.get("id") in our_policy_ids
        ]
        if not attributed:
            continue

        dest = f.get("destination") or {}
        # Prefer a name a human recognises over a bare IP.
        target = (
            dest.get("client_name")
            or dest.get("host_name")
            or (dest.get("domains") or [None])[0]
            or dest.get("ip")
            or "unknown"
        )
        out.append({
            "time_ms": f.get("time") or f.get("flow_start_time"),
            "destination": target,
            "destination_ip": dest.get("ip"),
            "port": dest.get("port"),
            "protocol": f.get("protocol"),
            "count": f.get("count") or 1,
            "policy": attributed[0].get("name"),
            "network": dest.get("network_name"),
            "direction": f.get("direction"),
        })

    out.sort(key=lambda x: x.get("time_ms") or 0, reverse=True)
    return out


def blocked_counts_by_label(
    flows: List[Dict], policy_id_to_label: Dict[str, str]
) -> Dict[str, int]:
    """
    Total blocked attempts per locked-down device.

    Counts the flow's own `count` field, not the number of flow records — one
    record can represent several attempts.
    """
    totals: Dict[str, int] = {}
    for f in flows or []:
        for p in f.get("policies") or []:
            label = policy_id_to_label.get(p.get("id"))
            if label:
                totals[label] = totals.get(label, 0) + (f.get("count") or 1)
                break
    return totals


MATRIX_COLUMNS = [
    {"key": "zone", "label": "Zone",
     "help": "Networks in the same zone reach each other by default."},
    {"key": "isolation", "label": "Network isolation",
     "help": "Blocks this network from reaching your other networks."},
    {"key": "internet", "label": "Internet access",
     "help": "Whether devices here can reach the internet at all."},
    {"key": "mdns", "label": "mDNS forwarding",
     "help": "Lets service discovery (casting, AirPlay) cross this boundary."},
    {"key": "dns", "label": "DNS handed out",
     "help": "Which resolver DHCP gives devices here. A resolver on this same "
             "network cannot be filtered by the gateway."},
    {"key": "upnp", "label": "UPnP",
     "help": "Lets devices here open ports on the gateway by themselves."},
]


def _cell(state: str, label: str, detail: str) -> Dict:
    return {"state": state, "label": label, "detail": detail}


def _ip_in_subnet(ip: Optional[str], subnet: Optional[str]) -> bool:
    """
    Is this IP inside this network's own subnet?

    UniFi reports `ip_subnet` as the gateway address with a prefix
    ("192.168.200.1/24"), not the network address, so it is parsed with
    strict=False. Returns False on anything unparseable rather than raising —
    an unknown answer must not be reported as a hole.
    """
    if not ip or not subnet:
        return False
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


def build_isolation_matrix(
    networks: List[Dict], zones: List[Dict]
) -> Dict:
    """
    Build the network-by-attribute isolation matrix.

    One row per LAN, one column per security-relevant setting. Each cell
    carries its own explanation, so the raw API field name lives in the hover
    detail rather than in the table body.

    Deliberately reports what is actually set rather than what is implied: a
    VLAN existing is not isolation, and an unset flag is reported as off, not
    as unknown-therefore-fine.
    """
    zone_of = {}
    zone_members: Dict[str, List[str]] = {}
    for z in zones or []:
        zname = z.get("name") or "(zone)"
        for nid in z.get("network_ids") or []:
            zone_of[nid] = zname
            zone_members.setdefault(zname, []).append(nid)

    rows = []
    for n in networks or []:
        if n.get("purpose") == "wan":
            continue
        nid = n.get("_id")
        name = n.get("name") or "(unnamed)"
        vlan = n.get("vlan")
        zname = zone_of.get(nid)

        cells = {}

        # Zone
        siblings = [
            m for m in zone_members.get(zname, [])
            if m != nid and m in {x.get("_id") for x in networks
                                  if x.get("purpose") != "wan"}
        ]
        if zname:
            cells["zone"] = _cell(
                "warn" if siblings else "good",
                zname,
                f"{name} is in the {zname} zone with {len(siblings)} other "
                f"network(s). Traffic inside a zone is allowed unless a policy "
                f"blocks it, so these can reach each other by default."
                if siblings else
                f"{name} is alone in the {zname} zone, so nothing else shares "
                f"its default-allow boundary."
            )
        else:
            cells["zone"] = _cell("neutral", "—", "No zone membership reported.")

        # Network isolation
        iso = n.get("network_isolation_enabled")
        cells["isolation"] = _cell(
            "good" if iso else "warn",
            "On" if iso else "Off",
            f"VLAN {vlan} has network_isolation_enabled={iso!r}. "
            + ("Devices here are blocked from reaching your other networks."
               if iso else
               "Devices here can reach other networks unless a firewall policy "
               "stops them.")
        )

        # Internet access
        inet = n.get("internet_access_enabled")
        cells["internet"] = _cell(
            "warn" if inet is not False else "good",
            "Allowed" if inet is not False else "Blocked",
            f"internet_access_enabled={inet!r}. "
            + ("Devices here can reach the internet."
               if inet is not False else
               "Devices here have no internet access at the network level.")
        )

        # mDNS
        mdns = n.get("mdns_enabled")
        cells["mdns"] = _cell(
            "warn" if mdns else "good",
            "On" if mdns else "Off",
            f"mdns_enabled={mdns!r}. "
            + ("Service discovery crosses this boundary. Often wanted for "
               "casting, but it does advertise what lives here."
               if mdns else
               "Service discovery does not cross this boundary.")
        )

        # DNS handed out by DHCP.
        #
        # The distinction that matters is not "custom vs default" but whether
        # the resolver sits INSIDE this network. A resolver on the same subnet
        # is reached without passing the gateway, so no firewall policy can
        # filter it — that is the measured hole (a locked-down device still
        # resolved names through a same-subnet resolver). A resolver on another
        # VLAN crosses the gateway and therefore can be filtered.
        servers = [n.get(f"dhcpd_dns_{i}") for i in (1, 2, 3, 4)]
        servers = [x for x in servers if x]
        local = [x for x in servers if _ip_in_subnet(x, n.get("ip_subnet"))]

        if local:
            cells["dns"] = _cell(
                "warn", ", ".join(servers),
                f"{', '.join(local)} "
                + ("is" if len(local) == 1 else "are")
                + f" on this network's own subnet. Queries to "
                + ("it" if len(local) == 1 else "them")
                + " never pass the gateway, so no firewall policy can filter "
                  "them — a device locked down here can still resolve names, "
                  "and the resolver forwards upstream. Measured on a real "
                  "locked-down device."
            )
        elif servers:
            cells["dns"] = _cell(
                "neutral", ", ".join(servers),
                f"DHCP hands out {', '.join(servers)}, which "
                + ("is" if len(servers) == 1 else "are")
                + " outside this network. Those queries cross the gateway, so "
                  "a lockdown here can filter them."
            )
        else:
            cells["dns"] = _cell(
                "good", "Gateway",
                "Devices here use the gateway as resolver, so DNS can be "
                "controlled at the gateway."
            )

        # UPnP
        upnp = n.get("upnp_lan_enabled")
        cells["upnp"] = _cell(
            "warn" if upnp else "good",
            "On" if upnp else "Off",
            f"upnp_lan_enabled={upnp!r}. "
            + ("Devices here can open inbound ports on the gateway without "
               "asking you." if upnp else
               "Devices here cannot open their own inbound ports.")
        )

        rows.append({
            "id": nid, "name": name, "vlan": vlan,
            "purpose": n.get("purpose"), "cells": cells,
        })

    rows.sort(key=lambda r: (r["vlan"] is None, r["vlan"] or 0))
    return {"columns": list(MATRIX_COLUMNS), "rows": rows}


def check_precedence(ours: List[Dict], all_policies: List[Dict]) -> List[Dict]:
    """
    Find custom ALLOW policies that evaluate BEFORE one of our BLOCK policies.

    Measured 2026-09-15: the controller assigns the stored `index` itself and
    ignores the one we send — two policies created with 10004/10005 came back
    as 10000/10003, colliding with an existing rule. So House Arrest cannot
    place its rules at a chosen position, and a user's own ALLOW sitting at a
    lower index can override a lockdown.

    Lower index evaluates first (the predefined allow-all is last, at
    2147483647), so an ALLOW at or below our lowest BLOCK is a possible
    override. This is deliberately a conservative flag — it does not try to
    prove the ALLOW actually matches the locked-down device, only that it
    would be consulted first, which is the part the user needs to know.

    Returns:
        One dict per suspect ALLOW: policy_id, name, index, blocks_at.
    """
    block_indexes = [
        p.get("index") for p in ours or []
        if p.get("action") == "BLOCK" and isinstance(p.get("index"), int)
    ]
    if not block_indexes:
        return []
    lowest_block = min(block_indexes)

    our_ids = {p.get("_id") for p in ours or []}
    warnings = []
    for p in all_policies or []:
        if p.get("predefined") or p.get("_id") in our_ids:
            continue
        if p.get("action") != "ALLOW" or not p.get("enabled", True):
            continue
        idx = p.get("index")
        if isinstance(idx, int) and idx <= lowest_block:
            warnings.append({
                "policy_id": p.get("_id"),
                "name": p.get("name"),
                "index": idx,
                "blocks_at": lowest_block,
            })
    return warnings


def preset_from_policy(policy: Dict) -> Optional[str]:
    """
    Recover which preset created a policy, from the label we wrote into its
    description ("[HouseArrest] <preset label> for <device>").

    Release needs this: a quarantined device also has a VLAN override on its
    client record, and deleting the policies without clearing that override
    would leave the device stranded in the quarantine network.
    """
    desc = (policy or {}).get("description") or ""
    if MARKER not in desc:
        return None
    body = desc.replace(MARKER, "").strip()
    for value, label in PRESET_LABELS.items():
        if body.startswith(label):
            return value
    return None


def policy_macs(policy: Dict) -> List[str]:
    """The MACs a policy targets, or [] if it isn't client-matched."""
    src = (policy or {}).get("source") or {}
    if src.get("matching_target") != "CLIENT":
        return []
    return [m.lower() for m in src.get("client_macs") or []]


# Policy health states
OK = "ok"
BROKEN = "broken"
ROTATED = "rotated"


def check_breakage(ours: List[Dict], known: Dict[str, str]) -> List[Dict]:
    """
    Check whether each House Arrest policy still matches a real client.

    This is design decision 2: we do not predict MAC rotation, we detect that
    a rule has stopped matching. A policy whose MAC has left the client list
    is enforcing nothing, and the UI must not show it as green.

    Args:
        ours: policies carrying our marker
        known: {mac: name} for every client the controller knows about

    Returns:
        One dict per policy: policy_id, name, macs, status, missing, suggestion.
        status is OK, ROTATED (the MAC is gone but a same-named client exists
        on a different MAC — almost certainly the same device), or BROKEN (the
        MAC is gone with no obvious replacement).
    """
    known = {k.lower(): (v or "") for k, v in (known or {}).items()}

    # name -> macs currently known, for the rotation suggestion
    by_name: Dict[str, List[str]] = {}
    for mac, name in known.items():
        if name:
            by_name.setdefault(name.strip().lower(), []).append(mac)

    results = []
    for pol in ours or []:
        macs = policy_macs(pol)
        missing = [m for m in macs if m not in known]
        status = OK if not missing else BROKEN
        suggestion = None

        if missing:
            # Recover the device name from the policy description/name, then
            # look for a client using that name on a different MAC.
            label = _label_from_policy(pol)
            if label:
                candidates = [
                    m for m in by_name.get(label.strip().lower(), [])
                    if m not in macs
                ]
                if candidates:
                    status = ROTATED
                    suggestion = candidates[0]

        results.append({
            "policy_id": pol.get("_id"),
            "name": pol.get("name"),
            "macs": macs,
            "status": status,
            "missing": missing,
            "suggestion": suggestion,
        })
    return results


def _label_from_policy(policy: Dict) -> str:
    """
    Recover the device label from a policy we created.

    Names look like "House Arrest: <label> — <what>". Fall back to the
    description, which reads "[HouseArrest] <preset> for <label>".
    """
    name = policy.get("name") or ""
    if name.startswith("House Arrest:"):
        rest = name.split("House Arrest:", 1)[1]
        return rest.split("—")[0].strip()
    desc = (policy.get("description") or "").replace(MARKER, "").strip()
    if " for " in desc:
        return desc.rsplit(" for ", 1)[1].strip()
    return ""
