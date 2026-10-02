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
from typing import Dict, List, Optional, Tuple

# Marker lives in `description`, not `name` — users rename things.
# Every policy this tool creates is named "House Arrest: <label> — <what>".
# The prefix is a constant because blocked-traffic attribution falls back to
# it when a policy id is no longer on the controller.
NAME_PREFIX = "House Arrest: "

MARKER = "[HouseArrest]"

# Custom policies must evaluate before the predefined allow-all, which sits at
# index 2147483647. Anything at/above BASE_INDEX does.
BASE_INDEX = 10000
PREDEFINED_ALLOW_ALL_INDEX = 2147483647

# Presets
FULL_LOCKDOWN = "full_lockdown"
INTERNET_ONLY = "internet_only"
LAN_ONLY = "lan_only"
# REMOVED from the offered presets 2026-09-17, kept for release-side
# recognition only. Quarantine moved the device via the per-client
# `virtual_network_override`, and on a wired client that mechanism was measured
# to half-apply: the Pi obtained a DHCP lease on the target VLAN, then sat with
# no working L2 at all — ARP to its own gateway and to same-VLAN peers failed
# ("destination host unreachable") — while stat/sta and the UniFi UI reported
# contradictory locations for it. A quarantine whose outcome the platform
# cannot even report coherently cannot be verified, so the tool no longer
# offers it. A device that truly needs quarantining belongs in a dedicated
# VLAN assigned natively in UniFi (switch port network / Wi-Fi network), which
# this tool can then isolate and DNS-lock reliably.
QUARANTINE = "quarantine"

# ADDED 2026-10-02: the complete lockdown, shown to users as "Quarantine".
# Deliberately NOT the "quarantine" key above: that key still means the
# removed VLAN-move preset, and release() clears a VLAN override for it
# (requires_network). Reusing the key would make releasing a new Quarantine
# try to undo a move that never happened.
CUT_OFF = "cut_off"

# The presets the tool OFFERS, in the order the UI shows them: most to least
# permissive (Chris, 2026-10-02). Internet only and LAN only each cut one
# thing; No internet cuts both of theirs; Quarantine cuts everything. Internet
# only leads as the most-used. The legacy
# Quarantine stays out of this tuple but keeps its PRESET_LABELS /
# PRESET_EFFECTS entries so preset_from_policy() still recognises a
# pre-removal quarantine and release still clears its VLAN override instead
# of stranding the device.
PRESETS = (INTERNET_ONLY, LAN_ONLY, FULL_LOCKDOWN, CUT_OFF)

PRESET_LABELS = {
    CUT_OFF: "Quarantine",
    # RENAMED 2026-10-02 from "Full lockdown": next to Quarantine, a "full"
    # lockdown that still lets other devices in was the confusing one. The key
    # is unchanged so existing lockdowns keep working.
    FULL_LOCKDOWN: "No internet",
    INTERNET_ONLY: "Internet only",
    LAN_ONLY: "LAN only",
    QUARANTINE: "Quarantine + VLAN move",
}

# Labels older lockdowns were written with. preset_from_policy() reads the
# label back out of a policy's description, so a lockdown created before a
# rename must still be recognised (and released) under its old name.
LEGACY_PRESET_LABELS = {
    FULL_LOCKDOWN: ("Full lockdown",),
}

# What each preset actually does to the three traffic paths a device has.
#
# This is the source of truth the UI renders from, rather than hand-written
# copy in the template — if a preset changes here, the interface cannot go on
# describing the old behaviour.
#
# Same-VLAN traffic never reaches the GATEWAY, so no zone-based firewall policy
# can touch it — `peers` is "allow" for every preset on its own. UPDATED
# 2026-09-29: the optional neighbour block (NEIGHBOUR_BLOCK_PRESETS below) adds
# a per-device switch-ACL pair that does reach it, but only as far as the
# switches in the path can enforce, so the UI reports coverage per device
# rather than flipping this row to a flat "blocked".
#
# Quarantine (legacy, release-side only — see the note on the constant) is
# "moved": relocating the device changes WHICH peers it has, it does not cut
# peer traffic. Claiming otherwise would be the exact lie this tool exists to
# avoid.
#
# `inbound` is whether your other networks can still start connections to the
# device (allow_inbound). It used to be a checkbox; since 2026-10-02 each
# preset fixes it, and Quarantine is the "nothing reaches it" choice.
PRESET_EFFECTS = {
    CUT_OFF: {
        "internet": "block",
        "networks": "block",
        "peers": "allow",
        "inbound": False,
        "summary": "Nothing in or out. Cut off from the internet, your other "
                   "networks, and other devices on the same network.",
    },
    FULL_LOCKDOWN: {
        "internet": "block",
        "networks": "block",
        "peers": "allow",
        "inbound": True,
        "summary": "Can't reach the internet or your other networks, but you "
                   "can still reach this device.",
    },
    INTERNET_ONLY: {
        "internet": "allow",
        "networks": "block",
        "peers": "allow",
        "inbound": True,
        "summary": "Can reach the internet, nothing else on your network.",
    },
    LAN_ONLY: {
        "internet": "block",
        "networks": "allow",
        "peers": "allow",
        "inbound": True,
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
    "finish, so a streaming device won't stop mid-stream. Reconnect it, or "
    "wait for the session to end.",
    "Your gateway stays reachable. DHCP and the gateway's own services are "
    "not blocked, so the device keeps its address and stays on the network.",
    "DNS keeps working if your resolver is on the device's own VLAN. Verified "
    "on a locked-down device: names still resolved through a same-VLAN "
    "resolver, which forwards upstream, so a determined device still has a "
    "path out over DNS.",
]


# Presets that use the neighbour block (a per-device switch-ACL pair).
# Quarantine always applies it; Internet only offers it as the one remaining
# checkbox, because it has a real cost (casting and printing with neighbours
# stop). No internet and LAN only don't offer it: LAN only's whole point is
# keeping local access, and Quarantine is the "cut everything" choice.
NEIGHBOUR_BLOCK_PRESETS = (CUT_OFF, INTERNET_ONLY)
NEIGHBOUR_ALWAYS_PRESETS = (CUT_OFF,)

NEIGHBOUR_CAVEATS = [
    "The neighbour block works in both directions, so other devices on the "
    "same network can't reach this device either.",
    "The neighbour block only works on UniFi switch models that support it. "
    "House Arrest works out where each device is connected and shows how well "
    "the block will work for each one.",
]


def inbound_for(preset: str) -> bool:
    """Whether the preset lets your other networks start connections to it."""
    return bool(PRESET_EFFECTS.get(preset, {}).get("inbound", True))


def caveats_for(preset: str) -> List[str]:
    """
    Caveats worth showing for a preset. Only presets that claim to cut
    internet access need them; the others don't make that claim.
    """
    effects = PRESET_EFFECTS.get(preset, {})
    if effects.get("internet") != "block":
        return []
    if preset in NEIGHBOUR_ALWAYS_PRESETS:
        # The neighbour block also cuts a same-VLAN resolver wherever the
        # switches cover the device (measured 2026-10-01), so the plain
        # "DNS keeps working on its own VLAN" caveat would overclaim here.
        # Quarantine's rules match every connection state (allow_inbound
        # False), so open connections are cut too, unlike the other presets.
        keep = [c for c in LOCKDOWN_CAVEATS
                if not c.startswith(("DNS keeps working", "Connections already open"))]
        return keep + [
            "Quarantine also cuts connections that are already open, because "
            "its rules match every connection, not just new ones.",
            "A quarantined device can still look up names: the gateway's own "
            "DNS stays reachable, and so do your approved DNS servers if its "
            "network has a DNS Lockdown. It can't connect to anything on the "
            "internet, but because those DNS servers look up names on the "
            "internet for it, a determined device still has a slow path out "
            "over DNS.",
        ]
    return list(LOCKDOWN_CAVEATS)


def requires_network(preset: str) -> bool:
    """True if the preset cannot be applied without a target network."""
    return bool(PRESET_EFFECTS.get(preset, {}).get("requires_network"))


# CORRECTED 2026-09-16. The inbound row used to read "You reaching in to it",
# which understated the exposure. allow_inbound only narrows the BLOCK to the
# NEW and INVALID states with the locked-down device as SOURCE — so a
# connection STARTED by anything else never matches the policy at all, and the
# device's ESTABLISHED reply flows back. That is every device that can already
# route to it, not just the person reading this page.
PATH_LABELS = {
    "internet": "The internet",
    "networks": "Your other networks",
    "peers": "Other devices on the same network",
    "inbound": "Your other networks connecting to this device",
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
            "neighbour_block": value in NEIGHBOUR_BLOCK_PRESETS,
            # Quarantine applies the neighbour block without asking.
            "neighbour_always": value in NEIGHBOUR_ALWAYS_PRESETS,
            "inbound": inbound_for(value),
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
        "never passes the gateway, so no firewall policy reaches it. To block "
        "that too, turn on Device isolation for this network in the table. "
        "Hover its cell to see how many devices it will cover."
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


# ----------------------------------------------------------------------
# DNS Lockdown
#
# Force chosen networks to use only approved resolvers, and block DNS to
# anywhere else. Three policies per run, and their ORDER is the whole feature:
# the allow must evaluate before the blocks or the network loses DNS entirely.
#
# Measured 2026-09-16: the controller does not always store the index we send
# (10004/10005 once came back as 10000/10003), but policies created in
# sequence kept their relative order. So we create allow-first and then VERIFY
# the stored indexes, rather than trusting either behaviour.
# ----------------------------------------------------------------------

DNS_MARKER = "[DNS]"
DNS_PORT = "53"
DOT_PORT = "853"


# ----------------------------------------------------------------------
# Zone resolution
#
# MEASURED 2026-09-17 (home UCG-Fiber): every default zone document carries a
# stable `zone_key` — "internal", "external", "gateway", "vpn", "hotspot",
# "dmz" — that survives the user renaming the zone, plus `default_zone: true`
# and a `network_ids` membership list. Every LAN network document carries
# `firewall_zone_id` pointing at its zone's `_id`. Matching on the display
# name ("Internal"/"External") therefore breaks the moment a user renames a
# zone, while `zone_key` does not. Name matching is kept only as a fallback
# for firmware whose zone documents predate `zone_key`.
# ----------------------------------------------------------------------


def find_zone_id(zones: List[Dict], key: str) -> Optional[str]:
    """
    The `_id` of the zone whose `zone_key` is `key` ("internal", "external").

    Falls back to matching the display name, which only works while the user
    has not renamed the zone — zone_key is the reliable handle.
    """
    for z in zones or []:
        if (z.get("zone_key") or "").strip().lower() == key:
            return z.get("_id")
    for z in zones or []:
        if (z.get("name") or "").strip().lower() == key:
            return z.get("_id")
    return None


def zone_of_network(network: Dict, zones: List[Dict]) -> Optional[str]:
    """
    The zone `_id` a network belongs to.

    Prefers the network document's own `firewall_zone_id`; falls back to the
    zone whose `network_ids` membership list names this network. Returns None
    when neither side records the link.
    """
    if not network:
        return None
    zid = network.get("firewall_zone_id")
    if zid:
        return zid
    nid = network.get("_id")
    if nid:
        for z in zones or []:
            if nid in (z.get("network_ids") or []):
                return z.get("_id")
    return None


def zone_name(zones: List[Dict], zone_id: Optional[str]) -> str:
    """Display name for a zone id, for messages. Never raises."""
    for z in zones or []:
        if z.get("_id") == zone_id:
            return z.get("name") or "unnamed zone"
    return "unknown zone"


def other_lan_zones(zones: List[Dict], client_zone_id: str) -> List[Dict]:
    """
    Zones (other than the client's own) that hold at least one network and are
    not the External or Gateway zone — i.e. places a device could still reach
    that these rules' zone pairs do not cover. Used for honest caveats: a
    block scoped Internal->Internal says nothing about Internal->VPN.
    """
    out = []
    for z in zones or []:
        if z.get("_id") == client_zone_id:
            continue
        kind = ((z.get("zone_key") or z.get("name")) or "").strip().lower()
        if kind in ("external", "gateway"):
            continue
        if not z.get("network_ids"):
            continue
        out.append(z)
    return out


def network_source(network_ids: List[str], zone_id: str) -> Dict:
    """
    Source block matching whole networks.

    Shape measured from a predefined policy on a live console (2026-09-16).
    """
    if not network_ids:
        raise ValueError("At least one network id is required")
    if not zone_id:
        raise ValueError("zone_id is required")
    return {
        "matching_target": "NETWORK",
        "network_ids": list(network_ids),
        "match_mac": False,
        "match_opposite_networks": False,
        "match_opposite_ports": False,
        "port_matching_type": "ANY",
        "zone_id": zone_id,
    }


def describe_dns(note: str) -> str:
    return f"{MARKER}{DNS_MARKER} {note}".strip()


def is_dns_policy(policy: Dict) -> bool:
    """True for a DNS Lockdown policy we created."""
    if not is_house_arrest(policy):
        return False
    return DNS_MARKER in (policy.get("description") or "")


def dns_policy_count(
    block_dot: bool = False,
    has_lan_resolvers: bool = True,
    has_wan_resolvers: bool = False,
) -> int:
    """
    How many policies a DNS lockdown needs.

    Two blocks always (LAN and internet), plus DoT's two, plus ONE ALLOW PER
    ZONE PAIR that actually has an approved resolver in it. See
    classify_resolvers() for why the allow cannot be a single policy.
    """
    allows = (1 if has_lan_resolvers else 0) + (1 if has_wan_resolvers else 0)
    return allows + 2 + (2 if block_dot else 0)


def classify_resolvers(
    resolver_ips: List[str],
    networks: List[Dict],
    zones: Optional[List[Dict]] = None,
    client_zone_id: Optional[str] = None,
) -> Tuple[List[str], List[str], List[Dict]]:
    """
    Split approved resolvers by which zone they are reached through.

    MEASURED 2026-09-16. Firewall policy ordering — and the `index` counter
    itself — is scoped to a (source zone, destination zone) PAIR, not to the
    site. So an ALLOW created in the Internal -> Internal pair does nothing
    whatsoever about a BLOCK in the Internal -> External pair.

    That made a public resolver silently fatal: picking 1.1.1.1 put the allow
    in the Internal pair while the internet block killed the query, leaving the
    chosen networks with no DNS at all. A resolver therefore has to be allowed
    in the pair it is actually reached through, which means up to two allows.

    A LAN resolver can also sit on a network in a DIFFERENT zone than the
    locked-down networks (e.g. a Pi-hole in a custom "Servers" zone). The
    blocks this lockdown writes only cover the client zone's own pair and the
    External pair, so traffic to that resolver is neither blocked nor in need
    of an allow — it is simply outside these rules. Such resolvers come back
    in the third slot so the caller can say so out loud instead of writing an
    ALLOW into a zone pair where it does nothing.

    Returns:
        (resolvers in the client's own zone, resolvers on the internet,
         foreign LAN resolvers as {"ip", "network", "zone_id"} dicts)
    """
    lan, wan, foreign = [], [], []
    for ip in resolver_ips or []:
        home = None
        for n in networks or []:
            if n.get("purpose") == "wan" or not n.get("ip_subnet"):
                continue
            if _ip_in_subnet(ip, n.get("ip_subnet")):
                home = n
                break
        if home is None:
            wan.append(ip)
            continue
        home_zone = zone_of_network(home, zones)
        if client_zone_id and home_zone and home_zone != client_zone_id:
            foreign.append({
                "ip": ip,
                "network": home.get("name") or "network",
                "zone_id": home_zone,
            })
        else:
            lan.append(ip)
    return lan, wan, foreign


def _dns_dest(zone_id: str, port: str, ips: Optional[List[str]] = None) -> Dict:
    dest = {
        "matching_target": "IP" if ips else "ANY",
        "match_opposite_ports": False,
        "port": port,
        "port_matching_type": "SPECIFIC",
        "zone_id": zone_id,
    }
    if ips:
        dest["matching_target_type"] = "SPECIFIC"
        dest["ips"] = list(ips)
        dest["match_opposite_ips"] = False
    return dest


def build_dns_lockdown(
    network_ids: List[str],
    network_label: str,
    lan_resolvers: List[str],
    wan_resolvers: List[str],
    client_zone_id: str,
    external_zone_id: str,
    indexes: List[int],
    block_dot: bool = False,
    foreign_resolvers: Optional[List[Dict]] = None,
) -> List[Dict]:
    """
    Build the DNS Lockdown policy set.

    Returned in the order they must be CREATED, allow first:

      1. ALLOW  chosen networks -> approved resolvers on 53
      2. BLOCK  chosen networks -> anything on 53, inside the LAN
      3. BLOCK  chosen networks -> anything on 53, out to the internet
      4/5. the same two blocks on 853 (DoT) when block_dot is set

    DoT is worth blocking because a device that cannot reach port 853 falls
    back to plain 53, which rules 2 and 3 then capture. DoH (443) cannot be
    handled this way at all and is deliberately out of scope.

    Args:
        network_ids: the VLANs to lock down
        network_label: for policy names
        lan_resolvers: approved resolvers in the client zone (get the LAN allow)
        wan_resolvers: approved resolvers on the internet (get the WAN allow)
        client_zone_id: zone the chosen networks live in (from their
            firewall_zone_id — not assumed to be Internal)
        external_zone_id: the WAN zone
        indexes: pre-allocated, from next_free_index()
        block_dot: also block DNS-over-TLS on 853
        foreign_resolvers: approved resolvers on LAN networks in OTHER zones —
            no policy is written for them, they only relax the no-resolver
            guard, because nothing in this set blocks their zone pair anyway
    """
    if not network_ids:
        raise ValueError("At least one network is required")
    # A resolver in a foreign zone needs no ALLOW (nothing here blocks that
    # zone pair), so a foreign-only selection legitimately builds blocks-only.
    if not (lan_resolvers or wan_resolvers or foreign_resolvers):
        raise ValueError("At least one approved resolver is required")
    needed = dns_policy_count(block_dot, bool(lan_resolvers), bool(wan_resolvers))
    if len(indexes) < needed:
        raise ValueError(f"DNS lockdown needs {needed} indexes, got {len(indexes)}")

    src = network_source(network_ids, client_zone_id)
    desc = describe_dns(f"DNS lockdown for {network_label}")
    out: List[Dict] = []
    nxt = iter(indexes)

    # Allows first, one per zone pair that holds an approved resolver. A
    # resolver only survives the block that follows it if its allow sits in
    # the same (source zone -> destination zone) pair as that block.
    if lan_resolvers:
        out.append(_base_policy(
            name=f"House Arrest DNS: {network_label} - allow approved resolvers (LAN)",
            action="ALLOW", index=next(nxt), source=src,
            destination=_dns_dest(client_zone_id, DNS_PORT, lan_resolvers),
            description=describe_dns(
                f"Allow {', '.join(lan_resolvers)} for {network_label}"),
        ))
    if wan_resolvers:
        out.append(_base_policy(
            name=f"House Arrest DNS: {network_label} - allow approved resolvers (internet)",
            action="ALLOW", index=next(nxt), source=src,
            destination=_dns_dest(external_zone_id, DNS_PORT, wan_resolvers),
            description=describe_dns(
                f"Allow {', '.join(wan_resolvers)} for {network_label}"),
        ))

    out.append(_base_policy(
        name=f"House Arrest DNS: {network_label} - block other DNS (LAN)",
        action="BLOCK", index=next(nxt), source=src,
        destination=_dns_dest(client_zone_id, DNS_PORT),
        description=desc,
    ))
    out.append(_base_policy(
        name=f"House Arrest DNS: {network_label} - block other DNS (internet)",
        action="BLOCK", index=next(nxt), source=src,
        destination=_dns_dest(external_zone_id, DNS_PORT),
        description=desc,
    ))

    if block_dot:
        out.append(_base_policy(
            name=f"House Arrest DNS: {network_label} - block DoT (LAN)",
            action="BLOCK", index=next(nxt), source=src,
            destination=_dns_dest(client_zone_id, DOT_PORT),
            description=desc,
        ))
        out.append(_base_policy(
            name=f"House Arrest DNS: {network_label} - block DoT (internet)",
            action="BLOCK", index=next(nxt), source=src,
            destination=_dns_dest(external_zone_id, DOT_PORT),
            description=desc,
        ))
    return out


# DHCP hands out at most four name servers, in these fields.
DHCP_DNS_FIELDS = ("dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4")
MAX_DHCP_DNS = len(DHCP_DNS_FIELDS)


def dhcp_dns_payload(resolver_ips: List[str]) -> Dict:
    """
    The network-document fields that make DHCP hand out these resolvers.

    Verified against a live network document: `dhcpd_dns_1..4` are plain
    strings and `dhcpd_dns_enabled` gates them. Unused slots must be written
    as empty strings, not left alone, or a resolver the user just removed
    keeps being advertised.
    """
    ips = [str(ip).strip() for ip in (resolver_ips or []) if str(ip).strip()]
    if not ips:
        raise ValueError("At least one resolver is required")
    if len(ips) > MAX_DHCP_DNS:
        raise ValueError(
            f"DHCP can advertise at most {MAX_DHCP_DNS} name servers; "
            f"{len(ips)} given"
        )
    payload = {"dhcpd_dns_enabled": True}
    for i, field in enumerate(DHCP_DNS_FIELDS):
        payload[field] = ips[i] if i < len(ips) else ""
    return payload


def dhcp_dns_of(network: Dict) -> List[str]:
    """What DHCP currently hands out on this network."""
    return [v for v in ((network or {}).get(f) for f in DHCP_DNS_FIELDS) if v]


def dhcp_dns_conflicts(networks: List[Dict], resolver_ips: List[str]) -> List[str]:
    """
    Warn where DHCP hands out a resolver the lockdown is about to block.

    This is the most likely way to lock yourself out with this tool. The rules
    police which resolver a device may TALK to; DHCP decides which resolver it
    is TOLD to use. Nothing keeps the two in step, so approving 192.168.200.50
    while DHCP still advertises 192.168.200.12 leaves every device on that
    network pointed at an address it is no longer allowed to reach.

    Measured on a live console 2026-09-16: a Guests VLAN handing out
    192.168.200.12 and 1.1.1.1 while .50/.51 were the approved resolvers.

    Returns one message per affected network, empty when DHCP already agrees.
    """
    approved = {str(ip).strip() for ip in resolver_ips or []}
    out = []
    for n in networks or []:
        handed = [n.get(f"dhcpd_dns_{i}") for i in (1, 2, 3, 4)]
        handed = [h for h in handed if h]
        if not handed:
            # No override: DHCP points at the gateway, which is not in the
            # approved list either, but the gateway is never blocked by these
            # rules -- its own DNS service answers locally.
            continue
        stale = [h for h in handed if h not in approved]
        if not stale:
            continue
        name = n.get("name") or "network"
        if len(stale) == len(handed):
            out.append(
                f"{name} hands out {', '.join(handed)} over DHCP, and none of "
                f"those are approved. Devices there will be told to use a "
                f"DNS server this lockdown blocks, so those devices will lose DNS until "
                f"you change the DHCP name servers to {', '.join(sorted(approved))} "
                f"in Settings -> Networks -> {name}."
            )
        else:
            out.append(
                f"{name} hands out {', '.join(handed)} over DHCP. "
                f"{', '.join(stale)} "
                + ("is" if len(stale) == 1 else "are")
                + " not approved and will be blocked, so devices there fall "
                  "back to whichever DHCP DNS server is still allowed. "
                  "Tidier to match the DHCP name servers to the approved list."
            )
    return out


def content_filtered_ids(content_filters: List[Dict]) -> List[str]:
    """Network ids covered by an ENABLED CyberSecure Content Filter entry."""
    out = []
    for f in content_filters or []:
        if not f.get("enabled"):
            continue
        for nid in f.get("network_ids") or []:
            if nid not in out:
                out.append(nid)
    return out


def dns_interception_caveats(
    doh_setting: Optional[Dict],
    ips_setting: Optional[Dict],
    content_filters: List[Dict],
    network_ids: List[str],
    names_by_id: Dict[str, str],
) -> List[str]:
    """
    Ways the GATEWAY ITSELF intercepts DNS, which compete with a DNS lockdown.

    MEASURED 2026-09-18 (studio console, then field-verified on the home one):
    with CyberSecure's Encrypted DNS enabled (`setting/doh`, `state` != "off"),
    the gateway takes over resolution with its own DoH upstreams and a LAN
    resolver like a Pi-hole silently stops being used — every firewall rule
    can be correct and the lockdown still means nothing. Content Filter
    (v2 `content-filtering`, per network) and ad blocking
    (`setting/ips` -> `ad_blocking_enabled`) also intercept DNS at the
    gateway, less drastically.

    A missing/unreadable setting produces NO caveat: absence of the read is
    not evidence the feature is off (the null-result rule), and warning on
    every read failure would train people to ignore the warnings.
    """
    out = []
    state = (doh_setting or {}).get("state")
    if state and state != "off":
        out.append(
            "UniFi's Encrypted DNS is ON (Settings -> CyberSecure -> Threat "
            "Management -> Encrypted DNS). The gateway intercepts DNS and "
            "sends it to its own encrypted DNS servers, so devices may "
            "never reach your approved DNS servers, whatever the DNS Lockdown "
            "rules say. Turn Encrypted DNS off if you want your approved DNS "
            "servers to actually be used."
        )

    filtered = set(content_filtered_ids(content_filters))
    hit = [names_by_id.get(n, n) for n in (network_ids or []) if n in filtered]
    if hit:
        out.append(
            "CyberSecure Content Filter is on for "
            + ", ".join(hit)
            + " (Settings -> CyberSecure -> Content Filter). UniFi redirects "
            "a filtered network's DNS through UniFi's filtering DNS servers, "
            "which conflicts with your approved DNS servers."
        )

    if (ips_setting or {}).get("ad_blocking_enabled"):
        out.append(
            "UniFi's Ad Blocking is on, which also intercepts DNS at the "
            "gateway. Ad Blocking usually works alongside your own DNS "
            "servers, but if lookups look wrong, Ad Blocking is part of "
            "the path."
        )
    return out


def zone_pair_of(policy: Dict) -> Tuple[Optional[str], Optional[str]]:
    """The (source zone, destination zone) pair a policy is ordered within."""
    return (
        (policy.get("source") or {}).get("zone_id"),
        (policy.get("destination") or {}).get("zone_id"),
    )


def dns_order_is_safe(created: List[Dict], expect_allow: bool = True) -> bool:
    """
    Confirm each allow really did land ahead of the blocks it competes with.

    CORRECTED 2026-09-16. This used to compare every allow against every block
    site-wide, and that was wrong: it caused a false rollback carrying the
    message "the gateway placed the allow rule after the block rules".

    Ordering -- and the `index` counter itself -- is scoped to a
    (source zone, destination zone) PAIR, not to the site. Measured on a live
    console: two enabled policies both sat at index 10000, one
    Internal -> Internal and one Internal -> External. If ordering were
    site-wide that collision could not exist.

    So the internet-facing block routinely gets a LOWER index than the LAN
    allow, and that is not a conflict at all -- they never evaluate against
    each other. Comparing them rolled back a perfectly good lockdown.

    A pair holding blocks but no allow is fine and expected: it means no
    approved resolver is reached that way, so DNS in that direction is
    supposed to be shut.

    Lower index evaluates first.
    """
    by_pair: Dict[Tuple, Dict[str, List[int]]] = {}
    for p in created or []:
        idx = p.get("index")
        action = p.get("action")
        if not isinstance(idx, int) or action not in ("ALLOW", "BLOCK"):
            continue
        slot = by_pair.setdefault(zone_pair_of(p), {"ALLOW": [], "BLOCK": []})
        slot[action].append(idx)

    # No allow anywhere means nothing was created, or every resolver was
    # dropped. And no block anywhere means nothing is actually being shut —
    # an allow-only set is not a lockdown at all. Either way it is not a safe
    # state to walk away from. (A real lockdown always carries both — EXCEPT
    # when every approved resolver sits in a foreign zone, where no allow is
    # supposed to exist; the caller says so with expect_allow=False.)
    if expect_allow and not any(slot["ALLOW"] for slot in by_pair.values()):
        return False
    if not any(slot["BLOCK"] for slot in by_pair.values()):
        return False

    for slot in by_pair.values():
        if not slot["ALLOW"] or not slot["BLOCK"]:
            continue
        if max(slot["ALLOW"]) >= min(slot["BLOCK"]):
            return False
    return True


def dns_locked_network_ids(policies: List[Dict]) -> Dict[str, str]:
    """
    Networks already covered by a House Arrest DNS lockdown.

    Returns {network_id: label}, read from the source block of our own DNS
    policies. Matching by network id rather than by the policy's label, because
    the label is a comma-joined list of names and would not match a partially
    overlapping selection.

    This exists because nothing stopped a second lockdown being applied over
    the first. Measured on the bench console: a Guests lockdown showed **10
    rules** where five are correct, because the form kept its selection after
    applying and the same set was written twice. Duplicate BLOCK rules are
    mostly harmless; a duplicate ALLOW is not, since release deletes both and
    the precedence check then has two allows to reason about.
    """
    out: Dict[str, str] = {}
    for pol in policies or []:
        if not is_dns_policy(pol):
            continue
        label = dns_label_from_policy(pol) or "an existing lockdown"
        for nid in ((pol.get("source") or {}).get("network_ids") or []):
            out.setdefault(nid, label)
    return out


def arrested_macs(policies: List[Dict]) -> Dict[str, str]:
    """
    MACs already covered by a House Arrest device lockdown, as {mac: label}.

    Same reasoning as dns_locked_network_ids: applying a second preset over a
    device that already has one leaves two contradictory rule sets in place,
    and the tool would then report whichever it found first.
    """
    out: Dict[str, str] = {}
    for pol in policies or []:
        if is_network_policy(pol) or is_dns_policy(pol):
            continue
        label = _label_from_policy(pol) or "an existing lockdown"
        for mac in policy_macs(pol):
            out.setdefault(str(mac).lower(), label)
    return out


def dns_label_from_policy(policy: Dict) -> str:
    """Recover the label from a DNS Lockdown policy description."""
    desc = (policy.get("description") or "")
    desc = desc.replace(MARKER, "").replace(DNS_MARKER, "").strip()
    if " for " in desc:
        return desc.rsplit(" for ", 1)[1].strip()
    return ""


DNS_CAVEATS = [
    "DNS-over-HTTPS is not covered. A device that looks up names over HTTPS "
    "on port 443 gets past DNS Lockdown entirely, and blocking DoH would need "
    "a maintained list of DoH server addresses, which is out of scope here.",
    "A device using a DNS server on the same network isn't affected, because "
    "that traffic never reaches the gateway and no firewall rule can see it.",
    "Existing connections keep running. A device already talking to a "
    "different DNS server keeps doing so until that connection ends.",
]


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


# Connection-state vocabulary, read off the API's own enum validation errors
# (2026-09-16). Blocking only what the device INITIATES is what keeps it
# reachable from your side; blocking every state isolates it absolutely.
CONNECTION_STATE_ALL = "ALL"
CONNECTION_STATE_CUSTOM = "CUSTOM"
STATES_INITIATED_ONLY = ["NEW", "INVALID"]


def connection_state(allow_inbound: bool) -> Dict:
    """
    The connection-state fields for a BLOCK policy.

    allow_inbound=True  -> block only NEW and INVALID, so replies to
                           connections you started still get through.
    allow_inbound=False -> block every state, including replies.

    INVALID is paired with NEW deliberately: without it, packets conntrack
    cannot place (asymmetric routing, stale entries) would not be matched by
    the block and could leak out.
    """
    if allow_inbound:
        return {
            "connection_state_type": CONNECTION_STATE_CUSTOM,
            "connection_states": list(STATES_INITIATED_ONLY),
        }
    return {"connection_state_type": CONNECTION_STATE_ALL, "connection_states": []}


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

    UniFi's own Isolate Network rules express this with
    `create_allow_respond`, but the API refuses that on a policy we create
    when source and destination are in the SAME zone — which is exactly the
    "no LAN" case:

        api.err.FirewallPolicyCreateRespondTrafficPolicyNotAllowed

    Connection-state scoping does the same job and is accepted intra-zone
    (verified by creating and deleting a real policy, 2026-09-16). Blocking
    only NEW and INVALID stops anything the device starts, while ESTABLISHED
    and RELATED replies still flow — so it can answer when you contact it.

    Valid values, read off the API's own enum errors:
        connection_state_type: ALL | RESPOND_ONLY | CUSTOM
        connection_states:     NEW | RELATED | INVALID | ESTABLISHED

    Set allow_inbound False for absolute isolation: state type ALL, which
    matches every packet including replies.

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
        name=f"{NAME_PREFIX}{label} — no internet",
        action="BLOCK",
        index=indexes[0],
        source=src,
        destination=zone_destination(external_zone_id),
        description=describe(f"{PRESET_LABELS[preset]} for {label}"),
    )
    block_lan = _base_policy(
        name=f"{NAME_PREFIX}{label} — no LAN",
        action="BLOCK",
        index=indexes[-1],
        source=src,
        destination=zone_destination(client_zone_id),
        description=describe(f"{PRESET_LABELS[preset]} for {label}"),
    )
    for pol in (block_internet, block_lan):
        pol.update(connection_state(allow_inbound))

    if preset in (CUT_OFF, FULL_LOCKDOWN, QUARANTINE):
        return [block_internet, block_lan]
    if preset == INTERNET_ONLY:
        return [block_lan]
    if preset == LAN_ONLY:
        return [block_internet]
    raise ValueError(f"Unhandled preset: {preset!r}")  # pragma: no cover


def policy_count(preset: str) -> int:
    """How many policies a preset writes. Used to pre-allocate indexes."""
    if preset in (CUT_OFF, FULL_LOCKDOWN, QUARANTINE):
        return 2
    if preset in (INTERNET_ONLY, LAN_ONLY):
        return 1
    raise ValueError(f"Unknown preset: {preset!r}")


# ----------------------------------------------------------------------
# DNS under Internet only (MEASURED 2026-10-01, design doc)
#
# Internet only's "no LAN" BLOCK (device -> its own zone, NEW/INVALID) also
# stops DNS to a resolver on ANOTHER VLAN in that zone, so a device whose
# DHCP points at a Pi-hole on the main LAN lost name resolution while its
# card said "Enforcing". And because new policies are appended to the end of
# their zone pair, a DNS Lockdown applied AFTER a device lockdown landed its
# allow behind the device's block: same result, both tabs green.

DEVICE_DNS_SUFFIX = "DNS to its resolvers"


def device_dns_resolvers(
    device_networks: List[Dict],
    networks: List[Dict],
    zones: Optional[List[Dict]],
    client_zone_id: str,
) -> Tuple[List[str], List[str]]:
    """
    DNS servers an Internet only device must keep reaching through its block.

    Takes the DHCP DNS of each network the devices are on, and keeps the ones
    that sit on a DIFFERENT network in the device's own zone (those are the
    ones the "no LAN" block cuts). Resolvers on the device's own subnet never
    pass the gateway, and internet resolvers are allowed by Internet only
    anyway, so neither needs anything.

    Isolated networks are skipped on purpose: an allow there would punch
    through the isolation the Networks tab set (custom allows run before
    UniFi's Isolated Networks block). Their DNS to another VLAN only works
    through a DNS Lockdown, which is the caller's to report.

    Returns (resolver IPs to allow, ids of isolated networks skipped that
    hand out such a resolver).
    """
    allow: List[str] = []
    skipped: List[str] = []
    for net in device_networks or []:
        handed = dhcp_dns_of(net) if net.get("dhcpd_dns_enabled") is not False else []
        lan, _wan, _foreign = classify_resolvers(handed, networks, zones, client_zone_id)
        cross = [ip for ip in lan if not _ip_in_subnet(ip, net.get("ip_subnet"))]
        if not cross:
            continue
        if net.get(NET_FLAG_ISOLATION):
            skipped.append(net.get("_id"))
            continue
        for ip in cross:
            if ip not in allow:
                allow.append(ip)
    return allow, skipped


def build_device_dns_allow(
    macs: List[str],
    device_label: str,
    client_zone_id: str,
    resolver_ips: List[str],
    index: int,
) -> Dict:
    """
    ALLOW device -> its DHCP DNS servers on port 53, inside its own zone.

    The one ALLOW the Devices tab writes, and it is deliberately narrow: only
    the locked device as source, only port 53, only the resolvers its own
    network's DHCP already hands it, and never on an isolated network (see
    device_dns_resolvers). It must be CREATED before the "no LAN" block, so it
    lands ahead of it; the caller verifies the stored order.
    """
    if not resolver_ips:
        raise ValueError("At least one resolver is required")
    label = device_label or "device"
    return _base_policy(
        name=f"{NAME_PREFIX}{label} — {DEVICE_DNS_SUFFIX}",
        action="ALLOW",
        index=index,
        source=client_source(macs, client_zone_id),
        destination=_dns_dest(client_zone_id, DNS_PORT, resolver_ips),
        description=describe(f"{PRESET_LABELS[INTERNET_ONLY]} for {label}"),
    )


def is_device_dns_allow(policy: Dict) -> bool:
    return (is_house_arrest(policy) and policy.get("action") == "ALLOW"
            and (policy.get("name") or "").endswith(DEVICE_DNS_SUFFIX))


def _blocks_lan_for(block: Dict) -> bool:
    """A device "no LAN" block: our BLOCK, client source, own-zone destination."""
    if not is_house_arrest(block) or block.get("action") != "BLOCK":
        return False
    if is_dns_policy(block) or is_network_policy(block):
        return False
    if (block.get("source") or {}).get("matching_target") != "CLIENT":
        return False
    src_zone, dst_zone = zone_pair_of(block)
    return bool(src_zone) and src_zone == dst_zone


def dns_allows_for_device(
    policies: List[Dict], macs: List[str], network_ids: List[str]
) -> List[Dict]:
    """
    House Arrest ALLOWs that exist to carry this device's DNS: its own
    Internet-only DNS allow, and any DNS Lockdown allow covering its network.
    """
    want_macs = {m.lower() for m in macs or []}
    want_nets = set(network_ids or [])
    out = []
    for p in policies or []:
        if not is_house_arrest(p) or p.get("action") != "ALLOW" or not p.get("enabled", True):
            continue
        if is_device_dns_allow(p) and want_macs & set(policy_macs(p)):
            out.append(p)
        elif is_dns_policy(p) and want_nets & set((p.get("source") or {}).get("network_ids") or []):
            out.append(p)
    return out


def shadowed_dns_allows(
    block: Dict, policies: List[Dict], network_ids: List[str]
) -> List[Dict]:
    """
    DNS allows for this block's devices that sit BEHIND it in its zone pair.

    Lower index evaluates first, so any of these means the device's DNS is
    being cut by its own lockdown. Used by the health check (shown as
    "blocking its DNS") and to decide which blocks to re-create after a DNS
    Lockdown is applied.
    """
    if not _blocks_lan_for(block) or not isinstance(block.get("index"), int):
        return []
    pair = zone_pair_of(block)
    return [
        a for a in dns_allows_for_device(policies, policy_macs(block), network_ids)
        if zone_pair_of(a) == pair and isinstance(a.get("index"), int)
        and a["index"] > block["index"]
    ]


def recreate_payload(policy: Dict, index: int) -> Dict:
    """A copy of one of our policies, ready to POST, at a new index."""
    drop = {"_id", "site_id", "origin_id", "origin_type"}
    out = {k: v for k, v in policy.items() if k not in drop}
    out["index"] = index
    return out


# REMOVED 2026-09-29: build_exception / build_inbound_exception. They built
# per-device ALLOW policies, and a custom ALLOW is evaluated BEFORE UniFi's own
# "Isolated Networks" block (custom 10000s vs predefined 30000s) — so a
# per-device exception silently re-opens a network the Networks tab isolated.
# Decision (Chris): the Devices tab only ever ADDS restrictions. A user who
# needs a specific hole writes that firewall rule themselves in UniFi, where
# the Networks tab's exceptions view will then show it. Neither builder was
# wired to any endpoint.


def find_ours(policies: List[Dict]) -> List[Dict]:
    """Filter a policy list down to the ones House Arrest created."""
    return [p for p in policies or [] if is_house_arrest(p)]


def summarize_blocked(
    flows: List[Dict],
    our_policy_ids: set,
    device_label: Optional[str] = None,
) -> List[Dict]:
    """
    Reduce raw blocked traffic flows to what a person needs to see.

    Every flow here is already scoped to this device as SOURCE and to
    action=blocked by the query, so the only open question per flow is which
    rule stopped it. Each row is tagged rather than filtered:

      "ours"   - blocked by a House Arrest policy that exists right now
      "stale"  - blocked by a policy that carries our name for THIS device but
                 is no longer on the controller
      "other"  - blocked by somebody else's rule

    CORRECTED 2026-09-16. This used to drop everything but "ours" outright.
    Measured on a real device: 251 flows / 793 attempts existed, 87 flows /
    274 attempts of which were blocked by `6aaabcd0...`, a policy with the
    identical name to the live one but a different id -- the leftover of an
    earlier lockdown of the same device. Dropping them under-reported that
    device by more than a third, with no hint that anything had been
    discarded. Silently throwing away real blocks is the same failure as
    counting someone else's.

    Attribution is still by id for the "ours" claim. The "stale" tier falls
    back to the policy NAME, which is weaker -- a renamed policy could in
    principle land here -- so it is reported as its own tier and never folded
    into the headline as though the current rule did it.

    Returns:
        Newest first, each: time_ms, destination, port, protocol, count,
        policy (name), attribution, network, direction.
    """
    out = []
    marker_name = f"{NAME_PREFIX}{device_label}" if device_label else None

    for f in flows or []:
        policies = f.get("policies") or []
        ours = [p for p in policies if p.get("id") in our_policy_ids]

        if ours:
            attribution, blamed = "ours", ours[0]
        else:
            stale = [
                p for p in policies
                if marker_name and (p.get("name") or "").startswith(marker_name)
            ]
            if stale:
                attribution, blamed = "stale", stale[0]
            elif policies:
                attribution, blamed = "other", policies[0]
            else:
                attribution, blamed = "other", {}

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
            "policy": blamed.get("name"),
            "attribution": attribution,
            "network": dest.get("network_name"),
            "direction": f.get("direction"),
        })

    out.sort(key=lambda x: x.get("time_ms") or 0, reverse=True)
    return out


# Destination ports at or above this are ephemeral: the transient port an OS
# picks as the SOURCE of its own outgoing conversation. Traffic aimed at one is
# therefore almost never a service being contacted.
EPHEMERAL_PORT = 32768


def flow_kind(row: Dict) -> str:
    """
    Split blocked traffic into connection attempts and return traffic.

    MEASURED 2026-09-16 on a locked-down Roku, over 7 days: 246 blocked flows,
    778 attempts, 100% UDP, and *not one* destination port below 32768. Every
    packet was aimed at an ephemeral port on one of exactly four devices — the
    four that actually use that Roku (a PC and three phones).

    A device probing the LAN does not behave like that. It contacts services on
    well-known ports (8060 Roku ECP, 1900 SSDP, 5353 mDNS, 53, 443) and it
    sprays across hosts. Traffic to a scattering of high ports on precisely the
    devices that talk to it has the shape of the far side of a conversation
    those devices opened.

    INFERRED, not measured: that these are specifically replies whose UDP
    conntrack entry expired and so came back through as NEW. The obvious test —
    querying flows where the Roku is the DESTINATION — returned zero rows, but
    the `destination_mac` filter is unverified and may simply be ignored, so
    that null result proves nothing and is not cited as evidence.

    Either way the operational point stands and does not depend on the
    mechanism: these rows are not the device reaching out, they drown out the
    rows that are, and they must not be presented as "what it tried to reach".

    Returns "connection" or "return_traffic".
    """
    port = row.get("port")
    proto = (row.get("protocol") or "").upper()
    # Demote ONLY the pattern that was actually measured as return traffic:
    # UDP aimed at an ephemeral port. Everything else — TCP, UDP to a service
    # port, and anything portless such as an ICMP ping sweep — counts as the
    # device reaching out.
    #
    # The polarity matters. Written the other way round (list what counts as a
    # connection, default to return traffic) an ICMP sweep, which carries no
    # port at all, fell through to return traffic and got hidden. A host
    # discovery sweep is exactly what this panel must not bury, so the default
    # is "show it".
    if proto == "UDP" and isinstance(port, int) and port >= EPHEMERAL_PORT:
        return "return_traffic"
    return "connection"


def aggregate_blocked(rows: List[Dict]) -> List[Dict]:
    """
    Collapse blocked flows to one row per thing the device tried to reach.

    Grouped by (destination, ip, protocol) — deliberately NOT by port. Measured
    2026-09-16 on a real locked-down Roku: 424 attempts across 399 flow records,
    which grouping by port only folded to 87 rows because the device hit the
    same two peers on dozens of ephemeral UDP ports. Dropping port from the key
    takes it to a handful of rows, which is the honest shape of the finding —
    "it keeps trying to reach your PC", not eighty-seven separate events.

    The port is still reported when every record agreed on one; otherwise the
    row carries how many distinct ports were folded in, so nothing is hidden.

    Busiest first: "what does this device keep trying to do" is the question
    the panel exists to answer, and that is a question about volume.
    """
    groups: Dict[Tuple, Dict] = {}
    for r in rows or []:
        key = (r.get("destination"), r.get("destination_ip"), r.get("protocol"),
               r.get("attribution"))
        g = groups.get(key)
        if g is None:
            g = dict(r)
            g["_ports"] = {r.get("port")} if r.get("port") is not None else set()
            g["_raw"] = [r]
            g["flow_count"] = 1
            groups[key] = g
            continue
        g["_raw"].append(r)
        g["count"] = (g.get("count") or 0) + (r.get("count") or 0)
        g["flow_count"] = g.get("flow_count", 1) + 1
        if r.get("port") is not None:
            g["_ports"].add(r.get("port"))
        if (r.get("time_ms") or 0) > (g.get("time_ms") or 0):
            g["time_ms"] = r.get("time_ms")
        g["network"] = g.get("network") or r.get("network")

    merged = []
    for g in groups.values():
        ports = g.pop("_ports", set())
        g["port_count"] = len(ports)
        # Only claim a specific port when there genuinely was only one.
        g["port"] = next(iter(ports)) if len(ports) == 1 else None
        # Classified on the aggregate: a destination is a connection attempt if
        # ANY of the folded flows looked like one, so a single real attempt is
        # never buried under a pile of return traffic to the same host.
        g["kind"] = ("connection"
                     if any(flow_kind(r) == "connection" for r in g.pop("_raw", [g]))
                     else "return_traffic")
        merged.append(g)

    merged.sort(key=lambda x: (-(x.get("count") or 0), -(x.get("time_ms") or 0)))
    return merged


def observed_location(flows: List[Dict], our_policy_ids: set = None) -> Dict[str, Dict]:
    """
    Where each locked-down device actually was, taken from blocked traffic.

    The controller's own client record is not always reliable: measured
    2026-09-16, a Roku sitting on 192.168.107.129/IDIoT was reported by both
    `stat/sta` and the Integration API as network "Default" with a null IP.
    Its blocked flows gave the true source IP, network and subnet.

    So live client data is preferred where present, and this fills the gap.
    Returns {mac: {ip, network, seen_ms}} from the newest flow per device.
    """
    # Deliberately NOT filtered to our own policies. Attribution matters for
    # counting what we blocked, but any recent flow from the device tells us
    # where it is — and right after applying a lockdown there are no flows
    # attributed to the new policy ids yet, which would leave the location
    # blank exactly when the user is looking at it.
    out: Dict[str, Dict] = {}
    for f in flows or []:
        src = f.get("source") or {}
        mac = (src.get("mac") or "").lower()
        if not mac or not src.get("ip"):
            continue
        when = f.get("time") or f.get("flow_start_time") or 0
        prev = out.get(mac)
        if prev is None or when > prev.get("seen_ms", 0):
            out[mac] = {
                "ip": src.get("ip"),
                "network": src.get("network_name"),
                "seen_ms": when,
            }
    return out


def blocked_counts_by_label(
    flows: List[Dict],
    policy_id_to_label: Dict[str, str],
    label_for_mac: Optional[Dict[str, str]] = None,
) -> Dict[str, int]:
    """
    Total blocked attempts per locked-down device.

    Counts the flow's own `count` field, not the number of flow records -- one
    record can represent several attempts.

    A flow whose blocking policy is no longer on the controller still counts,
    provided the policy name says it was ours for that device. Those are the
    leftovers of an earlier lockdown of the same device; measured at over a
    third of one device's traffic, and dropping them made the headline disagree
    with reality.
    """
    totals: Dict[str, int] = {}
    for f in flows or []:
        n = f.get("count") or 1
        matched = False
        for p in f.get("policies") or []:
            label = policy_id_to_label.get(p.get("id"))
            if label:
                totals[label] = totals.get(label, 0) + n
                matched = True
                break
        if matched:
            continue
        # Fall back to the policy name for a rule we no longer own.
        for p in f.get("policies") or []:
            name = p.get("name") or ""
            if not name.startswith(NAME_PREFIX):
                continue
            for label in set(policy_id_to_label.values()):
                if name.startswith(f"{NAME_PREFIX}{label}"):
                    totals[label] = totals.get(label, 0) + n
                    matched = True
                    break
            if matched:
                break
    return totals


MATRIX_COLUMNS = [
    {"key": "zone", "label": "Zone",
     "help": "Networks in the same zone reach each other by default."},
    {"key": "isolation", "label": "Network isolation",
     "help": "Blocks this network from reaching your other networks."},
    {"key": "device_isolation", "label": "Device isolation",
     "help": "Stops devices on this network from reaching each other. Device "
             "isolation only fully works for wired devices plugged into a UniFi "
             "switch model that supports it."},
    {"key": "internet", "label": "Internet access",
     "help": "Whether devices here can reach the internet at all."},
    {"key": "mdns", "label": "mDNS forwarding",
     "help": "Lets service discovery (casting, AirPlay) cross this boundary."},
    {"key": "dns", "label": "DNS handed out",
     "help": "Which DNS server DHCP gives devices here. DNS Lockdown can't block "
             "a DNS server on this same network."},
]


# Which matrix columns are a single boolean on the network object, and so can
# be flipped straight from the table.
#
# Zone and DNS are deliberately NOT here. Zone is membership in a zone that
# other networks also belong to — changing it is a move, not a toggle, and its
# blast radius reaches every network in both zones. DNS is a list of resolver
# addresses (dhcpd_dns_1..4), so there is no second state to toggle TO; a
# one-click cell would have to invent one.
EDITABLE_COLUMNS = {
    "isolation": {
        "field": NET_FLAG_ISOLATION,
        "on": "On", "off": "Off",
        "on_warning": "Every device on this network loses access to your other "
                      "networks, now and in future.",
        "off_warning": "Devices here will be able to reach your other networks "
                       "again. If House Arrest isolated this network, this "
                       "releases it.",
    },
    "internet": {
        "field": NET_FLAG_INTERNET,
        "on": "Allowed", "off": "Blocked",
        # This flag reads the opposite way round: True means internet allowed.
        "on_warning": "Devices here get internet access back.",
        "off_warning": "Every device on this network loses internet access, "
                       "now and in future.",
    },
}


def mdns_effective_ids(config: Optional[Dict], networks: List[Dict]) -> List[str]:
    """
    The network ids the site-wide mDNS scope currently covers.

    `mdns_enabled_for` was measured as "some" with an explicit id list; "all"
    is inferred from the UI's "All networks" option and expanded to every
    non-WAN network so removing one network from it degrades gracefully to
    "some" minus that network. Anything else (or a missing config) reads as
    an empty scope — the caller then only ever ADDS, which is safe.
    """
    mode = (config or {}).get("mdns_enabled_for")
    if mode == "all":
        return [
            str(n["_id"]) for n in networks or []
            if n.get("_id") and n.get("purpose") != "wan"
        ]
    if mode == "some":
        return [str(i) for i in (config or {}).get("mdns_enabled_for_network_ids") or []]
    return []


def editable_column(key: str) -> Optional[Dict]:
    """The toggle spec for a matrix column, or None if it is not a switch."""
    return EDITABLE_COLUMNS.get(key)


def _cell(state: str, label: str, detail: str, editable: bool = False) -> Dict:
    """
    One matrix cell. `editable` is decided here rather than in the browser so
    the UI cannot offer a switch the controller will ignore.
    """
    return {"state": state, "label": label, "detail": detail, "editable": editable}


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
    networks: List[Dict],
    zones: List[Dict],
    device_isolation_ids: Optional[List[str]] = None,
    coverage: Optional[Dict[str, Dict[str, int]]] = None,
    switch_acl_supported: Optional[bool] = None,
    isolation_exceptions: Optional[Dict[str, List[str]]] = None,
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
                f"network(s). Traffic inside a zone is allowed unless a firewall "
                f"rule blocks it, so these networks can reach each other by "
                f"default."
                if siblings else
                f"{name} is the only network in the {zname} zone, so no other "
                f"network can reach {name} by default."
            )
        else:
            cells["zone"] = _cell("neutral", "—", "No zone membership reported.")

        # Network isolation. Stays a plain green "On" like every other column,
        # but the hover names every custom ALLOW that gets through it — a
        # green cell must not imply nothing does.
        iso = n.get("network_isolation_enabled")
        holes = (isolation_exceptions or {}).get(nid) or [] if iso else []
        if iso and holes:
            # A hover box grows with its text, so a site with dozens of rules
            # would bury the point. Always give the count; name at most
            # EXCEPTIONS_SHOWN (House Arrest's own first) and point to UniFi's
            # Policy Table for the full list.
            shown = sorted(holes, key=lambda h: 0 if "House Arrest" in h else 1)
            shown = shown[:EXCEPTIONS_SHOWN]
            more = len(holes) - len(shown)
            count = len(holes)
            iso_detail = (
                f"On. Devices here are blocked from your other networks, except "
                f"for what {count} {'rule lets' if count == 1 else 'rules let'} through: "
                + "; ".join(shown)
                + (f"; and {more} more. See them all in UniFi under Settings → "
                   f"Policy Engine → Policy Table, filtered to {name}."
                   if more else ".")
            )
        elif iso:
            iso_detail = ("On. Devices here are blocked from your other networks, "
                          "in both directions. No rules make exceptions.")
        else:
            iso_detail = ("Off. Devices here can reach your other networks unless "
                          "a firewall rule stops them.")
        cells["isolation"] = _cell(
            "good" if iso else "warn",
            "On" if iso else "Off",
            iso_detail,
            editable=True,
        )

        # Device isolation (switch ACL). A SITE-LEVEL list, like mDNS: the
        # toggle adds or removes this network from `acl_device_isolation`.
        # None means the list could not be read — reported as unknown and not
        # offered as a switch, never shown as "Off".
        if n.get("purpose") not in DEVICE_ISOLATION_PURPOSES:
            # UniFi's own Device Isolation picker lists only local networks
            # (measured: exactly the `corporate` ones). Offering the switch on
            # a VPN or transit segment would be a toggle the controller ignores.
            cells["device_isolation"] = _cell(
                "neutral", "—",
                "Device isolation only applies to local networks, not to VPN "
                "or transit networks like this one.")
        elif device_isolation_ids is None:
            cells["device_isolation"] = _cell(
                "neutral", "Unknown",
                "House Arrest couldn't read the Device isolation setting from "
                "the controller, so it can't show or change that setting here.")
        else:
            cells["device_isolation"] = device_isolation_cell(
                nid in device_isolation_ids,
                (coverage or {}).get(nid) if coverage is not None else None,
                site_supported=switch_acl_supported,
            )

        # Internet access
        inet = n.get("internet_access_enabled")
        cells["internet"] = _cell(
            "warn" if inet is not False else "good",
            "Allowed" if inet is not False else "Blocked",
            ("Devices here can reach the internet."
               if inet is not False else
               "Devices here have no internet access at the network level."),
            editable=True,
        )

        # mDNS
        # Editable since 2026-09-17, via the one route that actually works:
        # MEASURED 2026-09-16, `PUT v2/api/site/{site}/global/config/network`
        # with `mdns_enabled_for_network_ids`. The legacy setting/mdns routes
        # name the field `enabled_for_network_ids` and silently discard the
        # v2 spelling, which is what produced 200-and-no-change for so long.
        #
        # The control is still SITE-LEVEL — one shared VLAN list (the Gateway
        # mDNS Proxy "Custom" scope). The toggle here adds or removes THIS
        # network from that shared list, and the confirm dialog says exactly
        # that, so a per-network switch never quietly edits site state.
        mdns = n.get("mdns_enabled")
        cells["mdns"] = _cell(
            "warn" if mdns else "good",
            "On" if mdns else "Off",
            ("Service discovery crosses this boundary. Often wanted for "
             "casting, but it also lets your other networks see the devices "
             "on this network."
             if mdns else
             "Service discovery does not cross this boundary.")
            + " mDNS is one site-wide list (Settings -> Networks -> Gateway "
              "mDNS Proxy -> Custom). Changing this cell adds or removes this "
              "network from that shared list, the same edit the UniFi UI "
              "makes.",
            editable=True,
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
                + f" on this network's own subnet, so DNS queries to "
                + ("that DNS server" if len(local) == 1 else "those DNS servers")
                + " never pass the gateway and no firewall rule can filter "
                  "them. A device locked down on this network can still look "
                  "up names, and the DNS server looks them up on the internet. "
                  "Measured on a real locked-down device."
            )
        elif servers:
            cells["dns"] = _cell(
                "neutral", ", ".join(servers),
                f"DHCP hands out {', '.join(servers)}, which "
                + ("is" if len(servers) == 1 else "are")
                + " outside this network. DNS queries to "
                + ("that server" if len(servers) == 1 else "those servers")
                + " cross the gateway, so a DNS Lockdown on this network can "
                  "control them."
            )
        else:
            cells["dns"] = _cell(
                "good", "Gateway",
                "Devices here use the gateway as their DNS server, so DNS "
                "can be controlled at the gateway."
            )

        rows.append({
            "id": nid, "name": name, "vlan": vlan,
            "purpose": n.get("purpose"), "cells": cells,
        })

    rows.sort(key=lambda r: (r["vlan"] is None, r["vlan"] or 0))
    return {"columns": list(MATRIX_COLUMNS), "rows": rows}


# ---------------------------------------------------------------------------
# Switch ACLs: coverage, Device Isolation, and the per-device neighbour block
# ---------------------------------------------------------------------------
#
# Everything here was measured on a live console on 2026-09-29 — see the
# design doc, "MEASURED 2026-09-29". The rules that shape the code:
#
#   * Same-network traffic never reaches the gateway, so no firewall policy
#     can touch it. Switch ACLs can, but only switches that report
#     `switch_caps.max_custom_mac_acls > 0` enforce them — never hardcode
#     models.
#   * An ACL is enforced by every capable switch the traffic CROSSES, not only
#     the device's own port. A device on a cheap switch is still partly
#     covered if a capable switch sits above it.
#   * That holds for Wi-Fi clients too, but two devices whose traffic meets
#     below every capable switch (same AP, or APs joined on a cheap switch)
#     are not covered at all. Per-SSID client isolation is the tool there.
#   * "Block this device -> Any" also blocks the gateway, i.e. the internet.
#     The neighbour block is therefore a PAIR: ALLOW to the gateway's LAN
#     MACs plus broadcast/IPv6-multicast (the exact set UniFi's own
#     Local-Blocklist ACL generates), then BLOCK -> Any.

COVERED = "covered"
PARTIAL = "partial"
NOT_COVERED = "none"
UNKNOWN = "unknown"

ACL_NAME_PREFIX = "[HouseArrest] "
ACL_NAME_MAX = 32
# Broadcast (ARP, DHCP) and the IPv6 all-routers / DHCPv6 multicast groups.
# Mirrors the ALLOW list UniFi generates for its own Local Blocklist.
ACL_ALWAYS_ALLOW = ["ff:ff:ff:ff:ff:ff", "33:33:00:00:00:02", "33:33:00:01:00:02"]
GATEWAY_TYPES = ("udm", "ugw", "uxg")
# Network purposes UniFi offers Device Isolation for. Measured 2026-09-29: its
# picker listed exactly the `corporate` networks; `guest` is the other LAN
# purpose UniFi uses and is included on the same footing.
DEVICE_ISOLATION_PURPOSES = ("corporate", "guest")


def acl_capable(device: Optional[Dict]) -> bool:
    """Does this device enforce switch ACLs? Read from its own capabilities."""
    caps = (device or {}).get("switch_caps") or {}
    try:
        return int(caps.get("max_custom_mac_acls") or 0) > 0
    except (TypeError, ValueError):
        return False


def gateway_lan_macs(devices: List[Dict]) -> List[str]:
    """
    The MACs a LAN device sees as its gateway.

    Measured: the gateway answers ARP on a LAN with the MAC in its
    `network_table[].mac` (…:85 here), which is NOT the device MAC the
    controller reports (…:80). `ethernet_table[].mac` lists every interface;
    UniFi's own generated ACL allows all of them, so this does too.
    """
    macs = []
    for d in devices or []:
        if d.get("type") not in GATEWAY_TYPES or not d.get("network_table"):
            continue
        for row in (d.get("network_table") or []) + (d.get("ethernet_table") or []):
            m = (row.get("mac") or "").lower()
            if m and m not in macs:
                macs.append(m)
        own = (d.get("mac") or "").lower()
        if own and own not in macs:
            macs.append(own)
    return macs


def _devices_by_mac(devices: List[Dict]) -> Dict[str, Dict]:
    return {(d.get("mac") or "").lower(): d for d in devices or [] if d.get("mac")}


def _first_enforcer_above(
    start_mac: Optional[str], by_mac: Dict[str, Dict]
) -> Tuple[Optional[Dict], bool]:
    """
    Walk the uplink chain and return (first ACL-capable device, complete).

    `complete` is False when the chain points at a device the controller does
    not list (measured 2026-09-29: an AP still named a since-removed switch as
    its uplink). An unfollowable path means "unknown", never "not covered".
    A loop is treated as the end of a complete chain.
    """
    seen = set()
    mac = (start_mac or "").lower()
    while mac and mac not in seen:
        if mac not in by_mac:
            return None, False
        seen.add(mac)
        dev = by_mac[mac]
        if acl_capable(dev):
            return dev, True
        mac = ((dev.get("uplink") or {}).get("uplink_mac") or "").lower()
    return None, True


def site_acl_capable(devices: List[Dict]) -> Optional[bool]:
    """
    Does ANY switch on this site support switch ACLs?

    None when the device list could not be read (unknown, never "no"). False
    means nothing on this network can enforce Device Isolation or the
    neighbour block, so neither should be offered at all.
    """
    if not devices:
        return None
    return any(acl_capable(d) for d in devices)


def _shares_port(client: Dict, clients: Optional[Dict[str, Dict]]) -> bool:
    """
    Does another client sit on the same switch port?

    UniFi cannot see unmanaged gear. Several clients on one port almost always
    means an unmanaged switch (or a VM host) hangs off it, and devices behind
    that never reach the UniFi switch, so "fully covered" would overclaim.
    """
    if not clients or not client.get("is_wired"):
        return False
    sw, port, mac = client.get("sw_mac"), client.get("sw_port"), client.get("mac")
    if not sw or port is None:
        return False
    return any(
        c.get("is_wired") and c.get("sw_mac") == sw and c.get("sw_port") == port
        and c.get("mac") != mac
        for c in clients.values()
    )


def client_coverage(
    client: Optional[Dict],
    devices: List[Dict],
    clients: Optional[Dict[str, Dict]] = None,
) -> Dict:
    """
    How well switch ACLs can separate this device from its neighbours.

    Returns {status, attached_to, enforcer, wired, shared_port}. `status`:
      covered  — its own switch enforces, so every frame it sends is checked
      partial  — a switch further up enforces, so devices elsewhere are
                 separated but neighbours on the same switch/AP are not. Also
                 used when a capable switch's port is shared with other
                 devices (probably an unmanaged switch in between)
      none     — no capable switch anywhere on its path
      unknown  — the controller could not place it (offline, or unreported)

    `clients` (the live client dict) enables the shared-port check; without
    it the verdict is based on the switch alone.
    """
    by_mac = _devices_by_mac(devices)
    if not client:
        return {"status": UNKNOWN, "attached_to": None, "enforcer": None,
                "wired": None, "shared_port": False}
    wired = bool(client.get("is_wired"))
    attach_mac = (client.get("sw_mac") if wired else client.get("ap_mac")) or ""
    attach = by_mac.get(attach_mac.lower())
    if not attach:
        return {"status": UNKNOWN, "attached_to": None, "enforcer": None,
                "wired": wired, "shared_port": False}
    name = attach.get("name") or attach.get("model") or "its switch"
    if wired and acl_capable(attach):
        if _shares_port(client, clients):
            return {"status": PARTIAL, "attached_to": name, "enforcer": name,
                    "wired": True, "shared_port": True}
        return {"status": COVERED, "attached_to": name, "enforcer": name,
                "wired": True, "shared_port": False}
    up = ((attach.get("uplink") or {}).get("uplink_mac") or "")
    enforcer, complete = _first_enforcer_above(up, by_mac)
    if not enforcer and not complete:
        return {"status": UNKNOWN, "attached_to": name, "enforcer": None,
                "wired": wired, "shared_port": False}
    if enforcer:
        return {"status": PARTIAL, "attached_to": name,
                "enforcer": enforcer.get("name") or "an upstream switch",
                "wired": wired, "shared_port": False}
    return {"status": NOT_COVERED, "attached_to": name, "enforcer": None,
            "wired": wired, "shared_port": False}


# The short verdict shown on chips. Plain words, no "enforced".
COVERAGE_LABELS = {
    COVERED: "Fully blocked",
    PARTIAL: "Partly blocked",
    NOT_COVERED: "Not blocked",
    UNKNOWN: "Unknown",
}


def coverage_sentence(cov: Dict) -> str:
    """One plain sentence for the UI. No ACL vocabulary."""
    # Partial wording is deliberately "may": measured 2026-09-29, peers on
    # other switches or APs that meet BELOW the capable switch were not
    # blocked either, so "everything else is blocked" would overclaim.
    status = cov.get("status")
    where = cov.get("attached_to") or "its switch"
    via = cov.get("enforcer") or "a switch that supports it"
    if status == COVERED:
        return f"Plugged into {where}, which supports the neighbour block."
    if status == PARTIAL and cov.get("shared_port"):
        return (f"Plugged into {where}, which supports the neighbour block, "
                f"but other devices share the same switch port. That usually "
                f"means there's another switch in between, or a computer running "
                f"virtual machines. Devices sharing that port may still reach this device.")
    if status == PARTIAL and cov.get("wired"):
        return (f"Plugged into {where}, which doesn't support the neighbour "
                f"block. Devices whose traffic passes through {via} are blocked, "
                f"but other devices on {where}, or on other switches that don't "
                f"support it, may still reach this device.")
    if status == PARTIAL:
        return (f"Connected to Wi-Fi through {where}. Devices whose traffic "
                f"passes through {via} are blocked, but other Wi-Fi devices, "
                f"especially ones on the same access point, may still reach this device. "
                f"Turn on Wi-Fi client isolation for this device's network to close that gap.")
    if status == NOT_COVERED:
        return (f"None of the switches between {where} and the rest of your "
                f"network support the neighbour block, so it would have no "
                f"effect on this device.")
    if cov.get("attached_to"):
        return (f"Connected to {where}, but UniFi can't show the full path "
                f"from there to your gateway because a device along the way isn't "
                f"listed in UniFi. House Arrest can't tell how well the neighbour "
                f"block will work.")
    return ("UniFi doesn't currently know where this device is connected (it "
            "may be offline), so House Arrest can't tell how well the neighbour "
            "block will work.")


def network_isolation_coverage(
    network_id: str, clients: Dict[str, Dict], devices: List[Dict]
) -> Dict[str, int]:
    """Count this network's online devices by coverage status."""
    counts = {COVERED: 0, PARTIAL: 0, NOT_COVERED: 0, UNKNOWN: 0}
    for c in (clients or {}).values():
        if c.get("network_id") != network_id:
            continue
        counts[client_coverage(c, devices, clients)["status"]] += 1
    return counts


NOT_SUPPORTED_DETAIL = (
    "None of your UniFi switches support Device isolation, so turning it on "
    "would have no effect. For Wi-Fi devices, use Wi-Fi client isolation "
    "instead.")


def device_isolation_cell(
    enabled: bool,
    counts: Optional[Dict[str, int]],
    site_supported: Optional[bool] = None,
) -> Dict:
    """
    The matrix cell for Device Isolation.

    "On" alone would overclaim — on the network these were measured on, it
    reached 4 of 41 devices. So an enabled cell always carries the count, and
    goes to warn whenever anything on the network sits outside coverage.
    """
    # No capable switch anywhere: never offer a switch that does nothing, and
    # never show a green "On" for a setting that cannot take effect. If it IS
    # on (set in UniFi), say so without the green.
    if site_supported is False:
        return _cell("neutral", "Not supported",
                     ("Device isolation is turned on in UniFi for this network. "
                      if enabled else "")
                     + NOT_SUPPORTED_DETAIL)
    # Plain-language copy. What the count counts is spelled out, because
    # "N of M covered" alone does not say N of what.
    # Worded for the cell's state: an Off cell describes what turning it on
    # WOULD do, so nothing in it reads as already happening.
    if enabled:
        what = ("Device isolation stops devices on this network from reaching "
                "each other. Device isolation only fully works for wired devices "
                "plugged into a UniFi switch model that supports it. Wi-Fi devices are only "
                "partly blocked, so turn on Wi-Fi client isolation for those as "
                "well. Casting, AirPlay, and printing between devices on this "
                "network don't work while it is on.")
    else:
        what = ("Turning on Device isolation would stop devices on this network "
                "from reaching each other. Device isolation only fully works for "
                "wired devices plugged into a UniFi switch model that supports "
                "it. Wi-Fi "
                "devices would only be partly blocked, so turn on Wi-Fi client "
                "isolation for those as well. Casting, AirPlay, and printing "
                "between devices on this network would stop working.")
    if counts is None:
        now = (" House Arrest couldn't read from the controller which devices "
               "it would block.")
    else:
        total = sum(counts.values())
        full = counts.get(COVERED, 0)
        # "are" while it is on, "would be" while it is off, so an Off cell
        # never reads as if devices are already blocked.
        verb = "are" if enabled else "would be"
        now = (
            f" Of the {total} {'device' if total == 1 else 'devices'} online "
            f"on this network, {full} {verb} fully blocked, "
            f"{counts.get(PARTIAL, 0)} partly blocked (Wi-Fi, or wired behind a "
            f"switch that doesn't support it), {counts.get(NOT_COVERED, 0)} not "
            f"blocked, and {counts.get(UNKNOWN, 0)} unknown."
        )
    # Same colour language as every other column (decided 2026-09-29): On is
    # green, Off is amber. Mixed colours for the same word confused more than
    # they informed. Partial coverage is stated in the hover detail instead.
    if not enabled:
        return _cell("warn", "Off", "Off. " + what + now, editable=True)
    return _cell("good", "On", "On. " + what + now, editable=True)


def acl_rule_name(label: str) -> str:
    """ACL names are capped at 32 characters and there is no description."""
    return (ACL_NAME_PREFIX + (label or "device"))[:ACL_NAME_MAX]


def is_house_arrest_acl(rule: Dict) -> bool:
    """Ours = our name prefix and not generated by UniFi (Objects etc.)."""
    return (
        not rule.get("predefined")
        and (rule.get("name") or "").startswith(ACL_NAME_PREFIX)
    )


def acl_source_macs(rule: Dict) -> List[str]:
    src = rule.get("traffic_source") or {}
    return [m.lower() for m in src.get("specific_mac_addresses") or []]


def _acl_endpoint(macs: List[str]) -> Dict:
    return {"ips_or_subnets": [], "network_ids": [], "ports": [],
            "specific_mac_addresses": macs, "type": "CLIENT_MAC"}


def next_acl_indexes(rules: List[Dict], count: int) -> List[int]:
    """Place ours after every existing rule. acl_index is honoured on create."""
    top = max([r.get("acl_index") or 0 for r in rules or []] + [-1])
    return [top + 1 + i for i in range(count)]


def same_network_resolvers(
    network: Optional[Dict], clients: Optional[Dict]
) -> Tuple[List[Dict], List[str]]:
    """
    DNS servers this network hands out by DHCP that sit on the network itself.

    MEASURED 2026-10-01: the neighbour block's BLOCK device -> Any also cuts a
    Pi-hole on the device's own VLAN, so Internet only lost name resolution
    (internet by IP kept working, HTTPS by name failed) while the card said
    "Fully enforced". Those resolvers get added to the ALLOW beside the gateway.

    Returns (found, missing): found is [{ip, mac, name}] for resolvers matched
    to a live client; missing is the IPs on this subnet with no known MAC
    (offline), which the caller must not silently cut off. Resolvers on other
    networks are routed through the gateway, which the ALLOW already covers.
    """
    if not network or network.get("dhcpd_dns_enabled") is False:
        return [], []
    subnet = network.get("ip_subnet")
    handed = [network.get(f"dhcpd_dns_{i}") for i in (1, 2, 3, 4)]
    local = [ip for ip in handed if ip and _ip_in_subnet(ip, subnet)]
    by_ip = {}
    for c in (clients or {}).values():
        if c.get("ip") and c.get("mac"):
            by_ip.setdefault(c["ip"], c)
    found, missing = [], []
    for ip in local:
        c = by_ip.get(ip)
        if c:
            found.append({"ip": ip, "mac": c["mac"].lower(),
                          "name": c.get("name") or c.get("hostname") or ip})
        else:
            missing.append(ip)
    return found, missing


def resolver_note(found: List[Dict]) -> Optional[str]:
    """One plain sentence for the picker and the lockdown card."""
    if not found:
        return None
    names = [r["name"] for r in found]
    joined = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
    return (f"DNS keeps working: this device can still reach {joined} on the "
            f"same network. Switch rules can't filter by port, so this device can reach "
            f"{'that device' if len(found) == 1 else 'those devices'} on any "
            f"port, not only DNS.")


def acl_allowed_resolvers(
    rules: List[Dict], macs: List[str], clients: Optional[Dict]
) -> List[Dict]:
    """
    Clients our stored ALLOW rule lets these MACs reach, read back from the
    controller rather than recomputed, so the card reports what is enforced.
    The gateway and broadcast/multicast entries aren't clients, so only
    resolvers added by build_neighbour_acls() come back.
    """
    clients = clients or {}
    out, seen = [], set()
    for r in neighbour_acls_for(rules, macs):
        if r.get("action") != "ALLOW":
            continue
        dest = (r.get("traffic_destination") or {}).get("specific_mac_addresses") or []
        for m in dest:
            m = m.lower()
            c = clients.get(m)
            if c and m not in seen:
                seen.add(m)
                out.append({"ip": c.get("ip"), "mac": m,
                            "name": c.get("name") or c.get("hostname") or c.get("ip") or m})
    return out


def build_neighbour_acls(
    macs: List[str],
    network_id: str,
    gateway_macs: List[str],
    label: str,
    indexes: List[int],
    resolver_macs: Optional[List[str]] = None,
) -> List[Dict]:
    """
    The measured neighbour-block pair for devices on one network.

    ALLOW device -> gateway LAN MACs + broadcast/multicast (+ any DNS servers
    the network hands out on the same VLAN) first, then BLOCK device -> Any.
    Without the ALLOW the device loses the gateway and with it the internet
    and DHCP; without the resolvers it loses name resolution.
    """
    if not macs:
        raise ValueError("At least one MAC is required")
    if not network_id:
        raise ValueError("network_id is required")
    if not gateway_macs:
        raise ValueError("Could not find the gateway's MAC addresses")
    src = [normalize_mac(m) for m in macs]
    allow_to = []
    for m in list(gateway_macs) + list(resolver_macs or []) + ACL_ALWAYS_ALLOW:
        m = m.lower()
        # A locked-down Pi-hole is its own resolver; never allow it to itself.
        if m not in allow_to and m not in src:
            allow_to.append(m)
    name = acl_rule_name(label)
    base = {"enabled": True, "mac_acl_network_id": network_id, "name": name,
            "specific_enforcers": [], "traffic_source": _acl_endpoint(src),
            "type": "MAC"}
    return [
        {**base, "acl_index": indexes[0], "action": "ALLOW",
         "traffic_destination": _acl_endpoint(allow_to)},
        {**base, "acl_index": indexes[1], "action": "BLOCK",
         "traffic_destination": _acl_endpoint([])},
    ]


def neighbour_acls_for(rules: List[Dict], macs: List[str]) -> List[Dict]:
    """Our ACL rules whose source is any of these MACs."""
    wanted = {m.lower() for m in macs or []}
    return [r for r in rules or []
            if is_house_arrest_acl(r) and wanted & set(acl_source_macs(r))]


def neighbour_block_state(rules: List[Dict], macs: List[str]) -> Optional[str]:
    """
    None if no neighbour block exists for these MACs, "ok" if the ALLOW+BLOCK
    pair is present and enabled, otherwise "broken" or "disabled". A lone
    BLOCK is broken, not merely incomplete: it cuts the device off entirely.
    """
    ours = neighbour_acls_for(rules, macs)
    if not ours:
        return None
    actions = {r.get("action") for r in ours}
    if "ALLOW" not in actions or "BLOCK" not in actions:
        return "broken"
    if any(r.get("enabled") is False for r in ours):
        return "disabled"
    return "ok"


# ---------------------------------------------------------------------------
# Exceptions that get through network isolation
# ---------------------------------------------------------------------------
#
# UniFi evaluates custom policies (10000s) before its own "Isolated Networks"
# block (30000s), so any enabled custom ALLOW touching an isolated network
# opens a path through it. MEASURED 2026-09-29: a Guests device (isolated)
# still reached the Pi-hole on port 53 through the DNS Lockdown's allow.
# Inbound holes work too: a custom ALLOW INTO an isolated network gets a
# generated "(Return)" policy at 30000-30002, ahead of the isolation block.
#
# The Networks tab must show these next to "Network isolation: On" rather
# than let a green cell imply nothing gets through.

ISOLATION_ZONE_KEYS = ("internal", "hotspot", "dmz")
# How many exceptions the isolation hover names before "and N more".
EXCEPTIONS_SHOWN = 3


def _endpoint_hits_network(
    ep: Dict,
    network: Dict,
    network_zone_id: Optional[str],
    client_network: Dict[str, str],
) -> bool:
    """Could this policy endpoint be a device on `network`?"""
    target = ep.get("matching_target")
    nid = network.get("_id")
    if target == "ANY":
        return bool(network_zone_id) and ep.get("zone_id") == network_zone_id
    if target == "NETWORK":
        return nid in (ep.get("network_ids") or [])
    if target == "IP":
        return any(_ip_in_subnet(str(ip).split("/")[0], network.get("ip_subnet"))
                   for ip in ep.get("ips") or [])
    if target == "CLIENT":
        return any(client_network.get((m or "").lower()) == nid
                   for m in ep.get("client_macs") or [])
    return False


def _describe_exception(policy: Dict, inbound: bool) -> str:
    dest = policy.get("destination") or {}
    port = dest.get("port")
    if is_dns_policy(policy):
        ips = ", ".join(dest.get("ips") or []) or "approved resolvers"
        return f"DNS to {ips} (House Arrest DNS Lockdown)"
    who = "a House Arrest rule" if is_house_arrest(policy) else "your rule"
    name = policy.get("name") or "unnamed rule"
    bits = [f"\"{name}\" ({who}"]
    if inbound:
        bits.append(", into this network")
    if port:
        bits.append(f", port {port}")
    return "".join(bits) + ")"


def isolation_exceptions(
    network: Dict,
    zones: List[Dict],
    policies: List[Dict],
    clients: Optional[Dict[str, Dict]] = None,
) -> List[str]:
    """
    Plain descriptions of the custom ALLOW policies that open a path through
    this network's isolation, in either direction.
    """
    zone_key_by_id = {z.get("_id"): z.get("zone_key") for z in zones or []}
    network_zone_id = network.get("firewall_zone_id")
    client_network = {(m or "").lower(): (c or {}).get("network_id")
                      for m, c in (clients or {}).items()}
    out = []
    for p in policies or []:
        if p.get("predefined") or p.get("action") != "ALLOW" or p.get("enabled") is False:
            continue
        src, dst = p.get("source") or {}, p.get("destination") or {}
        dst_zone = zone_key_by_id.get(dst.get("zone_id"))
        src_zone = zone_key_by_id.get(src.get("zone_id"))
        src_here = _endpoint_hits_network(src, network, network_zone_id, client_network)
        dst_here = _endpoint_hits_network(dst, network, network_zone_id, client_network)
        src_any = src.get("matching_target") == "ANY"
        dst_any = dst.get("matching_target") == "ANY"
        # Out: can start here, and the destination is somewhere ELSE local.
        # "Any" in the zone includes other networks, so it counts.
        outbound = (src_here and dst_zone in ISOLATION_ZONE_KEYS
                    and (dst_any or not dst_here))
        # In: the destination is named inside this network, and the source is
        # somewhere else local (or "Any", which includes somewhere else).
        inbound = (dst_here and not dst_any and src_zone in ISOLATION_ZONE_KEYS
                   and (src_any or not src_here))
        if outbound or inbound:
            text = _describe_exception(p, inbound=inbound and not outbound)
            if text not in out:
                out.append(text)
    return out


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
    # Match "<label> for " exactly. A bare startswith() let "Quarantine"
    # (the new preset) swallow "Quarantine + VLAN move for X" (the legacy
    # one) depending on dict order, and then release would skip clearing the
    # legacy VLAN override: the same failure as the 2026-09-16 shadow bug.
    # Longest label first, so no label can be a prefix match for another.
    candidates = [(v, lbl) for v, lbl in PRESET_LABELS.items()]
    for v, olds in LEGACY_PRESET_LABELS.items():
        candidates.extend((v, lbl) for lbl in olds)
    for value, label in sorted(candidates, key=lambda c: -len(c[1])):
        if body.startswith(label + " for "):
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
# Toggled off in the UniFi UI. The rule still exists but enforces nothing,
# which is exactly the state this tool must never paint green (it happened
# for real: a paused DNS rule kept showing "Enforcing" for a day).
DISABLED = "disabled"
# Every rule present and enabled, but the lockdown's own block runs before a
# DNS allow meant for the device, so it can't resolve names (measured
# 2026-10-01, test B). Set by get_state via shadowed_dns_allows().
DNS_BLOCKED = "dns_blocked"


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

        # A policy switched off in the UniFi UI enforces nothing no matter
        # what its MACs are doing, and "re-enable it" is the fix — so it
        # outranks the rotation check. Only an explicit False counts; docs
        # without the field are treated as enabled.
        if pol.get("enabled") is False:
            status = DISABLED
            results.append({
                "policy_id": pol.get("_id"),
                "name": pol.get("name"),
                "macs": macs,
                "status": status,
                "missing": missing,
                "suggestion": None,
            })
            continue

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
