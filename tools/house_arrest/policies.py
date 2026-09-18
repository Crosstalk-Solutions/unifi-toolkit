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

# The presets the tool OFFERS. Quarantine stays out of this tuple but keeps its
# PRESET_LABELS / PRESET_EFFECTS entries so preset_from_policy() still
# recognises a pre-removal quarantine and release still clears its VLAN
# override instead of stranding the device.
PRESETS = (FULL_LOCKDOWN, INTERNET_ONLY, LAN_ONLY)

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
# Quarantine (legacy, release-side only — see the note on the constant) is
# "moved": relocating the device changes WHICH peers it has, it does not cut
# peer traffic. Claiming otherwise would be the exact lie this tool exists to
# avoid.
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


# CORRECTED 2026-09-16. The inbound row used to read "You reaching in to it",
# which understated the exposure. allow_inbound only narrows the BLOCK to the
# NEW and INVALID states with the locked-down device as SOURCE — so a
# connection STARTED by anything else never matches the policy at all, and the
# device's ESTABLISHED reply flows back. That is every device that can already
# route to it, not just the person reading this page.
PATH_LABELS = {
    "internet": "The internet",
    "networks": "Your other networks",
    "peers": "Devices on its own VLAN",
    "inbound": "Other devices reaching in to it",
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
    resolver_ips: List[str], networks: List[Dict]
) -> Tuple[List[str], List[str]]:
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

    Returns:
        (resolvers inside the LAN, resolvers out on the internet)
    """
    subnets = [
        n.get("ip_subnet") for n in networks or []
        if n.get("purpose") != "wan" and n.get("ip_subnet")
    ]
    lan, wan = [], []
    for ip in resolver_ips or []:
        (lan if any(_ip_in_subnet(ip, sn) for sn in subnets) else wan).append(ip)
    return lan, wan


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
        resolver_ips: the approved resolvers
        resolver_zone_id: zone the resolvers live in
        client_zone_id: zone the networks live in
        external_zone_id: the WAN zone
        indexes: pre-allocated, from next_free_index()
        block_dot: also block DNS-over-TLS on 853
    """
    if not network_ids:
        raise ValueError("At least one network is required")
    if not (lan_resolvers or wan_resolvers):
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
                f"resolver this lockdown blocks, so they will lose DNS until "
                f"you change the DHCP name servers to {', '.join(sorted(approved))} "
                f"in Settings -> Networks -> {name}."
            )
        else:
            out.append(
                f"{name} hands out {', '.join(handed)} over DHCP. "
                f"{', '.join(stale)} "
                + ("is" if len(stale) == 1 else "are")
                + " not approved and will be blocked, so devices there fall "
                  "back to whichever handed-out resolver is still allowed. "
                  "Tidier to match the DHCP name servers to the approved list."
            )
    return out


def zone_pair_of(policy: Dict) -> Tuple[Optional[str], Optional[str]]:
    """The (source zone, destination zone) pair a policy is ordered within."""
    return (
        (policy.get("source") or {}).get("zone_id"),
        (policy.get("destination") or {}).get("zone_id"),
    )


def dns_order_is_safe(created: List[Dict]) -> bool:
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
    # state to walk away from. (A real lockdown always carries both.)
    if not any(slot["ALLOW"] for slot in by_pair.values()):
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
    "DNS-over-HTTPS is not covered. A device that resolves over HTTPS on port "
    "443 bypasses this entirely, and blocking that needs a maintained list of "
    "DoH server addresses — out of scope here.",
    "A device using a resolver on its OWN network is unaffected: that traffic "
    "never reaches the gateway, so no firewall policy can see it.",
    "Existing connections keep running. A device already talking to another "
    "resolver continues until that conversation ends.",
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
        name=f"{NAME_PREFIX}{label} — allow {where}",
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
        name=f"{NAME_PREFIX}{label} — allow {where} inbound",
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
    {"key": "internet", "label": "Internet access",
     "help": "Whether devices here can reach the internet at all."},
    {"key": "mdns", "label": "mDNS forwarding",
     "help": "Lets service discovery (casting, AirPlay) cross this boundary."},
    {"key": "dns", "label": "DNS handed out",
     "help": "Which resolver DHCP gives devices here. A resolver on this same "
             "network cannot be filtered by the gateway."},
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
               "stops them."),
            editable=True,
        )

        # Internet access
        inet = n.get("internet_access_enabled")
        cells["internet"] = _cell(
            "warn" if inet is not False else "good",
            "Allowed" if inet is not False else "Blocked",
            f"internet_access_enabled={inet!r}. "
            + ("Devices here can reach the internet."
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
            f"mdns_enabled={mdns!r}. "
            + ("Service discovery crosses this boundary. Often wanted for "
               "casting, but it does advertise what lives here."
               if mdns else
               "Service discovery does not cross this boundary.")
            + " mDNS is one site-wide list (Settings -> Networks -> Gateway "
              "mDNS Proxy -> Custom). Toggling it here adds or removes this "
              "network from that shared list — the same edit the UniFi UI "
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
