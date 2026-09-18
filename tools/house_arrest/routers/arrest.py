"""
House Arrest API endpoints.

Safety rules enforced here, not in the UI:

  * Every write endpoint defaults to dry_run=True. A caller has to ask for a
    real write explicitly.
  * Release only ever deletes policies that pass is_house_arrest(). Anything
    else is refused and reported back, never silently skipped.
"""
import logging
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException

from shared.unifi_session import get_shared_client
from tools.house_arrest import policies as P
from tools.house_arrest.models import (
    ArrestSummary,
    BlockedFlow,
    ClientInfo,
    DnsLockdownEntry,
    DnsLockdownRequest,
    DnsLockdownResponse,
    InspectionFinding,
    InspectionResponse,
    IsolateRequest,
    IsolateResponse,
    IsolatedNetwork,
    IsolationMatrix,
    LockdownRequest,
    LockdownResponse,
    NetworkInfo,
    NetworkSettingRequest,
    DhcpDnsChange,
    DhcpDnsRequest,
    DhcpDnsResponse,
    PolicyHealth,
    PrecedenceWarning,
    ReleaseRequest,
    ReleaseResponse,
    StateResponse,
    WlanInfo,
    WlanIsolationRequest,
    ZoneInfo,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["house_arrest"])


def _zone_ids(zones: List[Dict]) -> Tuple[Optional[str], Optional[str]]:
    """
    Find the Internal and External zone IDs.

    Zone IDs are per-console, so they are always looked up, never hardcoded.
    Matched on the stable `zone_key` field, not the display name — a renamed
    zone keeps its zone_key (measured 2026-09-17; name matching remains only
    as a fallback inside find_zone_id for firmware without zone_key).
    """
    return P.find_zone_id(zones, "internal"), P.find_zone_id(zones, "external")


def _device_zone(
    macs: List[str],
    known_clients: List[Dict],
    networks: List[Dict],
    zones: List[Dict],
    internal_id: str,
    caveats: List[str],
) -> Tuple[Optional[str], Optional[str]]:
    """
    The firewall zone id to scope a device lockdown to.

    Attribution chain per MAC: known-client record -> last_connection_network_id
    -> that network's firewall_zone_id. Unattributable MACs fall back to the
    Internal zone. Returns (zone_id, error): mixed zones across the selection
    are refused as an error, and a non-Internal result appends a caveat so the
    user can see exactly what the rules were scoped to.
    """
    nets_by_id = {n.get("_id"): n for n in networks or [] if n.get("_id")}
    by_mac = {}
    for c in known_clients or []:
        mac = (c.get("mac") or "").lower()
        if mac:
            by_mac[mac] = c

    found: Dict[str, List[str]] = {}
    unknown: List[str] = []
    for mac in macs:
        rec = by_mac.get(mac.lower())
        net = nets_by_id.get((rec or {}).get("last_connection_network_id"))
        zid = P.zone_of_network(net, zones) if net else None
        if zid:
            found.setdefault(zid, []).append(mac)
        else:
            unknown.append(mac)

    if len(found) > 1:
        parts = "; ".join(
            f"{P.zone_name(zones, z)}: {', '.join(ms)}"
            for z, ms in found.items()
        )
        return None, (
            f"These devices sit in different firewall zones ({parts}). "
            "Firewall rules are scoped to one zone pair, so apply a separate "
            "lockdown per zone instead."
        )

    zone_id = next(iter(found)) if found else internal_id
    if zone_id != internal_id:
        caveats.append(
            f"The controller last saw "
            + ("this device" if len(macs) == 1 else "these devices")
            + f" on a network in the \"{P.zone_name(zones, zone_id)}\" "
            "firewall zone, so the rules are scoped to that zone. If the "
            "device has since moved to another zone, release and re-apply."
        )
        if unknown:
            caveats.append(
                f"No network could be attributed to {', '.join(unknown)}; "
                f"included in the \"{P.zone_name(zones, zone_id)}\" scope "
                "with the rest of the selection."
            )
    return zone_id, None


async def _client_or_error():
    client = await get_shared_client()
    if client is None:
        return None, "UniFi controller not configured or unreachable"
    return client, None


@router.get("/state", response_model=StateResponse)
async def get_state():
    """
    Everything the dashboard needs: zones, active lockdowns, and whether each
    one is actually still enforcing anything.
    """
    client, err = await _client_or_error()
    if err:
        return StateResponse(connected=False, error=err)

    try:
        zones = await client.get_firewall_zones()
        all_policies = await client.get_firewall_policies()
        known_clients = await client.get_known_clients()
    except Exception as e:
        logger.error(f"House Arrest state fetch failed: {e}")
        return StateResponse(connected=False, error=str(e))

    internal_id, external_id = _zone_ids(zones)
    ours_all = P.find_ours(all_policies)
    # Network-scoped policies must never be listed as locked-down devices.
    net_policies = [p for p in ours_all if P.is_network_policy(p)]
    dns_policies = [p for p in ours_all if P.is_dns_policy(p)]
    ours = [
        p for p in ours_all
        if not P.is_network_policy(p) and not P.is_dns_policy(p)
    ]

    # Known clients, not active ones: a device that is merely switched off
    # has not broken its policy.
    known = {}
    for c in known_clients or []:
        mac = (c.get("mac") or "").lower()
        if mac:
            known[mac] = c.get("name") or c.get("hostname") or ""

    health_rows = P.check_breakage(ours, known)

    # A saved VLAN override that the device has not picked up yet is not a
    # completed quarantine. Measured: a wired client keeps its VLAN and lease
    # until it reconnects, so the override can sit pending indefinitely.
    pending_move = set()
    try:
        active_now = await client.get_clients()
    except Exception:
        active_now = {}
    for c in known_clients or []:
        mac = (c.get("mac") or "").lower()
        target = c.get("virtual_network_override_id")
        if not mac or not c.get("virtual_network_override_enabled") or not target:
            continue
        live = active_now.get(mac)
        if live and live.get("network_id") != target:
            pending_move.add(mac)

    # Group policies into one entry per locked-down device.
    grouped: Dict[str, ArrestSummary] = {}
    health_by_id = {h["policy_id"]: h for h in health_rows}
    for pol in ours:
        label = P._label_from_policy(pol) or "device"
        summary = grouped.get(label)
        if summary is None:
            summary = ArrestSummary(label=label, macs=P.policy_macs(pol))
            grouped[label] = summary
        pid = pol.get("_id")
        if pid:
            summary.policy_ids.append(pid)
        # Which lockdown this is. Read off the first policy that declares it;
        # every policy in a set carries the same preset.
        if not summary.preset:
            # preset_from_policy returns the internal key; show the friendly
            # label the preset grid uses.
            key = P.preset_from_policy(pol)
            summary.preset = P.PRESET_LABELS.get(key) if key else None
        h = health_by_id.get(pid)
        if h and h["status"] != P.OK:
            summary.status = h["status"]
            summary.suggestion = h.get("suggestion")
        elif any(m in pending_move for m in summary.macs):
            summary.status = "pending_move"

    # Blocked-traffic counts: only worth a round trip when something is
    # actually locked down.
    if ours:
        policy_to_label = {}
        for pol in ours:
            pid = pol.get("_id")
            if pid:
                policy_to_label[pid] = P._label_from_policy(pol) or "device"
        all_macs = sorted({m for pol in ours for m in P.policy_macs(pol)})
        our_ids = {p.get("_id") for p in ours if p.get("_id")}
        try:
            flows = await client.get_blocked_flows(all_macs, hours=24)
            totals = P.blocked_counts_by_label(flows, policy_to_label)
            seen = P.observed_location(flows, our_ids)
            for summary in grouped.values():
                summary.blocked_count = totals.get(summary.label, 0)
                for mac in summary.macs:
                    # Observed (traffic-flow) location first, stat/sta second.
                    # Measured 2026-09-17: stat/sta reported a device on
                    # Default/192.168.200.234 while its own console — and its
                    # blocked-flow source addresses — showed IDIoT/.107.177.
                    # Flow data carries the address the device actually sends
                    # from; stat/sta is the API the design doc already flags
                    # as misreporting networks.
                    if mac in seen:
                        summary.ip = seen[mac]["ip"]
                        summary.network = seen[mac]["network"]
                        summary.location_source = "observed"
                        break
                    live = (active_now.get(mac) or {})
                    if live.get("ip"):
                        summary.ip = live.get("ip")
                        summary.network = live.get("network")
                        summary.location_source = "live"
                        break
        except Exception as e:
            logger.warning(f"Could not fetch blocked flows: {e}")

    # Isolated networks are read from UniFi's own flags, so this list matches
    # what the UniFi UI shows. Legacy House Arrest network policies from the
    # earlier implementation are still surfaced so they can be cleaned up.
    isolated: List[IsolatedNetwork] = []
    try:
        all_networks = await client.get_networks()
    except Exception:
        all_networks = []
    for n in all_networks:
        if n.get("purpose") == "wan":
            continue
        iso = bool(n.get(P.NET_FLAG_ISOLATION))
        no_net = n.get(P.NET_FLAG_INTERNET) is False
        if not (iso or no_net):
            continue
        bits = []
        if iso:
            bits.append("isolated from other networks")
        if no_net:
            bits.append("no internet")
        isolated.append(IsolatedNetwork(
            label=n.get("name") or "network",
            network_id=n.get("_id"),
            preset=" + ".join(bits),
        ))

    legacy = []
    for pol in net_policies:
        legacy.append({
            "policy_id": pol.get("_id"),
            "name": pol.get("name"),
            "label": P.network_label_from_policy(pol) or "network",
        })

    dns_by_label: Dict[str, DnsLockdownEntry] = {}
    for pol in dns_policies:
        label = P.dns_label_from_policy(pol) or "network"
        entry = dns_by_label.get(label)
        if entry is None:
            entry = DnsLockdownEntry(label=label)
            dns_by_label[label] = entry
        pid = pol.get("_id")
        if pid:
            entry.policy_ids.append(pid)
        for nid in ((pol.get("source") or {}).get("network_ids") or []):
            if nid not in entry.network_ids:
                entry.network_ids.append(nid)
        dest = pol.get("destination") or {}
        if pol.get("action") == "ALLOW" and dest.get("ips"):
            entry.resolvers = list(dest.get("ips"))
        if dest.get("port") == P.DOT_PORT:
            entry.blocks_dot = True

    return StateResponse(
        connected=True,
        dns_lockdowns=list(dns_by_label.values()),
        isolated_networks=isolated,
        legacy_network_policies=legacy,
        zones=[ZoneInfo(id=z.get("_id", ""), name=z.get("name", "")) for z in zones],
        internal_zone_id=internal_id,
        external_zone_id=external_id,
        arrests=list(grouped.values()),
        health=[PolicyHealth(**h) for h in health_rows],
        custom_policy_count=len([p for p in all_policies if not p.get("predefined")]),
        total_policy_count=len(all_policies),
        # The controller assigns the stored index itself, so our rules can land
        # after a user's own ALLOW. Surface that rather than assume ordering.
        precedence_warnings=[
            PrecedenceWarning(**w)
            for w in P.check_precedence(ours_all, all_policies)
        ],
    )


@router.get("/clients", response_model=List[ClientInfo])
async def list_clients(online_only: bool = False):
    """Clients for the device picker."""
    client, err = await _client_or_error()
    if err:
        raise HTTPException(status_code=503, detail=err)

    try:
        known_clients = await client.get_known_clients()
        active = await client.get_clients()
        networks = await client.get_networks()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    # A client sitting on a genuine WAN network (purpose == "wan") cannot be put
    # under a per-device LAN lockdown — a firewall rule against the WAN uplink
    # does nothing — so it has no place in the picker. Match WANs by id and by
    # name, the same way list_networks() excludes them as quarantine targets.
    # NOTE: purpose is the authority, not the name. A user-named "Comcast WAN"
    # can actually be a purpose "vlan-only" transit segment; its (nameless,
    # IP-less) transit MACs are left in the list rather than guessed at from the
    # word "WAN", because filtering nameless+IP-less entries wholesale would also
    # hide every legitimately offline, MAC-only device.
    wan_ids = {n.get("_id") for n in networks if n.get("purpose") == "wan" and n.get("_id")}
    wan_names = {n.get("name") for n in networks if n.get("purpose") == "wan" and n.get("name")}

    out = []
    for c in known_clients or []:
        mac = (c.get("mac") or "").lower()
        if not mac:
            continue
        live = active.get(mac) or {}
        online = bool(live)
        if online_only and not online:
            continue
        if live.get("network_id") in wan_ids or live.get("network") in wan_names:
            continue
        out.append(ClientInfo(
            mac=mac,
            name=c.get("name") or c.get("hostname") or "",
            ip=live.get("ip"),
            network=live.get("network"),
            online=online,
            fixed_ip=c.get("fixed_ip") if c.get("use_fixedip") else None,
            locally_administered=P.is_locally_administered(mac),
        ))
    out.sort(key=lambda x: (not x.online, (x.name or "zzz").lower()))
    return out


@router.get("/wlans", response_model=List[WlanInfo])
async def list_wlans():
    """
    SSIDs with their client-isolation state and how many clients each carries.

    This is the only control the tool has over same-VLAN peer traffic. A
    firewall policy never sees that traffic — it does not pass the gateway —
    so no preset on the Devices tab can touch it.
    """
    client, err = await _client_or_error()
    if err:
        raise HTTPException(status_code=503, detail=err)

    try:
        wlans = await client.get_wlans()
        stations = await client.get_clients()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    # get_clients() returns a dict keyed by MAC, not a list — iterating it
    # directly yields MAC strings and silently counts nothing.
    counts: Dict[str, int] = {}
    for st in (stations or {}).values():
        if not isinstance(st, dict):
            continue
        essid = st.get("essid")
        if essid:
            counts[essid] = counts.get(essid, 0) + 1

    out = []
    for w in wlans:
        name = w.get("name") or "(unnamed)"
        out.append(WlanInfo(
            id=w.get("_id") or "",
            name=name,
            enabled=bool(w.get("enabled", True)),
            isolated=bool(w.get("l2_isolation")),
            client_count=counts.get(name, 0),
            network_id=w.get("networkconf_id"),
        ))
    out.sort(key=lambda x: (not x.enabled, x.name.lower()))
    return out


@router.post("/wlan-isolation")
async def set_wlan_isolation(req: WlanIsolationRequest):
    """
    Turn client isolation on or off for one SSID.

    Deliberately not folded into any device preset. Isolation is a property of
    the SSID, so it lands on every client using it — turning it on to contain
    one television also stops every phone on that SSID casting or printing. A
    per-device tool must not make that choice on the user's behalf.
    """
    client, err = await _client_or_error()
    if err:
        raise HTTPException(status_code=503, detail=err)

    ok = await client.set_wlan_isolation(req.wlan_id, req.enabled)
    if not ok:
        raise HTTPException(
            status_code=502,
            detail=("The controller did not apply the change. Nothing was "
                    "changed as far as we can confirm — check the UniFi UI."),
        )
    return {"ok": True, "wlan_id": req.wlan_id, "isolated": req.enabled}


@router.post("/dhcp-dns", response_model=DhcpDnsResponse)
async def set_dhcp_dns(req: DhcpDnsRequest):
    """
    Point a network's DHCP name servers at the approved resolvers.

    This is the other half of a DNS lockdown, and it is deliberately a separate,
    explicit action rather than something the lockdown does for you. The rules
    police which resolver a device may TALK to; DHCP decides which one it is
    TOLD to use. Applying a lockdown while DHCP still advertises a blocked
    resolver is the main way to take a network's DNS out, so the tool offers to
    fix it — but changing what every device on a network is told is a bigger
    blast radius than a firewall rule, and it gets its own confirmation.

    Always previewed first: dry_run reports the from/to per network.
    """
    client, err = await _client_or_error()
    if err:
        return DhcpDnsResponse(dry_run=req.dry_run, error=err)
    if not req.network_ids:
        raise HTTPException(status_code=400, detail="Select at least one network")

    try:
        payload = P.dhcp_dns_payload(req.resolver_ips)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        networks = await client.get_networks()
    except Exception as e:
        return DhcpDnsResponse(dry_run=req.dry_run, error=str(e))

    by_id = {n.get("_id"): n for n in networks}
    proposed = [v for v in (payload[f] for f in P.DHCP_DNS_FIELDS) if v]

    changes: List[DhcpDnsChange] = []
    for nid in req.network_ids:
        n = by_id.get(nid)
        if n is None:
            raise HTTPException(status_code=400, detail=f"Unknown network {nid}")
        changes.append(DhcpDnsChange(
            network_id=nid,
            label=n.get("name") or "network",
            current=P.dhcp_dns_of(n),
            proposed=list(proposed),
        ))

    if req.dry_run:
        return DhcpDnsResponse(dry_run=True, changes=changes)

    for ch in changes:
        # Already correct: leave it alone and say so, rather than writing a
        # document back for no reason.
        if ch.current == ch.proposed:
            ch.applied = True
            continue
        ok = await client.set_network_fields(ch.network_id, **payload)
        ch.applied = ok
        if not ok:
            ch.error = ("The controller did not apply the change. Check the "
                        "UniFi UI before assuming it took.")

    return DhcpDnsResponse(dry_run=False, changes=changes)


@router.post("/network-setting")
async def set_network_setting(req: NetworkSettingRequest):
    """
    Flip one boolean network setting from the inspection matrix.

    Only the columns listed in EDITABLE_COLUMNS can be written, so a crafted
    request cannot set an arbitrary field on the network object. The write is
    confirmed by re-reading (set_network_flags polls), because the controller
    provisions asynchronously and a single immediate re-read reports false
    failures.
    """
    client, err = await _client_or_error()
    if err:
        raise HTTPException(status_code=503, detail=err)

    # mDNS is not a per-network field — it is ONE site-wide list (the Gateway
    # mDNS Proxy scope), and the per-network `mdns_enabled` is a read-only
    # projection of it. So this toggle edits that shared list: read the
    # current scope, add or remove this one network, write the whole list
    # back through the v2 route (the only one that actually applies it).
    if req.column == "mdns":
        config = await client.get_global_network_config()
        if config is None:
            raise HTTPException(
                status_code=502,
                detail=("Could not read the site-wide mDNS scope from the "
                        "controller, so nothing was changed."),
            )
        try:
            networks = await client.get_networks()
        except Exception as e:
            raise HTTPException(status_code=502, detail=str(e))
        current = P.mdns_effective_ids(config, networks)
        wanted = [i for i in current if i != req.network_id]
        if req.value:
            wanted.append(req.network_id)
        if sorted(wanted) == sorted(current):
            return {"ok": True, "field": "mdns_enabled_for_network_ids",
                    "value": req.value}
        ok = await client.set_mdns_networks(wanted)
        if not ok:
            raise HTTPException(
                status_code=502,
                detail=("The controller did not apply the mDNS scope change. "
                        "Nothing was changed as far as we can confirm — check "
                        "Settings -> Networks -> Gateway mDNS Proxy."),
            )
        return {"ok": True, "field": "mdns_enabled_for_network_ids",
                "value": req.value}

    spec = P.editable_column(req.column)
    if spec is None:
        raise HTTPException(
            status_code=400, detail=f"{req.column!r} is not an editable setting")

    field = spec["field"]
    ok = await client.set_network_flags(req.network_id, **{field: req.value})
    if not ok:
        raise HTTPException(
            status_code=502,
            detail=(f"The controller did not apply {field}. Nothing was "
                    f"changed as far as we can confirm — check the UniFi UI."),
        )
    return {"ok": True, "field": field, "value": req.value}


@router.get("/blocked", response_model=List[BlockedFlow])
async def blocked(label: Optional[str] = None, hours: int = 24):
    """
    Traffic this tool actually stopped, newest first.

    Only flows the gateway attributes to a House Arrest policy are returned —
    attribution is by policy id, so another rule's blocks are never counted as
    ours.
    """
    client, err = await _client_or_error()
    if err:
        raise HTTPException(status_code=503, detail=err)

    try:
        all_policies = await client.get_firewall_policies()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    ours = P.find_ours(all_policies)
    if label:
        wanted = label.strip().lower()
        ours = [p for p in ours if P._label_from_policy(p).strip().lower() == wanted]
    if not ours:
        return []

    macs = sorted({m for pol in ours for m in P.policy_macs(pol)})
    our_ids = {p.get("_id") for p in ours if p.get("_id")}

    try:
        flows = await client.get_blocked_flows(macs, hours=hours)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    # device_label lets a flow blocked by an earlier, now-deleted policy for
    # THIS device still be attributed, instead of being silently dropped.
    rows = P.aggregate_blocked(
        P.summarize_blocked(flows, our_ids, device_label=label)
    )
    return [BlockedFlow(**row) for row in rows]


@router.post("/isolate", response_model=IsolateResponse)
async def isolate(req: IsolateRequest):
    """
    Isolate a whole network using UniFi's own per-network settings.

    Uses the native `network_isolation_enabled` / `internet_access_enabled`
    flags rather than writing parallel firewall policies, so the UniFi UI and
    this tool always agree. The controller generates the backing BLOCK rules
    itself, covering every destination zone rather than just Internal.

    Only flags that need changing are touched, so releasing later never
    switches off something that was already set.
    """
    client, err = await _client_or_error()
    if err:
        return IsolateResponse(dry_run=req.dry_run, error=err)

    if req.preset not in P.NETWORK_PRESETS:
        raise HTTPException(status_code=400, detail=f"Unknown preset: {req.preset}")

    try:
        networks = await client.get_networks()
    except Exception as e:
        return IsolateResponse(dry_run=req.dry_run, error=str(e))

    target = next((n for n in networks if n.get("_id") == req.network_id), None)
    if target is None:
        raise HTTPException(status_code=400, detail="Unknown network")
    if target.get("purpose") == "wan":
        raise HTTPException(status_code=400, detail="Cannot isolate a WAN")

    changes = P.network_changes_needed(target, req.preset)
    name = target.get("name") or "network"

    if not changes:
        return IsolateResponse(
            dry_run=req.dry_run, changes={},
            note=f"{name} is already set that way — nothing to change.",
        )

    if req.dry_run:
        return IsolateResponse(dry_run=True, changes=changes)

    if not await client.set_network_flags(req.network_id, **changes):
        return IsolateResponse(
            dry_run=False, changes={},
            error=f"Could not update {name}; no settings were changed.",
        )

    return IsolateResponse(dry_run=False, changes=changes)


@router.post("/release-network", response_model=IsolateResponse)
async def release_network(req: IsolateRequest):
    """
    Undo network isolation: reachable again, with internet.

    Only flips flags that are currently set the isolating way, so a network
    the user had already configured themselves is left alone.
    """
    client, err = await _client_or_error()
    if err:
        return IsolateResponse(dry_run=req.dry_run, error=err)

    try:
        networks = await client.get_networks()
    except Exception as e:
        return IsolateResponse(dry_run=req.dry_run, error=str(e))

    target = next((n for n in networks if n.get("_id") == req.network_id), None)
    if target is None:
        raise HTTPException(status_code=400, detail="Unknown network")

    wanted = P.network_flags_to_release()
    changes = {
        k: v for k, v in wanted.items() if bool(target.get(k)) != bool(v)
    }
    name = target.get("name") or "network"

    if not changes:
        return IsolateResponse(
            dry_run=req.dry_run, changes={},
            note=f"{name} is not isolated.",
        )
    if req.dry_run:
        return IsolateResponse(dry_run=True, changes=changes)

    if not await client.set_network_flags(req.network_id, **changes):
        return IsolateResponse(
            dry_run=False, changes={},
            error=f"Could not update {name}.",
        )
    return IsolateResponse(dry_run=False, changes=changes)


@router.post("/dns-lockdown", response_model=DnsLockdownResponse)
async def dns_lockdown(req: DnsLockdownRequest):
    """
    Force chosen networks to use only approved resolvers.

    The allow rule must evaluate before the blocks, or the networks lose DNS
    entirely. Creation order is respected by the controller, but the stored
    index is not always the one we send — so after applying, the real order is
    verified and the whole set rolled back if the allow did not land first.
    """
    client, err = await _client_or_error()
    if err:
        return DnsLockdownResponse(dry_run=req.dry_run, error=err)

    if not req.network_ids:
        raise HTTPException(status_code=400, detail="Select at least one network")
    if not req.resolver_ips:
        raise HTTPException(status_code=400, detail="Add at least one approved resolver")

    try:
        zones = await client.get_firewall_zones()
        existing = await client.get_firewall_policies()
        networks = await client.get_networks()
    except Exception as e:
        return DnsLockdownResponse(dry_run=req.dry_run, error=str(e))

    internal_id, external_id = _zone_ids(zones)
    if not internal_id or not external_id:
        return DnsLockdownResponse(
            dry_run=req.dry_run,
            error="Could not find Internal and External zones on this console",
        )

    chosen = [n for n in networks if n.get("_id") in req.network_ids]
    if not chosen:
        raise HTTPException(status_code=400, detail="Unknown network")
    label = ", ".join(n.get("name") or "network" for n in chosen)

    # Scope the rules to the zone the chosen networks are ACTUALLY in, read
    # off each network's firewall_zone_id — not assumed to be Internal. A
    # custom-zone network locked with Internal-pair rules would get policies
    # its traffic never crosses: silent non-protection.
    by_zone: Dict[str, List[str]] = {}
    for n in chosen:
        zid = P.zone_of_network(n, zones) or internal_id
        by_zone.setdefault(zid, []).append(n.get("name") or "network")
    if len(by_zone) > 1:
        parts = "; ".join(
            f"{P.zone_name(zones, z)}: {', '.join(names)}"
            for z, names in by_zone.items()
        )
        return DnsLockdownResponse(
            dry_run=req.dry_run,
            error=("These networks sit in different firewall zones "
                   f"({parts}). Firewall rules are scoped to one zone pair, "
                   "so apply a separate DNS lockdown per zone instead."),
        )
    client_zone_id = next(iter(by_zone))

    # Refuse to stack a second lockdown on a network that already has one.
    # Without this the same set could be written twice — it was, on the bench
    # console, leaving 10 rules where 5 are correct.
    already = P.dns_locked_network_ids(P.find_ours(existing))
    clashes = [
        f"{n.get('name') or 'network'} (already covered by \"{already[n['_id']]}\")"
        for n in chosen if n.get("_id") in already
    ]
    if clashes:
        return DnsLockdownResponse(
            dry_run=req.dry_run,
            error=("Already locked down: " + "; ".join(clashes) +
                   ". Release the existing lockdown first, or pick different "
                   "networks — applying a second set over the first leaves "
                   "duplicate rules that both have to be cleaned up."),
        )

    # A resolver living on one of the locked-down networks cannot be reached
    # through the gateway, so the rules would never see that traffic.
    unreachable = []
    for n in chosen:
        for ip in req.resolver_ips:
            if P._ip_in_subnet(ip, n.get("ip_subnet")):
                unreachable.append(f"{ip} is on {n.get('name')} itself")

    # A resolver has to be allowed in the zone pair it is actually reached
    # through. Splitting them is what stops a public resolver like 1.1.1.1
    # from being allowed on the LAN side while the internet block kills it.
    lan_resolvers, wan_resolvers, foreign_resolvers = P.classify_resolvers(
        req.resolver_ips, networks, zones, client_zone_id
    )

    try:
        indexes = P.next_free_index(
            existing,
            P.dns_policy_count(
                req.block_dot, bool(lan_resolvers), bool(wan_resolvers)
            ),
        )
        payloads = P.build_dns_lockdown(
            network_ids=req.network_ids,
            network_label=label,
            lan_resolvers=lan_resolvers,
            wan_resolvers=wan_resolvers,
            client_zone_id=client_zone_id,
            external_zone_id=external_id,
            indexes=indexes,
            block_dot=req.block_dot,
            foreign_resolvers=foreign_resolvers,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # The likeliest self-inflicted outage: DHCP still advertising a resolver
    # these rules are about to block. Leads the caveats because it is the one
    # that actually breaks the network.
    caveats = P.dhcp_dns_conflicts(chosen, req.resolver_ips)
    caveats += [
        f"{u} — traffic to it never passes the gateway, so these rules cannot "
        f"police it." for u in unreachable
    ]
    caveats += list(P.DNS_CAVEATS)
    if wan_resolvers:
        caveats.append(
            f"{', '.join(wan_resolvers)} "
            + ("is" if len(wan_resolvers) == 1 else "are")
            + " out on the internet, so "
            + ("it gets" if len(wan_resolvers) == 1 else "they get")
            + " its own allow rule on the internet side. Queries to "
            + ("it" if len(wan_resolvers) == 1 else "them")
            + " leave your network in the clear, as ordinary DNS always does."
        )
    if client_zone_id != internal_id:
        caveats.append(
            f"These networks sit in the \"{P.zone_name(zones, client_zone_id)}\" "
            "firewall zone, so the rules are scoped to that zone's pairs "
            "rather than Internal's."
        )
    for f in foreign_resolvers:
        caveats.append(
            f"{f['ip']} lives on {f['network']} in the "
            f"\"{P.zone_name(zones, f['zone_id'])}\" zone — a different zone "
            "than the locked networks. No rule is needed (or written) for it: "
            "these rules do not block that zone pair at all, which also means "
            "every OTHER DNS server in that zone stays reachable too."
        )
    others = P.other_lan_zones(zones, client_zone_id)
    if others:
        names = ", ".join(f"\"{z.get('name') or 'unnamed'}\"" for z in others)
        caveats.append(
            f"This console has more LAN zones than just the locked networks' "
            f"own ({names}). These rules cover the "
            f"\"{P.zone_name(zones, client_zone_id)}\" and External pairs "
            "only, so a DNS server on a network in those other zones would "
            "still be reachable."
        )

    if req.dry_run:
        return DnsLockdownResponse(dry_run=True, payloads=payloads, caveats=caveats)

    created = []

    async def roll_back():
        for done in created:
            pid = done.get("_id")
            if pid:
                await client.delete_firewall_policy(pid)

    for payload in payloads:
        result = await client.create_firewall_policy(payload)
        if result is None:
            await roll_back()
            return DnsLockdownResponse(
                dry_run=False,
                error=f"Failed to create {payload.get('name')!r}; rolled back.",
            )
        created.append(result)

    # A foreign-zone-only resolver set legitimately creates no allow, so the
    # no-allow trip in the safety check must not roll that back.
    if not P.dns_order_is_safe(
        created, expect_allow=bool(lan_resolvers or wan_resolvers)
    ):
        await roll_back()
        return DnsLockdownResponse(
            dry_run=False,
            error=(
                "The gateway placed the allow rule after the block rules, which "
                "would have left these networks with no working DNS at all. "
                "Everything was rolled back; nothing changed."
            ),
        )

    return DnsLockdownResponse(dry_run=False, created=created, caveats=caveats)


@router.post("/dns-release", response_model=DnsLockdownResponse)
async def dns_release(label: Optional[str] = None):
    """Remove DNS Lockdown policies. Only ever touches ones we created."""
    client, err = await _client_or_error()
    if err:
        return DnsLockdownResponse(dry_run=False, error=err)

    try:
        all_policies = await client.get_firewall_policies()
    except Exception as e:
        return DnsLockdownResponse(dry_run=False, error=str(e))

    targets = [p for p in P.find_ours(all_policies) if P.is_dns_policy(p)]
    if label:
        wanted = label.strip().lower()
        targets = [p for p in targets
                   if P.dns_label_from_policy(p).strip().lower() == wanted]

    removed = []
    for pol in targets:
        pid = pol.get("_id")
        if pid and await client.delete_firewall_policy(pid):
            removed.append(pol)
    return DnsLockdownResponse(dry_run=False, created=removed)


@router.get("/networks", response_model=List[NetworkInfo])
async def list_networks():
    """
    Networks, for the Networks-tab selectors and the DNS lockdown picker.

    WANs are excluded, and so is any network without a VLAN id — House Arrest
    moves a device into an existing VLAN and never creates one.
    """
    client, err = await _client_or_error()
    if err:
        raise HTTPException(status_code=503, detail=err)

    try:
        networks = await client.get_networks()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    out = []
    for n in networks:
        if n.get("purpose") == "wan" or n.get("vlan") is None:
            continue
        out.append(NetworkInfo(
            id=n.get("_id"),
            name=n.get("name") or "(unnamed)",
            vlan=n.get("vlan"),
            isolation_enabled=n.get("network_isolation_enabled"),
            mdns_enabled=n.get("mdns_enabled"),
            dhcp_dns=P.dhcp_dns_of(n),
            purpose=n.get("purpose"),
        ))
    out.sort(key=lambda x: x.vlan or 0)
    return out


@router.get("/inspect", response_model=InspectionResponse)
async def inspect():
    """
    Read-only audit: is anything actually isolated, or does the predefined
    allow-all make a nominally isolated VLAN reachable anyway?
    """
    client, err = await _client_or_error()
    if err:
        return InspectionResponse(connected=False, error=err)

    try:
        networks = await client.get_networks()
        all_policies = await client.get_firewall_policies()
        zones = await client.get_firewall_zones()
    except Exception as e:
        return InspectionResponse(connected=False, error=str(e))

    allow_all_index = None
    for p in all_policies:
        if p.get("predefined") and p.get("action") == "ALLOW":
            idx = p.get("index")
            if isinstance(idx, int) and (allow_all_index is None or idx > allow_all_index):
                allow_all_index = idx

    # Zone membership is the real isolation story. Several VLANs sitting in one
    # zone reach each other freely by default — separate VLANs are NOT separate
    # security boundaries, and inferring isolation from their existence is the
    # mistake this report exists to prevent.
    net_names = {n.get("_id"): (n.get("name") or "(unnamed)") for n in networks}
    # A LAN is any non-WAN network, including the untagged Default network
    # (vlan is None there) — excluding it undercounts the zone and makes the
    # report say "3 VLANs" when four can reach each other.
    net_is_lan = {
        n.get("_id") for n in networks
        if n.get("purpose") not in ("wan", None) or n.get("vlan") is not None
    }
    zone_findings = []
    for z in zones or []:
        members = [
            net_names.get(nid, nid) for nid in (z.get("network_ids") or [])
            if nid in net_is_lan or nid in net_names
        ]
        lan_members = [
            net_names.get(nid) for nid in (z.get("network_ids") or [])
            if nid in net_is_lan
        ]
        if len(lan_members) > 1:
            zone_findings.append(InspectionFinding(
                severity="warn",
                network=z.get("name") or "(zone)",
                finding=f"{len(lan_members)} VLANs share the {z.get('name')} zone",
                detail=(
                    f"{', '.join(lan_members)} can reach each other by default — "
                    f"traffic inside a zone is allowed unless a policy blocks it. "
                    f"Separate VLANs are not separate security boundaries on their own."
                ),
            ))

    net_models, findings = [], []
    for n in networks:
        purpose = n.get("purpose")
        vlan = n.get("vlan")
        isolation = n.get("network_isolation_enabled")
        mdns = n.get("mdns_enabled")
        name = n.get("name") or "(unnamed)"

        net_models.append(NetworkInfo(
            id=n.get("_id"), name=name, vlan=vlan,
            isolation_enabled=isolation, mdns_enabled=mdns, purpose=purpose,
        ))

        # Only LAN-ish networks can meaningfully be isolated.
        if purpose in ("wan",) or vlan is None:
            continue

        if not isolation:
            findings.append(InspectionFinding(
                severity="warn", network=name,
                finding="Network isolation is off",
                detail=(
                    f"VLAN {vlan} has network_isolation_enabled="
                    f"{isolation!r}. Devices here can reach other networks "
                    f"unless a firewall policy stops them."
                ),
            ))
        if mdns:
            findings.append(InspectionFinding(
                severity="info", network=name,
                finding="mDNS forwarding is on",
                detail=(
                    "Service discovery crosses this boundary, which is often "
                    "wanted (casting) but does leak device presence."
                ),
            ))

    if allow_all_index is not None:
        findings.append(InspectionFinding(
            severity="info", network="(all)",
            finding=f"Predefined allow-all sits at index {allow_all_index}",
            detail=(
                "Any House Arrest policy must sit below this to take effect. "
                f"Policies are written at {P.BASE_INDEX}+."
            ),
        ))

    matrix = IsolationMatrix(**P.build_isolation_matrix(networks, zones))

    return InspectionResponse(
        connected=True, networks=net_models,
        findings=zone_findings + findings,
        matrix=matrix,
        allow_all_index=allow_all_index,
    )


@router.post("/lockdown", response_model=LockdownResponse)
async def lockdown(req: LockdownRequest):
    """
    Apply a lockdown preset. Defaults to a dry run — pass dry_run=false to
    actually write policies to the gateway.
    """
    client, err = await _client_or_error()
    if err:
        return LockdownResponse(dry_run=req.dry_run, error=err)

    if req.preset not in P.PRESETS:
        # This also refuses the removed Quarantine preset — PRESETS is the
        # offered list, and quarantine was taken out of it (see policies.py).
        raise HTTPException(status_code=400, detail=f"Unknown preset: {req.preset}")
    if not req.macs:
        raise HTTPException(status_code=400, detail="At least one MAC is required")

    try:
        zones = await client.get_firewall_zones()
        existing = await client.get_firewall_policies()
        networks = await client.get_networks()
        known_clients = await client.get_known_clients()
    except Exception as e:
        return LockdownResponse(dry_run=req.dry_run, error=str(e))

    internal_id, external_id = _zone_ids(zones)
    if not internal_id or not external_id:
        return LockdownResponse(
            dry_run=req.dry_run,
            error="Could not find Internal and External zones on this console",
        )

    # Scope the rules to the zone the devices are actually in. The only
    # attribution available for a MAC is the known-client record's
    # last_connection_network_id -> that network's firewall_zone_id. That
    # record shares stat/sta's staleness problems, but zone-level attribution
    # is coarser than network-level (the measured misreports swapped VLANs
    # WITHIN the Internal zone), and a lockdown built for the wrong zone is
    # silent non-protection — so a best-effort zone beats a hardcoded one.
    caveats: List[str] = []
    client_zone_id, zone_err = _device_zone(
        req.macs, known_clients, networks, zones, internal_id, caveats
    )
    if zone_err:
        return LockdownResponse(dry_run=req.dry_run, error=zone_err)

    # Same guard as DNS: a second preset over a device that already has one
    # leaves two contradictory rule sets, and the tool would then report
    # whichever it happened to read first.
    arrested = P.arrested_macs(P.find_ours(existing))
    dupes = [
        f"{m} (already under \"{arrested[m.lower()]}\")"
        for m in req.macs if m.lower() in arrested
    ]
    if dupes:
        return LockdownResponse(
            dry_run=req.dry_run,
            error=("Already locked down: " + "; ".join(dupes) +
                   ". Release it first, then apply the new preset."),
        )

    try:
        indexes = P.next_free_index(existing, P.policy_count(req.preset))
        payloads = P.build_lockdown(
            preset=req.preset,
            macs=req.macs,
            device_label=req.label,
            client_zone_id=client_zone_id,
            external_zone_id=external_id,
            indexes=indexes,
            allow_inbound=req.allow_inbound,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # "No LAN" is one block in the device's own zone pair. Where the console
    # has further LAN zones, say out loud that those stay reachable rather
    # than letting the preset name overclaim.
    if req.preset in (P.FULL_LOCKDOWN, P.INTERNET_ONLY):
        others = P.other_lan_zones(zones, client_zone_id)
        if others:
            names = ", ".join(f"\"{z.get('name') or 'unnamed'}\"" for z in others)
            caveats.append(
                f"This console has more LAN zones than the device's own "
                f"({names}). The LAN block covers the "
                f"\"{P.zone_name(zones, client_zone_id)}\" zone pair only, so "
                "networks in those other zones stay reachable from this device."
            )

    if req.dry_run:
        return LockdownResponse(dry_run=True, payloads=payloads, caveats=caveats)

    async def roll_back():
        for done in created:
            pid = done.get("_id")
            if pid:
                await client.delete_firewall_policy(pid)

    created = []
    for payload in payloads:
        result = await client.create_firewall_policy(payload)
        if result is None:
            # Roll back what we already wrote so a half-applied lockdown
            # never survives a failure.
            await roll_back()
            return LockdownResponse(
                dry_run=False, created=[],
                error=f"Failed to create policy {payload.get('name')!r}; rolled back",
            )
        created.append(result)

    # No offered preset relocates the device any more. The Quarantine preset's
    # VLAN move (per-client virtual_network_override) was removed 2026-09-17
    # after it was measured half-applying on a wired client — a lease on the
    # target VLAN but no working L2 (ARP failures to gateway and peers), with
    # the controller reporting contradictory locations. Release still clears
    # any pre-removal override (see release()); only the apply side is gone.
    return LockdownResponse(dry_run=False, created=created, caveats=caveats)


@router.post("/release", response_model=ReleaseResponse)
async def release(req: ReleaseRequest):
    """
    Remove House Arrest policies. Defaults to a dry run.

    Refuses to delete anything that does not carry our marker, including any
    predefined policy, and reports the refusal rather than skipping quietly.
    """
    client, err = await _client_or_error()
    if err:
        return ReleaseResponse(dry_run=req.dry_run, error=err)

    try:
        all_policies = await client.get_firewall_policies()
    except Exception as e:
        return ReleaseResponse(dry_run=req.dry_run, error=str(e))

    by_id = {p.get("_id"): p for p in all_policies if p.get("_id")}

    targets, refused = [], []
    if req.policy_ids:
        for pid in req.policy_ids:
            pol = by_id.get(pid)
            if pol is None:
                refused.append({"policy_id": pid, "reason": "not found"})
            elif not P.is_house_arrest(pol):
                refused.append({
                    "policy_id": pid,
                    "name": pol.get("name"),
                    "reason": "not a House Arrest policy — refusing to delete",
                })
            else:
                targets.append(pol)
    else:
        targets = P.find_ours(all_policies)
        if req.kind == "network":
            targets = [p for p in targets if P.is_network_policy(p)]
        elif req.kind == "device":
            targets = [p for p in targets if not P.is_network_policy(p)]
        if req.label:
            wanted = req.label.strip().lower()

            def _label(p):
                return (
                    P.network_label_from_policy(p) if P.is_network_policy(p)
                    else P._label_from_policy(p)
                )

            targets = [p for p in targets if _label(p).strip().lower() == wanted]

    if req.dry_run:
        return ReleaseResponse(
            dry_run=True,
            would_delete=[
                {"policy_id": p.get("_id"), "name": p.get("name")} for p in targets
            ],
            refused=refused,
        )

    # Clear any VLAN override first. Deleting the policies while the device is
    # still parked in the quarantine network would look like a release but
    # leave the device stranded there.
    stranded = set()
    for pol in targets:
        if P.preset_from_policy(pol) and P.requires_network(P.preset_from_policy(pol)):
            stranded.update(P.policy_macs(pol))

    for mac in stranded:
        if not await client.set_client_network(mac, None):
            refused.append({
                "mac": mac,
                "reason": "could not clear the VLAN override; policies left in place",
            })
            return ReleaseResponse(dry_run=False, deleted=[], refused=refused)

    deleted = []
    for pol in targets:
        pid = pol.get("_id")
        if pid and await client.delete_firewall_policy(pid):
            deleted.append(pid)
        else:
            refused.append({
                "policy_id": pid, "name": pol.get("name"),
                "reason": "delete failed",
            })

    return ReleaseResponse(dry_run=False, deleted=deleted, refused=refused)
