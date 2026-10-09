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


def _device_network_ids(
    macs: List[str], known_by_mac: Dict[str, Dict], live: Dict[str, Dict]
) -> List[str]:
    """
    Networks these devices are on: the live record first, then the network
    the controller last saw them on (offline devices). Unattributable MACs
    simply contribute nothing.
    """
    out: List[str] = []
    for mac in macs or []:
        m = mac.lower()
        nid = (live.get(m) or {}).get("network_id") or \
            (known_by_mac.get(m) or {}).get("last_connection_network_id")
        if nid and nid not in out:
            out.append(nid)
    return out


async def _requeue_shadowing_blocks(client) -> Tuple[List[str], List[str]]:
    """
    Re-create any device "no LAN" block that sits ahead of a DNS allow meant
    for that device, so the allow evaluates first.

    MEASURED 2026-10-01 (test B): a DNS Lockdown applied after a device
    lockdown got the next index in the zone pair, landing BEHIND the device's
    block, and the device lost DNS with both tabs green. Policies can't be
    placed by index (the controller assigns it), but creation order is kept,
    so a fresh copy of the block lands after the allow.

    The copy is created and its stored position checked BEFORE the original
    is deleted, so the device is never unprotected in between.

    Returns (labels moved, labels that could not be moved).
    """
    policies = await client.get_firewall_policies()
    try:
        known_by_mac = {(c.get("mac") or "").lower(): c
                        for c in await client.get_known_clients() or []}
        live = await client.get_clients()
    except Exception:
        known_by_mac, live = {}, {}
    moved, failed = [], []
    for block in [p for p in policies if P._blocks_lan_for(p)]:
        nets = _device_network_ids(P.policy_macs(block), known_by_mac, live)
        if not P.shadowed_dns_allows(block, policies, nets):
            continue
        label = P._label_from_policy(block) or "a device"
        idx = P.next_free_index(policies, 1)[0]
        copy = await client.create_firewall_policy(P.recreate_payload(block, idx))
        if copy is None:
            failed.append(label)
            continue
        policies = await client.get_firewall_policies()
        stored = next((p for p in policies if p.get("_id") == copy.get("_id")), copy)
        if P.shadowed_dns_allows(stored, policies, nets):
            # Still behind: keep the original, drop the copy, and report it.
            await client.delete_firewall_policy(copy.get("_id"))
            failed.append(label)
            continue
        await client.delete_firewall_policy(block.get("_id"))
        policies = [p for p in policies if p.get("_id") != block.get("_id")]
        moved.append(label)
    return moved, failed


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

    # Neighbour block (switch ACL pair) per device, and how much of it the
    # switches in the path can actually enforce. A read failure leaves the
    # fields unset rather than implying there is no block.
    if grouped:
        try:
            acl_rules = await client.get_acl_rules()
            devices = await client.get_devices_raw() if acl_rules else []
        except Exception:
            acl_rules, devices = None, []
        for summary in grouped.values():
            state = P.neighbour_block_state(acl_rules or [], summary.macs)
            if not state:
                continue
            summary.neighbours = state
            live = next((active_now.get(m.lower()) for m in summary.macs
                         if active_now.get(m.lower())), None)
            cov = P.client_coverage(live if devices else None, devices, active_now)
            summary.neighbours_coverage = cov["status"]
            summary.neighbours_note = P.coverage_sentence(cov)
            summary.neighbours_dns_note = P.resolver_note(
                P.acl_allowed_resolvers(acl_rules or [], summary.macs, active_now))
            if state != "ok" and summary.status == "ok":
                summary.status = "broken" if state == "broken" else P.DISABLED
                summary.suggestion = (
                    "Part of the neighbour block is missing, which can cut this "
                    "device off from everything, including the internet. "
                    "Release the lockdown and apply it again."
                    if state == "broken" else
                    "The neighbour block's rules are turned off in UniFi "
                    "(Policy Table, ACL Rules). Turn them back on there, or "
                    "release the lockdown and apply it again."
                )

    # A lockdown whose own block sits ahead of a DNS allow meant for the same
    # device is cutting that device's DNS (measured 2026-10-01, test B), even
    # though every rule is present and enabled. Apply-time code prevents it;
    # this catches anything that drifts later, e.g. rules reordered in UniFi.
    if grouped:
        known_by_mac = {(c.get("mac") or "").lower(): c for c in known_clients or []}
        for summary in grouped.values():
            if summary.status != P.OK:
                continue
            nets = _device_network_ids(summary.macs, known_by_mac, active_now)
            mine = [p for p in ours if p.get("_id") in set(summary.policy_ids)]
            if any(P.shadowed_dns_allows(b, all_policies, nets) for b in mine):
                summary.status = P.DNS_BLOCKED
                summary.suggestion = (
                    "This lockdown's block runs before a rule that lets the "
                    "device reach its DNS servers, so the device can't look up "
                    "names. Release the lockdown and apply it again to fix the order.")

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
        if pol.get("enabled") is False:
            entry.disabled_count += 1
        for nid in ((pol.get("source") or {}).get("network_ids") or []):
            if nid not in entry.network_ids:
                entry.network_ids.append(nid)
        dest = pol.get("destination") or {}
        if pol.get("action") == "ALLOW" and dest.get("ips"):
            entry.resolvers = list(dest.get("ips"))
        if dest.get("port") == P.DOT_PORT:
            entry.blocks_dot = True

    # A lockdown is only ever created with at least one network, so an empty
    # or entirely unknown list means its networks were deleted. Skipped when
    # the network read failed: unknown is not missing.
    if all_networks:
        live_ids = {n.get("_id") for n in all_networks}
        for entry in dns_by_label.values():
            if not any(nid in live_ids for nid in entry.network_ids):
                entry.network_missing = True

    # Gateway-level DNS interception signals for the DNS tab. Each read is
    # independent and failure means unknown (None / empty), never "off".
    encrypted_dns_on = None
    ad_blocking_on = None
    content_filtered = []
    try:
        doh = await client.get_site_setting("doh")
        if doh is not None and doh.get("state") is not None:
            encrypted_dns_on = doh.get("state") != "off"
    except Exception:
        pass
    try:
        ips_setting = await client.get_site_setting("ips")
        if ips_setting is not None:
            ad_blocking_on = bool(ips_setting.get("ad_blocking_enabled"))
    except Exception:
        pass
    try:
        content_filtered = P.content_filtered_ids(await client.get_content_filters())
    except Exception:
        pass

    try:
        switch_acl_supported = P.site_acl_capable(await client.get_devices_raw())
    except Exception:
        switch_acl_supported = None

    return StateResponse(
        connected=True,
        switch_acl_supported=switch_acl_supported,
        encrypted_dns_on=encrypted_dns_on,
        ad_blocking_on=ad_blocking_on,
        content_filtered_network_ids=content_filtered,
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
    try:
        devices = await client.get_devices_raw()
    except Exception:
        devices = []
    try:
        gs = await client.get_site_setting("global_switch")
        di_ids = set(str(i) for i in (gs or {}).get("acl_device_isolation") or []) if gs else None
    except Exception:
        di_ids = None
    nets_by_id = {n.get("_id"): n for n in networks if n.get("_id")}
    try:
        zones = await client.get_firewall_zones()
        policies = await client.get_firewall_policies()
        holes_by_net = {
            nid: len(P.isolation_exceptions(n, zones, policies, active))
            for nid, n in nets_by_id.items() if n.get(P.NET_FLAG_ISOLATION)
        }
    except Exception:
        holes_by_net = {}

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
        # Offline devices have no attachment point, and an empty device list
        # means the read failed: both are "unknown", never "not covered".
        cov = P.client_coverage(live if (live and devices) else None, devices, active)
        # Offline devices: fall back to the network the controller last saw.
        net_id = live.get("network_id") or c.get("last_connection_network_id")
        net = nets_by_id.get(net_id) or {}
        found, missing = P.same_network_resolvers(net or None, active)
        found = [r for r in found if r["mac"] != mac]
        if missing:
            dns_note = ("This device's network hands out " + ", ".join(missing) + " for DNS, "
                        "which is on the same network, but UniFi doesn't currently "
                        "know that device's MAC address. The neighbour block can't "
                        "be applied until it does, or this device would lose DNS.")
        else:
            dns_note = P.resolver_note(found)
        out.append(ClientInfo(
            mac=mac,
            name=c.get("name") or c.get("hostname") or "",
            ip=live.get("ip"),
            network=live.get("network"),
            online=online,
            fixed_ip=c.get("fixed_ip") if c.get("use_fixedip") else None,
            locally_administered=P.is_locally_administered(mac),
            essid=live.get("essid"),
            is_wired=live.get("is_wired"),
            neighbour_coverage=cov["status"],
            neighbour_coverage_note=P.coverage_sentence(cov),
            neighbour_dns_note=dns_note,
            network_isolated=bool(net.get(P.NET_FLAG_ISOLATION)) if net else None,
            network_internet_off=(net.get(P.NET_FLAG_INTERNET) is False) if net else None,
            network_device_isolation=(net_id in di_ids) if (net and di_ids is not None) else None,
            network_isolation_exceptions=holes_by_net.get(net_id, 0),
        ))
    out.sort(key=lambda x: (not x.online, (x.name or "zzz").lower()))
    return out


@router.get("/wlans", response_model=List[WlanInfo])
async def list_wlans():
    """
    SSIDs with their client-isolation state and how many clients each carries.

    One of the controls over same-VLAN peer traffic, alongside switch ACLs
    (Device Isolation, the per-device neighbour block). A firewall policy
    never sees that traffic, and switch ACLs miss two Wi-Fi devices on the
    same AP, so this is the one that covers that case.
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

    # Device Isolation (switch ACL) is the same shape as mDNS: ONE site-wide
    # list (`global_switch.acl_device_isolation`), so the toggle adds or
    # removes this network from it. Measured writable 2026-09-29.
    if req.column == "device_isolation":
        current_doc = await client.get_site_setting("global_switch")
        if current_doc is None:
            raise HTTPException(
                status_code=502,
                detail=("House Arrest couldn't read the Device isolation setting "
                        "from the controller, so nothing was changed."),
            )
        if req.value:
            try:
                devices = await client.get_devices_raw()
            except Exception:
                devices = []
            if P.site_acl_capable(devices) is False:
                raise HTTPException(
                    status_code=409,
                    detail=P.NOT_SUPPORTED_DETAIL + " Nothing was changed.")
        current = [str(i) for i in current_doc.get("acl_device_isolation") or []]
        wanted = [i for i in current if i != req.network_id]
        if req.value:
            wanted.append(req.network_id)
        if sorted(wanted) == sorted(current):
            return {"ok": True, "field": "acl_device_isolation", "value": req.value}
        if not await client.set_device_isolation_networks(wanted):
            raise HTTPException(
                status_code=502,
                detail=("The controller didn't confirm the Device isolation "
                        "change, so House Arrest can't tell whether it was "
                        "applied. Check it in UniFi under Settings > Networks > "
                        "Device Isolation (ACL)."),
            )
        return {"ok": True, "field": "acl_device_isolation", "value": req.value}

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
        f"{u} is on the same network as the devices it would serve, so "
        f"traffic to {u} never passes the gateway and DNS Lockdown can't "
        f"control it." for u in unreachable
    ]
    caveats += list(P.DNS_CAVEATS)
    if wan_resolvers:
        caveats.append(
            f"{', '.join(wan_resolvers)} "
            + ("is" if len(wan_resolvers) == 1 else "are")
            + " on the internet, so DNS Lockdown adds a separate allow rule "
              "on the internet side for "
            + ("that DNS server" if len(wan_resolvers) == 1 else "those DNS servers")
            + ". DNS queries to "
            + ("it" if len(wan_resolvers) == 1 else "them")
            + " leave your network unencrypted, as ordinary DNS always does."
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
            f"\"{P.zone_name(zones, f['zone_id'])}\" zone, a different zone "
            "than the locked networks. DNS Lockdown doesn't need or write a rule "
            "for that DNS server, because its rules don't cover that zone at "
            "all. That also means every other DNS server in that zone stays "
            "reachable."
        )
    try:
        caveats += P.dns_interception_caveats(
            await client.get_site_setting("doh"),
            await client.get_site_setting("ips"),
            await client.get_content_filters(),
            req.network_ids,
            {n.get("_id"): (n.get("name") or "network") for n in networks},
        )
    except Exception as e:
        logger.warning(f"Could not read DNS interception settings: {e}")

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

    # A device lockdown applied earlier on these networks would now sit ahead
    # of the new allow and cut its DNS (measured, test B). Move those blocks
    # behind it.
    try:
        moved, failed = await _requeue_shadowing_blocks(client)
    except Exception as e:
        moved, failed = [], [f"(couldn't check: {e})"]
    notices: List[str] = []
    if moved:
        notices.append(
            "Re-created the device lockdown for " + ", ".join(moved) + " so this "
            "DNS Lockdown's allow rule runs first and those devices keep their DNS.")
    if failed:
        notices.append(
            "Couldn't move the device lockdown for " + ", ".join(failed) + " behind "
            "this DNS Lockdown, so those devices can't reach the approved DNS "
            "servers. Release that lockdown on the Devices tab and apply it again.")

    return DnsLockdownResponse(dry_run=False, created=created, caveats=caveats,
                               notices=notices, notices_failed=bool(failed))


@router.post("/dns-release", response_model=DnsLockdownResponse)
async def dns_release(label: Optional[str] = None):
    """Remove DNS Lockdown policies. Only ever touches ones we created."""
    # No label used to mean "every DNS Lockdown", deleted immediately with no
    # dry run. The UI always sends one; refuse the unscoped call.
    if not (label or "").strip():
        return DnsLockdownResponse(
            dry_run=False,
            error="Name the DNS Lockdown to release (label). Releasing every "
                  "DNS Lockdown at once is refused.")
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

    WANs are excluded. Untagged networks (vlan is None — usually Default) are
    INCLUDED: the old exclusion was a leftover from the removed Quarantine
    preset, whose picker chose VLAN move targets. It silently kept the
    Default network out of DNS Lockdown (found on the NOMAD2 console, where
    Default is the primary network).
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
        if n.get("purpose") == "wan":
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

    # Device Isolation is a site-level list, and whether it does anything
    # depends on which switches each device's traffic crosses. Every read is
    # independent; a failure means "unknown", never "off" or "not covered".
    di_ids = None
    coverage = None
    acl_supported = None
    live: Dict = {}
    try:
        gs = await client.get_site_setting("global_switch")
        if gs is not None:
            di_ids = [str(i) for i in gs.get("acl_device_isolation") or []]
    except Exception:
        di_ids = None
    try:
        devices = await client.get_devices_raw()
        live = await client.get_clients()
        acl_supported = P.site_acl_capable(devices)
        if devices:
            coverage = {
                n.get("_id"): P.network_isolation_coverage(n.get("_id"), live, devices)
                for n in networks if n.get("_id")
            }
    except Exception:
        coverage = None

    holes = {
        n.get("_id"): P.isolation_exceptions(n, zones, all_policies, live)
        for n in networks
        if n.get("_id") and n.get("network_isolation_enabled")
    }

    matrix = IsolationMatrix(**P.build_isolation_matrix(
        networks, zones, device_isolation_ids=di_ids, coverage=coverage,
        switch_acl_supported=acl_supported, isolation_exceptions=holes))

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
        live = await client.get_clients()
    except Exception:
        live = {}
    known_by_mac = {(c.get("mac") or "").lower(): c for c in known_clients or []}
    nets_by_id = {n.get("_id"): n for n in networks if n.get("_id")}
    device_net_ids = _device_network_ids(req.macs, known_by_mac, live)

    # Internet only keeps the DNS servers its network hands out on other
    # VLANs (measured 2026-10-01: the "no LAN" block cut them). The allow is
    # created FIRST so it lands ahead of the block; the order is verified
    # after creation.
    dns_ips: List[str] = []
    if req.preset == P.INTERNET_ONLY:
        dns_ips, skipped = P.device_dns_resolvers(
            [nets_by_id[n] for n in device_net_ids if n in nets_by_id],
            networks, zones, client_zone_id)
        dns_locked = P.dns_locked_network_ids(existing)
        for nid in skipped:
            if nid not in dns_locked:
                name = (nets_by_id.get(nid) or {}).get("name") or "This device's network"
                caveats.append(
                    f"{name} is isolated and hands out a DNS server on another "
                    "network. Isolation already blocks that, so this device has no "
                    "DNS unless you add a DNS Lockdown for that network on the DNS "
                    "Lockdown tab, which allows it.")
        if dns_ips:
            caveats.append(
                "DNS keeps working: this device can still reach " + ", ".join(dns_ips) +
                " on port 53, the DNS servers its network hands out. Nothing "
                "else on your network is reachable.")

    try:
        count = P.policy_count(req.preset) + (1 if dns_ips else 0)
        indexes = P.next_free_index(existing, count)
        payloads = []
        if dns_ips:
            payloads.append(P.build_device_dns_allow(
                req.macs, req.label, client_zone_id, dns_ips, indexes[0]))
            indexes = indexes[1:]
        payloads += P.build_lockdown(
            preset=req.preset,
            macs=req.macs,
            device_label=req.label,
            client_zone_id=client_zone_id,
            external_zone_id=external_id,
            indexes=indexes,
            # Fixed by the preset since 2026-10-02 (the checkbox was removed):
            # Quarantine lets nothing in, every other preset still answers.
            allow_inbound=P.inbound_for(req.preset),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # "No LAN" is one block in the device's own zone pair. Where the console
    # has further LAN zones, say out loud that those stay reachable rather
    # than letting the preset name overclaim.
    if req.preset in (P.CUT_OFF, P.FULL_LOCKDOWN, P.INTERNET_ONLY):
        others = P.other_lan_zones(zones, client_zone_id)
        if others:
            names = ", ".join(f"\"{z.get('name') or 'unnamed'}\"" for z in others)
            caveats.append(
                f"This console has more LAN zones than the device's own "
                f"({names}). The LAN block covers the "
                f"\"{P.zone_name(zones, client_zone_id)}\" zone pair only, so "
                "networks in those other zones stay reachable from this device."
            )

    # Neighbour block: a switch-ACL pair per network the devices sit on.
    # Quarantine always applies it; Internet only applies it when ticked.
    # Built here (before the dry-run return) so the preview shows it.
    #
    # A failure is handled by who asked for it. Ticked on Internet only, it is
    # an error: the user chose it and should know it can't be done. Part of
    # Quarantine, the rest of the lockdown still applies and the caveat says
    # plainly that neighbours can still reach the device.
    acl_payloads: List[Dict] = []
    always = req.preset in P.NEIGHBOUR_ALWAYS_PRESETS
    if req.block_neighbours and req.preset not in P.NEIGHBOUR_BLOCK_PRESETS:
        raise HTTPException(
            status_code=400,
            detail="The neighbour block is only available with Quarantine and Internet only.",
        )
    want_neighbours = always or req.block_neighbours
    neighbour_problem: Optional[str] = None
    verdicts: Dict[str, Dict] = {}
    if want_neighbours:
        try:
            acl_rules = await client.get_acl_rules()
            devices = await client.get_devices_raw()
        except Exception as e:
            return LockdownResponse(dry_run=req.dry_run, error=str(e))
        by_network: Dict[str, List[str]] = {}
        unplaced = []
        for mac in req.macs:
            m = mac.lower()
            nid = (live.get(m) or {}).get("network_id") or                 (known_by_mac.get(m) or {}).get("last_connection_network_id")
            if nid:
                by_network.setdefault(nid, []).append(m)
            else:
                unplaced.append(m)
        if acl_rules is None or not devices:
            neighbour_problem = ("House Arrest couldn't read your switches from the "
                                 "controller, so the neighbour block can't be set up "
                                 "safely.")
        elif P.site_acl_capable(devices) is False:
            neighbour_problem = ("None of your UniFi switches support the neighbour "
                                 "block. For Wi-Fi devices, use Wi-Fi client "
                                 "isolation instead.")
        else:
            verdicts = {m.lower(): P.client_coverage(live.get(m.lower()), devices, live)
                        for m in req.macs}
            if all(v["status"] == P.NOT_COVERED for v in verdicts.values()):
                neighbour_problem = ("None of the selected devices are connected "
                                     "through a switch that supports the neighbour "
                                     "block.")
            elif P.neighbour_acls_for(acl_rules, req.macs):
                return LockdownResponse(
                    dry_run=req.dry_run,
                    error=("A neighbour block already exists for this device. Release "
                           "it first, then apply again."),
                )
            elif unplaced:
                neighbour_problem = ("House Arrest couldn't tell which network "
                                     + ", ".join(unplaced) + " is on, so its "
                                     "neighbours can't be blocked. Bring the device "
                                     "online and try again.")
        # DNS servers on the device's own VLAN go in the ALLOW beside the
        # gateway, for Internet only (measured 2026-10-01: without this the
        # neighbour block cut a same-VLAN Pi-hole). Quarantine has no
        # internet, so a hole to a resolver would only be an opening.
        resolver_macs: Dict[str, List[str]] = {}
        if not neighbour_problem and req.preset == P.INTERNET_ONLY:
            for nid in by_network:
                found, missing = P.same_network_resolvers(nets_by_id.get(nid), live)
                if missing:
                    return LockdownResponse(
                        dry_run=req.dry_run,
                        error=("This device's network hands out "
                               + ", ".join(missing)
                               + " for DNS, which is on the same network, but UniFi "
                                 "doesn't currently know that device's MAC address "
                                 "(it may be offline). The neighbour block would cut "
                                 "this device off from it, and websites and apps "
                                 "would stop loading by name. Bring that DNS server "
                                 "online and try again, or untick the neighbour block."),
                    )
                resolver_macs[nid] = [r["mac"] for r in found]
                note = P.resolver_note(found)
                if note:
                    caveats.append(note)
        if neighbour_problem and not always:
            return LockdownResponse(
                dry_run=req.dry_run,
                error=neighbour_problem + " Untick the neighbour block and apply again.",
            )
        if neighbour_problem:
            caveats.append(
                "The neighbour block isn't part of this Quarantine. "
                + neighbour_problem
                + " Other devices on the same network can still reach this device.")
        else:
            gw_macs = P.gateway_lan_macs(devices)
            acl_indexes = P.next_acl_indexes(acl_rules, 2 * len(by_network))
            try:
                for i, (nid, macs) in enumerate(sorted(by_network.items())):
                    acl_payloads.extend(P.build_neighbour_acls(
                        macs, nid, gw_macs, req.label, acl_indexes[2 * i: 2 * i + 2],
                        resolver_macs=resolver_macs.get(nid)))
            except ValueError as e:
                return LockdownResponse(dry_run=req.dry_run, error=str(e))
            caveats.extend(P.NEIGHBOUR_CAVEATS)
            for mac in req.macs:
                cov = verdicts[mac.lower()]
                who = req.label or mac
                caveats.append(
                    f"{who} ({P.COVERAGE_LABELS[cov['status']].lower()}): "
                    f"{P.coverage_sentence(cov)}")

    # The preset's measured caveats travel with every preview and result, so
    # the review step shows them beside everything else this lockdown does.
    caveats = caveats + P.caveats_for(req.preset)

    if req.dry_run:
        return LockdownResponse(
            dry_run=True, payloads=payloads + acl_payloads, caveats=caveats)

    async def roll_back():
        for done in created:
            pid = done.get("_id")
            if pid:
                await client.delete_firewall_policy(pid)
        for done in acl_created:
            rid = done.get("_id")
            if rid:
                await client.delete_acl_rule(rid)

    created = []
    acl_created: List[Dict] = []
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

    # The DNS allow was created first so it should sit ahead of the block. The
    # controller assigns stored indexes itself, so check what it stored rather
    # than trusting creation order; a lockdown that cuts its own DNS is the
    # bug this exists to prevent.
    if dns_ips:
        try:
            stored = {p.get("_id"): p for p in await client.get_firewall_policies()}
        except Exception:
            stored = {}
        mine = [stored.get(c.get("_id"), c) for c in created]
        blocks = [p for p in mine if P._blocks_lan_for(p)]
        allows = [p for p in mine if P.is_device_dns_allow(p)]
        if any(P.shadowed_dns_allows(b, allows, device_net_ids) for b in blocks) or not allows:
            await roll_back()
            return LockdownResponse(
                dry_run=False, created=[],
                error=("The gateway placed this device's DNS rule after its block, "
                       "which would cut its DNS, so House Arrest undid the "
                       "lockdown. Try applying it again."),
            )

    # ALLOW is always written before its BLOCK (payload order), so a failure
    # can never leave a lone BLOCK behind — which would cut the device off
    # from the gateway entirely.
    for payload in acl_payloads:
        result = await client.create_acl_rule(payload)
        if result is None:
            await roll_back()
            return LockdownResponse(
                dry_run=False, created=[],
                error=("House Arrest couldn't set up the neighbour block, so it "
                       "undid the whole lockdown."),
            )
        acl_created.append(result)
    created.extend(acl_created)

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
    scope_err = P.release_scope_error(req.kind, req.label, req.policy_ids)
    if scope_err:
        return ReleaseResponse(dry_run=req.dry_run, error=scope_err)

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
        targets = P.release_targets(all_policies, req.kind, req.label)

    # Neighbour-block ACLs belong to device lockdowns. Matched by the devices'
    # MACs and, for a label release, by name too (catches an ACL whose
    # firewall half was already removed). is_house_arrest_acl() still gates
    # every match, so nothing UniFi generated is ever touched.
    acl_targets: List[Dict] = []
    if req.kind != "network":
        device_macs = sorted({m for p in targets
                              if not P.is_network_policy(p) and not P.is_dns_policy(p)
                              for m in P.policy_macs(p)})
        acl_rules = await client.get_acl_rules()
        if acl_rules is None and device_macs:
            refused.append({"reason": "could not read switch ACL rules; any "
                                      "neighbour block was left in place"})
        for r in acl_rules or []:
            by_mac = bool(set(device_macs) & set(P.acl_source_macs(r)))
            by_name = bool(req.label) and r.get("name") == P.acl_rule_name(req.label)
            if P.is_house_arrest_acl(r) and (by_mac or by_name):
                acl_targets.append(r)
        # A partial release must never leave a lone BLOCK: take the ALLOW
        # only after its BLOCK, by deleting BLOCKs first below.
        acl_targets.sort(key=lambda r: 0 if r.get("action") == "BLOCK" else 1)

    if req.dry_run:
        return ReleaseResponse(
            dry_run=True,
            would_delete=[
                {"policy_id": p.get("_id"), "name": p.get("name")} for p in targets
            ] + [
                {"policy_id": r.get("_id"), "name": r.get("name") + " (switch rule)"}
                for r in acl_targets
            ],
            refused=refused,
        )

    acl_deleted: List[str] = []
    for r in acl_targets:
        rid = r.get("_id")
        if rid and await client.delete_acl_rule(rid):
            acl_deleted.append(rid)
        else:
            refused.append({"policy_id": rid, "name": r.get("name"),
                            "reason": "switch rule delete failed"})
            if r.get("action") == "BLOCK":
                # Stop before touching its ALLOW — a lone BLOCK cuts the
                # device off from the gateway.
                return ReleaseResponse(dry_run=False, deleted=acl_deleted, refused=refused)

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

    deleted = list(acl_deleted)
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
