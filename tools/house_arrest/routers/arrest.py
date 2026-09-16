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
    InspectionFinding,
    InspectionResponse,
    IsolateRequest,
    IsolateResponse,
    IsolatedNetwork,
    IsolationMatrix,
    LockdownRequest,
    LockdownResponse,
    NetworkInfo,
    PolicyHealth,
    PrecedenceWarning,
    ReleaseRequest,
    ReleaseResponse,
    StateResponse,
    ZoneInfo,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["house_arrest"])


def _zone_ids(zones: List[Dict]) -> Tuple[Optional[str], Optional[str]]:
    """
    Find the Internal and External zone IDs.

    Zone IDs are per-console, so they are always looked up, never hardcoded.
    """
    internal = external = None
    for z in zones:
        name = (z.get("name") or "").strip().lower()
        if name == "internal":
            internal = z.get("_id")
        elif name == "external":
            external = z.get("_id")
    return internal, external


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
    ours = [p for p in ours_all if not P.is_network_policy(p)]

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
        try:
            flows = await client.get_blocked_flows(all_macs, hours=24)
            totals = P.blocked_counts_by_label(flows, policy_to_label)
            for summary in grouped.values():
                summary.blocked_count = totals.get(summary.label, 0)
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

    return StateResponse(
        connected=True,
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
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    out = []
    for c in known_clients or []:
        mac = (c.get("mac") or "").lower()
        if not mac:
            continue
        live = active.get(mac) or {}
        online = bool(live)
        if online_only and not online:
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

    return [BlockedFlow(**row) for row in P.summarize_blocked(flows, our_ids)]


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


@router.get("/networks", response_model=List[NetworkInfo])
async def list_networks():
    """
    Networks that can be used as a quarantine destination.

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
        raise HTTPException(status_code=400, detail=f"Unknown preset: {req.preset}")
    if not req.macs:
        raise HTTPException(status_code=400, detail="At least one MAC is required")
    if P.requires_network(req.preset) and not req.network_id:
        raise HTTPException(
            status_code=400,
            detail=f"{P.PRESET_LABELS[req.preset]} needs a target network",
        )

    try:
        zones = await client.get_firewall_zones()
        existing = await client.get_firewall_policies()
    except Exception as e:
        return LockdownResponse(dry_run=req.dry_run, error=str(e))

    internal_id, external_id = _zone_ids(zones)
    if not internal_id or not external_id:
        return LockdownResponse(
            dry_run=req.dry_run,
            error="Could not find Internal and External zones on this console",
        )

    try:
        indexes = P.next_free_index(existing, P.policy_count(req.preset))
        payloads = P.build_lockdown(
            preset=req.preset,
            macs=req.macs,
            device_label=req.label,
            client_zone_id=internal_id,
            external_zone_id=external_id,
            indexes=indexes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if req.dry_run:
        return LockdownResponse(dry_run=True, payloads=payloads)

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

    # Presets that relocate the device do it after the policies are in place.
    # set_client_network() verifies the override by re-reading the client, so a
    # move that silently didn't take is reported as a failure rather than shown
    # as a completed quarantine.
    moved_to = None
    move_note = None
    if P.requires_network(req.preset):
        for mac in req.macs:
            if not await client.set_client_network(mac, req.network_id):
                await roll_back()
                return LockdownResponse(
                    dry_run=False, created=[],
                    error=(
                        f"Policies were created but the VLAN override for {mac} "
                        f"could not be written, so the whole lockdown was rolled "
                        f"back. Nothing was left half-applied."
                    ),
                )
        moved_to = req.network_id

        # Writing the override is NOT the same as the device moving.
        #
        # Measured 2026-09-16 on a wired client: the override was written and
        # read back correctly, and the device stayed on its original VLAN and
        # IP for 150s with its session never dropping. A wired client keeps its
        # current VLAN and DHCP lease until it reconnects.
        #
        # So the move is confirmed by watching the client's actual network, not
        # by trusting the write. The override is left in place either way —
        # it takes effect on the next reconnect — but the caller is told
        # plainly that the device has not moved yet.
        move_note = await _confirm_moved(client, req.macs, req.network_id)

    return LockdownResponse(
        dry_run=False, created=created, moved_to=moved_to, move_note=move_note,
    )


async def _confirm_moved(client, macs: List[str], network_id: str) -> Optional[str]:
    """
    Watch for the device actually landing on the target network.

    Returns None once every target has moved, or a human-readable note saying
    what still has not. Deliberately short: a wired device usually will not
    move until it reconnects, and blocking the request for minutes to watch
    something that needs physical action helps nobody.
    """
    import asyncio

    waited = 0.0
    pending = [m.lower() for m in macs]
    while waited < 15.0:
        try:
            active = await client.get_clients()
        except Exception:
            break
        pending = [
            m for m in pending
            if (active.get(m) or {}).get("network_id") != network_id
        ]
        if not pending:
            return None
        await asyncio.sleep(3.0)
        waited += 3.0

    if not pending:
        return None
    return (
        "The VLAN override is saved, but "
        + ("this device has" if len(pending) == 1 else "these devices have")
        + " not moved yet. A connected device keeps its current VLAN and IP "
        "address until it reconnects — unplug and replug it, or reboot it, to "
        "complete the move. The firewall rules are already in force."
    )


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
