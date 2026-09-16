# House Arrest — Design Document

**Status:** implemented and verified end to end (`tools/house_arrest/`, mounted at `/arrest`)
**Last updated:** 2026-09-15
**API research:** complete (probed live against UCG-Fiber, UniFi OS)
**End-to-end tested:** yes — against a wired Raspberry Pi (`testclient`, dc:a6:32:08:36:42) on 2026-09-15

## What it is

A UniFi Toolkit tool that locks a chosen device down: choose how to restrict its
LAN and WAN access, with named exceptions. Matching is by MAC, so wired and
wireless devices are covered identically (the end-to-end test used a wired Pi). Plus an audit mode that reports whether existing IoT VLANs
are actually isolated or only look like it.

Naming follows the Wi-Fi Stalker / Threat Watch / Network Pulse pattern.

Mechanism: UniFi's zone-based firewall (ZBF) policies. The tool writes custom
policies that evaluate ahead of the predefined allow-all rule.

## Evidence tiers

Claims below are marked **[Measured]** (read live from the controller, date given),
**[Read]** (found in this codebase, path given), or **[Inferred]** (reasoning, not
yet verified). Do not build on an [Inferred] claim without testing it first.

---

## Confirmed API behavior

### Endpoints

| Purpose | Method + path |
|---|---|
| List / create firewall policies | `/proxy/network/v2/api/site/{site}/firewall-policies` |
| List zones | `/proxy/network/v2/api/site/{site}/firewall/zone` |
| Networks (VLANs) | `/proxy/network/api/s/{site}/rest/networkconf` |
| Known clients | `/proxy/network/api/s/{site}/rest/user` |
| Active clients | `/proxy/network/api/s/{site}/stat/sta` |
| Write client (fixed IP, name) | `PUT /proxy/network/api/s/{site}/rest/user/{_id}` |

The client write path already exists in this repo as `set_client_name()` —
`shared/unifi_client.py:795`. **[Read]**

### Source: per-device matching works

**[Measured 2026-09-10]** A policy created in the UI with a single client as source:

```json
"source": {
  "matching_target": "CLIENT",
  "client_macs": ["ba:66:5c:5c:2b:36"],
  "zone_id": "<internal zone id>"
}
```

`client_macs` is an **array** — one policy can lock down several devices at once.
This is the core of the tool, and it means **the locked-down device needs no DHCP
reservation.** Matching is by MAC, not IP.

> Note: this test policy has since been deleted from the console. As of 2026-09-15
> the live config has 0 policies using MAC matching, so there is no example left to
> read back. The finding stands; the evidence is this document.

### Destination: IP only, no device option

**[Measured 2026-09-15]** The UI offers Any / Network / IP as destination — there is
**no** device/client option. A destination policy looks like:

```json
"destination": {
  "matching_target": "IP",
  "matching_target_type": "SPECIFIC",
  "ips": ["192.168.107.133"],
  "port": "8123",
  "port_matching_type": "SPECIFIC",
  "zone_id": "<internal zone id>"
}
```

`ips` is an array, so one rule can name several destinations.

**This reverses an earlier decision.** On 2026-09-10 fixed-IP support was deferred as
"not load-bearing." That was correct for the lockdown core (source-side, MAC-matched)
and **wrong** for the inbound exception. Reaching a locked-down device from the LAN
requires targeting it by IP, which requires a DHCP reservation. Fixed-IP handling is
back in scope. Do not re-derive the deferral from older notes.

### Other confirmed fields

**[Measured]**

| Field | Value | Meaning |
|---|---|---|
| `create_allow_respond` | `true` | asymmetric direction — allow the reply without allowing the reverse initiation |
| `index` | `10000+` | lands below the predefined allow-all at `2147483647` — but see the correction below: the controller, not us, decides the stored value |
| `predefined` | `false` | marks a user-created policy; never touch `predefined: true` ones |
| `schedule.mode` | `"ALWAYS"` | no time restriction |
| `ip_version` | `"BOTH"` | v4 + v6 |
| `virtual_network_override_id` | network id | optionally moves a client into an **existing** VLAN |
| `network_isolation_enabled`, `mdns_enabled` | bool | per-network, read for the audit report |

Zone ids are per-console and must be looked up from `/firewall/zone` at runtime —
never hardcode them.

### CORRECTION: we do not control the policy index

**[Measured 2026-09-15, live test]** The original note said House Arrest writes
policies "at `index: 10000+`" as though it chose the position. It does not.
Indexes sent as **10004/10005 were stored as 10000/10003**, colliding with an
existing user policy (`Madelena to n8n` at 10000). The controller assigns the
stored index itself.

Consequences:

* The rules still land far below the predefined allow-all, so lockdowns do take
  effect — this was verified end to end.
* But House Arrest **cannot place its rules relative to the user's own**. A
  user ALLOW at a lower index evaluates first and can override a lockdown.
* `next_free_index()` is therefore a request, not a placement. `check_precedence()`
  reads the stored indexes back and flags any enabled custom ALLOW at or below
  our lowest BLOCK, surfaced as a warning in the UI. It is deliberately
  conservative: it does not try to prove the ALLOW matches the device, only
  that it is consulted first.

### Measured: what survives a "full" lockdown

**[Measured 2026-09-15]** Probed from a real locked-down device, not inferred:

| Path | Under Full lockdown |
|---|---|
| WAN ping / HTTPS | blocked |
| Another VLAN (192.168.107.x) | blocked |
| Same-VLAN peer | **still reachable** (expected — never hits the gateway) |
| The gateway itself | **still reachable** |
| DNS resolution | **still works** |

The last two are not bugs, but they qualify the claim "cut off from the
internet" and are now shown as caveats next to that claim in the UI:

* **The gateway stays reachable.** Neither policy covers the Gateway zone, so
  DHCP and the gateway's own services still answer. That is what keeps the
  device on the network at all, which is the point of house arrest rather than
  a block.
* **DNS still resolves.** On the test network the resolvers (192.168.200.50/.51)
  sit on the device's own VLAN, so queries never reach the gateway and cannot be
  filtered. Those resolvers forward upstream, so a locked-down device still
  resolved `github.com` successfully. A determined device retains a data path
  out over DNS. Moving the resolver off the device's VLAN, or using Quarantine,
  is the answer where that matters.

### Verified behaviour per preset

**[Measured 2026-09-15]** Same probe script before, during and after each preset:

| Preset | WAN | Other VLANs | Same VLAN | Matches the UI's claim? |
|---|---|---|---|---|
| Full lockdown | blocked | blocked | reachable | yes |
| Internet only | reachable | blocked | reachable | yes |
| LAN only | blocked | reachable | reachable | yes |
| (released) | reachable | reachable | reachable | full restoration |

Safety paths also verified live:

* Release **refused** to delete a policy it did not create, reporting the
  refusal rather than skipping silently.
* A lockdown targeting a MAC that is not a known client reported
  **`status: broken` / "Not enforcing"** rather than claiming protection.
* Release removed exactly the policies House Arrest created, leaving the
  three pre-existing custom policies untouched.

---

## Design decisions

### 1. The boundary that matters is IoT ↔ trusted LAN

Same-VLAN peer traffic never reaches the gateway, so the firewall cannot filter it.
That was flagged early as the hardest problem in the feature — and then it stopped
being a problem, because intra-VLAN traffic should keep working anyway (casting,
Home Assistant). The boundary House Arrest enforces is between zones, which is fully
gateway-enforceable.

Consequence: no switch port-isolation capability matrix is needed. (The probe data on
per-port `isolation` fields was inconsistent across switch models anyway.)

### 2. Detect breakage; do not predict MAC rotation

**This replaces an earlier approach that was tested and failed.**

The original plan was to warn when a target device uses a randomized MAC, classified
by the locally-administered (LAA) bit plus a lifespan/staleness heuristic. Two runs
against the live client list killed it:

- **[Measured 2026-09-15]** `last_seen` in `/rest/user` is unreliable. Devices present
  in `/stat/sta` right now report staleness values of 18–48 days. Any heuristic derived
  from that field, including lifespan, is unsound.
- **[Measured 2026-09-15]** Generic device names are not rotation evidence. Ten clients
  named "iPhone" looked like one phone rotating ten times; their lifespans were 858,
  711, 406, 348 and 345 days. They are ten different devices, each holding a stable
  private address for one to two years. iOS privacy MACs are per-network and persistent.
- The classifier's own disproof test failed: it sorted `homeassistant` (a static VM MAC)
  as rotating and `Pixel-8` as static — both backwards.

What the data *does* support: rotation risk is not uniform. Apple Watches churn
(lifespans of 1.3–5.6 days across ten addresses); iPhones and iPads largely do not.

**The design instead:** the tool already polls the client list. At each poll, confirm
the MAC named in each House Arrest policy is still a known client. If it disappears —
and especially if a same-named device appears on a new MAC — the rule has died. Surface
that, offer to re-target. This is observed rather than guessed, produces no false alarms
on static locally-administered MACs, and also catches non-rotation breakage such as a
replaced NIC.

The LAA bit survives only as a soft note at rule-creation time, never as a blocker.

### 3. "Locked Down" must never be a lie

The green state is gated on the runtime check above. If the tool cannot confirm the
policy still matches a live client, it does not show green. A security tool that
reports protection it isn't delivering is worse than no tool.

### 4. Inbound exceptions need a reservation, and that's acceptable

An "allow LAN → device" exception is IP-matched, so the target needs a DHCP reservation,
and a reservation is keyed on MAC — inheriting the rotation problem.

**[Measured 2026-09-15]** This failure already exists in the wild on this console:
`Ollie's iPad` has `fixed_ip` set on two different locally-administered MACs, last seen
382 and 405 days ago. Dead reservations pointing at addresses that rotated away.

It does not bite in practice: devices worth reaching *inbound* (cameras, printers, NAS,
Elgato) have burned-in vendor MACs. Devices that rotate (phones, watches) are never
inbound targets. The runtime breakage check covers the remainder.

### 5. Tagging for clean revert

Every policy the tool creates carries a `[HouseArrest]` marker in its `description`
field (not the name, which the user may edit). Revert = delete exactly the policies
carrying that marker. The tool never modifies or deletes a policy it did not create,
and never touches `predefined: true`.

---

## Control set

**Lockdown presets** (each writes one or more custom policies at `index >= 10000`):

- **Full lockdown** — no internet, no cross-zone traffic. Intra-VLAN peer traffic
  unaffected (see decision 1).
- **Internet only** — device reaches WAN, nothing on the LAN.
- **LAN only** — device reaches local resources, no internet. The common case for a
  camera or an IoT device that shouldn't phone home.
- **Quarantine + VLAN move** — as Full lockdown, plus `virtual_network_override_id`
  into an existing VLAN. Never creates a VLAN.

**Exceptions**, added on top of any preset: destination IP + port or port group, using
`create_allow_respond` so the reply path works without opening the reverse direction.

## Inspection report

Read-only audit, no writes. Answers: which zones exist, which networks have
`network_isolation_enabled`, where `mdns_enabled` crosses a boundary, and — the point
of the whole thing — whether the predefined allow-all at index `2147483647` is making a
nominally isolated VLAN reachable anyway.

---

## MEASURED 2026-09-16: writing the VLAN override does not move the device

The Quarantine preset assumed that a successful `virtual_network_override`
write meant the device had moved. **It does not.**

Test: wired Raspberry Pi (`testclient`) on Default/192.168.200.234, port 2 of a
USW Flex 2.5G 5 with `forward: "all"` and no port overrides — so the port
already carries every VLAN and no tagging change was needed.

| Step | Result |
|---|---|
| `set_client_network(pi, IDIoT)` | returned **True** — override written and read back correctly |
| Client network after 15s … 150s | **still Default / 192.168.200.234**, unchanged |
| SSH session throughout | never dropped |
| Revert | clean; device unaffected |

A connected wired client keeps its current VLAN and DHCP lease until it
reconnects. The override sits pending, and applies on the next reconnect.

**Consequence:** the old code would have reported a completed quarantine while
the device sat exactly where it was — the same class of lie as showing a dead
policy as green. Fixed:

* After writing the override, the device's *actual* network is watched
  (`_confirm_moved`, ~15s). The override is deliberately left in place, since
  it does take effect on reconnect, but the caller is told plainly.
* A new arrest status, `pending_move`, renders as **"Rules live — VLAN move
  pending reconnect"**. State derives it by comparing each client's
  `virtual_network_override_id` against the network it is actually on, so it
  stays accurate however the override was set.
* The apply message tells the user to unplug/replug or reboot the device.

**Answers the open question about wired VLAN moves:** the blocker is not
primarily switch-port tagging — this port already carried the VLAN — it is that
the client does not re-DHCP until its link bounces. A port whose profile does
*not* carry the target VLAN would be a second, separate failure.

## Overnight research session — 2026-09-15/16

Two research agents plus bench verification. Every claim below is tagged by how
it was established. Where a source contradicted a bench measurement, the bench
measurement wins and is marked as such.

### RESOLVED: UniFi DNS policies cannot be scoped to a device

**[Measured — schema enumeration, no writes]** The Integration API rejects
unknown request properties, so the schema can be enumerated without creating
anything. Every plausible scoping field was rejected as not-in-schema:
`clientMacAddress, clientId, macAddress, clients, networkId, networkIds,
network, scope, vlan, vlanId, target, targets, source, appliesTo, deviceId`.

The `A_RECORD` schema is exactly `{type, domain, ipv4Address, enabled,
ttlSeconds}`. Valid `type` values: `A_RECORD, AAAA_RECORD, CNAME_RECORD,
MX_RECORD, TXT_RECORD, SRV_RECORD, FORWARD_DOMAIN`.

Independently confirmed by the official OpenAPI spec (Network 10.3.58): the only
scoping in the entire DNS policy contract is `siteId` in the path. Ubiquiti's
own docs call the feature "DNS forwarding rules".

**Decision: DECLINED as a House Arrest mechanism.** It is site-global. Using it
per-device would mean mutating DNS for the whole network to affect one device.
The authorised write was not spent — the schema settles it, so a write could
only confirm what is already proven.

*Residual use:* reading `dns/policies` to WARN when a `FORWARD_DOMAIN` entry
sends some domains to an arbitrary resolver, which is itself a lockdown bypass.

### CORRECTION: same-VLAN traffic is not unblockable in general

**[Documented]** The UI said "no firewall rule can separate them", which is too
absolute. Ubiquiti ships two mechanisms that do block same-VLAN peers:

* **Device Isolation (ACL)** — per-network toggle, pushes MAC/IP ACLs to UniFi
  switches.
* **Client Isolation** — per-SSID wireless toggle, blocks station-to-station
  traffic within an AP.

Both are per-network / per-SSID, so they affect every device on that network —
out of scope for a per-device tool, but the claim had to be narrowed to "no
*gateway firewall policy* can separate them". Copy fixed in `policies.py` and
`app.js`.

Ubiquiti's own Policy Engine has the same limitation: blocking works between
networks, not between client groups inside one network.

### MEASURED tonight: established connections survive a new lockdown

A rate-limited download was started on the test Pi, then Full lockdown applied
mid-transfer. The transfer **continued** (172 KB → 364 KB after the block)
while new connections failed immediately. The gateway's connection tracking
lets established sessions finish.

Consequence: locking down a streaming device will not stop the stream. Added as
a caveat in the UI. A future "force reconnect after apply" would flush this,
but the Integration API's client actions only support
`AUTHORIZE_GUEST_ACCESS` / `UNAUTHORIZE_GUEST_ACCESS` **[Documented]**, so a
kick would need the legacy `cmd/stamgr` path and does not apply to wired
clients at all.

### VIABLE, NOT BUILT: switch ACLs are the per-device same-VLAN mechanism

**[Measured — endpoint exists on this controller]**
`/proxy/network/integration/v1/sites/{uuid}/acl-rules` returns 200 (currently
empty), `/acl-rules/ordering` returns 200, and a `type: MAC` POST reports its
required fields as `networkIdFilter, enabled, action, name`. So the contract is
real on this hardware.

This is the only mechanism that is simultaneously per-device, effective on
same-VLAN traffic, and reachable from the official API. It could close both the
DNS hole and the peer-traffic gap for a single device.

**Not built — three unresolved questions, all needing a decision rather than
more research:**

1. **Hardware support is not universal.** ACLs are documented as unavailable on
   Flex & Flex Mini, US-8, USW Industrial, and USW Ultra / Ultra-60W /
   Ultra-210W, and on gateway switch ports and In-Wall APs. This network has
   several of those models. The test Pi is on a **USW Flex 2.5G 5**, and whether
   that counts as "Flex" is genuinely ambiguous — the unsupported list predates
   the 2.5G generation. `[VERIFY]`
2. **Wireless is not covered at all.** Two Wi-Fi clients on the same AP and VLAN
   are bridged at the AP; no switch ACL sees the frames.
3. **Ordering has a hard constraint.** `index` on ACL create/update is
   deprecated and has no effect; ordering requires a dedicated PUT that must
   list every rule id, or it is rejected.

A capability check would therefore have to precede any ACL feature: inspect
where the device is attached and say plainly when full lockdown is *not
achievable* for it, rather than reporting success. That is the same discipline
as the health check — never claim protection that is not being delivered.

### Improved: the audit now reports zone membership

**[Measured]** Zones on this console carry `network_ids`, and **Default,
Guests, IDIoT and OpenClaw all sit in the Internal zone** — which is exactly
why a device on 192.168.200.x could reach 192.168.107.x in the baseline probe.

Separate VLANs are not separate security boundaries; traffic inside a zone is
allowed unless a policy blocks it. The Inspection report now leads with this
rather than only reporting per-network isolation flags, because it explains the
cause rather than the symptom.

### Considered and declined

* **DoH/DoT blocking.** Blocking DoT (tcp/853) is cheap and effective and makes
  devices fall back to plain 53. Blocking DoH is only possible as a third-party
  IP blocklist with real collateral damage (one documented case: a Pi-hole
  forum IP shared with DoH endpoints). Not bundled into any preset; at most a
  future opt-in with a pinned, reviewable list.
* **DNS exfiltration as justification.** No credible measurement of prevalence
  on home networks. The honest justification for closing the DNS hole needs no
  threat model: a device under "full lockdown" with a working data path means
  **the tool is lying to the user**, which is a correctness bug on its own terms.
* **Content Filter** is the only documented per-client DNS control, but it is
  not in the Integration API, and enabling it silently repoints the VLAN's
  resolver to a third party and disables DoH for that VLAN **[Measured by a
  third party]**. Too many side effects to drive automatically.

## Lead: closing the DNS hole via the Integration API

Source: a third-party gist on locking down an LG TV
(gist.github.com/KallistoX/ca0413c63e58799ecdfc516b64d603ff). Treat every claim
from it as unverified unless marked otherwise below.

**[Measured 2026-09-15]** The UniFi **Integration API** exists on this console
and the toolkit's existing API key authenticates against it:

| Endpoint | Result |
|---|---|
| `/proxy/network/integration/v1/sites` | 200 — site id is a **UUID** (`88f7af54-…`), not `default` |
| `/proxy/network/integration/v1/info` | 200 — `applicationVersion: 10.6.106` |
| `/proxy/network/integration/v1/sites/{uuid}/dns/policies` | 200 — exists, currently empty |
| `/proxy/network/integration/v1/sites/{uuid}/dns/records` | 404 — the gist's naming is `dns/policies` |
| `/proxy/network/integration/v1/sites/{uuid}/clients` | 200 — clients carry an `access: {type: "DEFAULT"}` field |

Why this matters: the measured DNS hole above (a locked-down device still
resolves names through a same-VLAN resolver) might be closable with sinkhole
DNS policies instead of firewall rules.

**[VERIFY] before building on any of this:**

* **Scope.** The gist states DNS records are *site-wide, all VLANs*. If true,
  DNS policies are **unusable for House Arrest**, which is per-device by
  definition — sinkholing a domain for one device would sinkhole it for the
  whole network. This is the single claim that decides whether the idea is
  viable, and it could not be verified read-only (no existing policies to
  inspect, no schema endpoint: `openapi.json` and `/docs` both 404).
* **Payload shape.** Claimed to be an A record pointing at `0.0.0.0`. Unverified.
* **`access.type` on clients.** All 78 clients read `DEFAULT`. The field implies
  other values exist and hints at a first-class per-client block, which would be
  a cleaner primitive than firewall policies. No way to learn the other values
  without writing. Worth one experiment.

**Applied already — asynchronous provisioning.** The gist reports new DNS
records take **~45 s** to reach dnsmasq, and that verifying too early produced a
false negative. That maps onto a real weakness in this codebase:
`set_client_network()` verified its write with a single immediate re-read, which
would report a false failure and roll back a lockdown that had actually
succeeded. It now polls with backoff up to 20 s instead. Firewall policy writes
were observed to take effect within ~5 s, so this applies to client/DNS
provisioning rather than to policies.

**Out of scope.** The gist's main content is curated block-lists of LG/ACR
telemetry domains (ads, Nielsen/GfK broadcast measurement, app-store mirrors).
That is domain curation, a different product from House Arrest's traffic-path
lockdown. Noted as a possible future feature, not adopted here. Its advice to
"put the TV in an IoT VLAN with default-deny toward other segments" is what
Quarantine already does.

## Open items before building

1. **[Inferred]** Whether `client_macs` accepts multiple MACs in one policy in practice,
   not just by schema shape. Test with two devices before designing multi-select UI.
2. **[Inferred]** Behavior when a policy references a MAC that is no longer a known
   client — silently inert, or an API error on write? Decides how revert handles a
   device that vanished.
3. Port-group support in exceptions is assumed from the field's presence; not yet
   exercised.
4. Whether the `rest/user` PUT path accepts `fixed_ip` and `use_fixedip` together —
   `fixedip_test.py` was written for this and never run with `--apply`.

## Verify before shipping

- Zone ids are per-console; look up, never hardcode.
- Only stable/GA UniFi firmware is supported (see CLAUDE.md). Confirm policy shapes
  against the current GA release before release, not against EA.
- The `index` collision case: what happens if the user already has a custom policy at
  the index the tool wants.
