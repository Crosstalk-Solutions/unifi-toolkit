# House Arrest — Design Document

**Status:** implemented and verified end to end (`tools/house_arrest/`, mounted at `/arrest`)
**Last updated:** 2026-09-15
**API research:** complete (probed live against UCG-Fiber, UniFi OS)
**Anonymization:** device/VLAN names, MAC tails and controller object ids in the
measured examples are genericized; the measurements themselves are verbatim.
**End-to-end tested:** yes — against a wired Raspberry Pi (`testclient`, dc:a6:32:xx:xx:xx) on 2026-09-15

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
  "client_macs": ["aa:bb:cc:dd:ee:01"],
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
existing user policy (`Alice to n8n` at 10000). The controller assigns the
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
  out over DNS. Moving the resolver off the device's VLAN — or giving the
  device a dedicated VLAN natively in UniFi (see the 2026-09-17 quarantine
  removal below) — is the answer where that matters.

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
  as rotating and `a phone` as static — both backwards.

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
- **Quarantine + VLAN move** — REMOVED 2026-09-17, see the dated section below.
  Was: as Full lockdown, plus `virtual_network_override_id` into an existing
  VLAN. Release-side recognition of pre-removal quarantine policies is kept
  forever so their overrides still get cleared.

**Exceptions**, added on top of any preset: destination IP + port or port group, using
`create_allow_respond` so the reply path works without opening the reverse direction.

## Inspection report

Read-only audit, no writes. Answers: which zones exist, which networks have
`network_isolation_enabled`, where `mdns_enabled` crosses a boundary, and — the point
of the whole thing — whether the predefined allow-all at index `2147483647` is making a
nominally isolated VLAN reachable anyway.

---

## MEASURED 2026-09-17: the wired override HALF-APPLIES — Quarantine preset removed

The 2026-09-16 finding below ("override written but device unmoved until
reconnect") turned out to be the benign half of the problem. After the device
DID reconnect (reboot), the same wired Pi landed in a state strictly worse than
either "moved" or "not moved":

| Observation | Value |
|---|---|
| Pi's own console (`eth0`) | **192.168.107.177** — a real DHCP lease on the target VLAN (IoT/107) |
| Pi -> its own gateway 192.168.107.1 | **"destination host unreachable"** — ARP fails |
| Pi -> same-VLAN peer 192.168.107.99 | **"destination host unreachable"** — ARP fails |
| `stat/sta` | still reported **Default / 192.168.200.234** |
| UniFi UI | showed **network = IoT, IP = 192.168.200.234** — contradicting itself |

So DHCP (broadcast) got through on the target VLAN at least once, but
steady-state the client had no working L2 there at all — an address it could
not use, and no IPv4 connectivity anywhere. Firewall policies cannot cause
this (they are L3 at the gateway and cannot block ARP on the local segment);
this is the `virtual_network_override` mechanism itself misbehaving for a
wired client. The exact locus (switch MAC-based VLAN assignment flapping) is
inferred, not pinned down — and deliberately not worth pinning down, because:

**Decision: the Quarantine preset is removed.** Two principles decide it:

1. *Never claim protection the tool is not delivering.* The platform reported
   two different locations for the device at once; a quarantine whose outcome
   the controller cannot state coherently cannot be verified by us.
2. *Use UniFi's native mechanisms so the tool and the UniFi UI never
   disagree.* The per-client override was the one mechanism in the tool that
   fought the platform, and in two days of live testing it produced a
   stranding bug, a false `pending_move`, and this half-connected state.

What replaces it: the blind-spot box now tells the user to give the device a
dedicated VLAN **natively in UniFi** (the switch port's network for wired, a
dedicated Wi-Fi network for wireless) and then isolate/DNS-lock that VLAN
here — the operations this tool performs reliably. Kept on the release side:
`preset_from_policy` still recognises the "Quarantine + VLAN move" label and
`requires_network` still returns True for it, so releasing a pre-removal
quarantine clears the override instead of stranding the device. The apply
side (`_confirm_moved`, the move block in the lockdown endpoint, the VLAN
picker) is gone; quarantine's two scenario images were deleted with it.

Related fix kept from the same investigation: the arrest rows now prefer the
OBSERVED (traffic-flow) location over `stat/sta`, since flow data carried the
device's true address (107.177) while `stat/sta` repeated the stale one.

## MEASURED 2026-09-16: writing the VLAN override does not move the device

The Quarantine preset assumed that a successful `virtual_network_override`
write meant the device had moved. **It does not.**

Test: wired Raspberry Pi (`testclient`) on Default/192.168.200.234, port 2 of a
USW Flex 2.5G 5 with `forward: "all"` and no port overrides — so the port
already carries every VLAN and no tagging change was needed.

| Step | Result |
|---|---|
| `set_client_network(pi, IoT)` | returned **True** — override written and read back correctly |
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
Guest, IoT and Media VLANs all sit in the Internal zone** — which is exactly
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
"put the TV in an IoT VLAN with default-deny toward other segments" is now
done by assigning the TV a dedicated VLAN natively in UniFi and isolating it
here (the Quarantine preset that did the move itself was removed 2026-09-17).

## MEASURED 2026-09-16: firewall policy ordering is PER ZONE PAIR

This corrects the earlier note that the stored `index` "is not the one you
send" and should just be re-checked afterwards. That was true but incomplete,
and the incomplete version caused a real bug.

**The measurement.** Dumping every custom policy with its zone pair:

```
  10000 ALLOW  Internal -> Internal    Alice to n8n
  10000 BLOCK  Internal -> External    House Arrest: testclient - no internet
  10001 ALLOW  Internal -> Internal    SSH to Alice
  10002 ALLOW  Internal -> Internal    TEST ANY to Elgato2
  10003 BLOCK  Internal -> Internal    House Arrest: Roku2 - no LAN
  10004 BLOCK  Internal -> Internal    House Arrest: testclient - no LAN
```

Two *enabled* policies both sit at index 10000. They are in different zone
pairs. Every Internal -> Internal policy has a unique index. So the index
counter, and therefore evaluation order, is scoped to a
(source zone, destination zone) pair — not to the site.

**The disproof, had it been wrong:** if ordering were site-wide, that duplicate
index could not exist.

### Bug this caused #1 — false rollback (reported symptom)

`dns_order_is_safe()` compared every ALLOW against every BLOCK site-wide. The
internet-facing block routinely lands at a lower index than the LAN allow,
because it is counted in its own pair starting near 10000. The check read that
as an inversion and rolled the whole lockdown back with:

> "The gateway placed the allow rule after the block rules, which would have
> left these networks with no working DNS at all. Everything was rolled back;
> nothing changed."

Nothing was actually wrong. The two rules never evaluate against each other.
Fixed by grouping the created policies by zone pair and only comparing within
a pair. A pair holding blocks but no allow is legitimate — it means no
approved resolver is reached that way.

### Bug this caused #2 — public resolvers were silently fatal (not reported)

`build_dns_lockdown()` always created its single ALLOW with
`resolver_zone_id=internal_id`. With an internal resolver that happens to be
correct. With a public one (1.1.1.1, 8.8.8.8) the allow landed in the Internal
pair where it does nothing, while the Internal -> External block on port 53
killed the query — total DNS loss for the chosen networks, and the rollback
check would not have caught it because the *indexes* looked fine.

Fixed by `classify_resolvers()`, which splits approved resolvers by whether
they fall inside a configured LAN subnet, and emitting one ALLOW per zone pair
that actually holds a resolver.

### Also discovered

`PUT /proxy/network/v2/api/site/{site}/firewall-policies/batch-reorder` exists
(it rejects a list with a JSON parse error rather than 404) and its payload
requires `sourceZoneId` and `destinationZoneId` — independent confirmation that
ordering is per zone pair. Not used yet; creation order within a pair has been
sufficient. It is the endpoint to reach for if placement ever needs forcing.

## MEASURED 2026-09-16: DHCP and the DNS rules are not kept in step

The rules police which resolver a device may TALK to. DHCP decides which
resolver it is TOLD to use. Nothing links them.

Measured on the live console: the Guests VLAN hands out `192.168.200.12` and
`1.1.1.1` via `dhcpd_dns_1..4`, while `.50/.51` were being set as the approved
resolvers. Applying that would have left every device on Guests pointed at an
address it was no longer allowed to reach — a self-inflicted outage that every
existing check would have passed.

`dhcp_dns_conflicts()` now compares the two and leads the caveat list when they
disagree. **DNS Lockdown does not and should not write DHCP settings** — it
creates firewall policies only. The fix is the user's to make in
Settings -> Networks -> <network>, and the tool says so.

## CORRECTED 2026-09-16: "You reaching in to it" understated the exposure

`allow_inbound` narrows the BLOCK to the NEW and INVALID connection states with
the locked-down device as SOURCE. A connection STARTED by anything else never
matches the policy at all, and the device's ESTABLISHED reply flows back
freely. That is *every device that can already route to it*, not the person
reading the page.

The row label is now "Other devices reaching in to it", the checkbox reads
"Let other devices still reach this device", and the eight scenario images say
"Other devices" rather than "You". Saying "me" promised a narrowness the
firewall was never delivering.

## Editable inspection-matrix cells

Four of the six matrix columns are a single boolean on the network object and
can be flipped from the table: `isolation` (`network_isolation_enabled`),
`internet` (`internet_access_enabled`), `mdns` (`mdns_enabled`) and `upnp`
(`upnp_lan_enabled`). `EDITABLE_COLUMNS` in `policies.py` is the whitelist and
the `/api/network-setting` endpoint enforces it, so a crafted request cannot
set an arbitrary field on the network document.

**Zone and DNS are deliberately not editable.** Zone is membership in a zone
other networks also belong to — changing it is a move whose blast radius
reaches every network in both zones, not a toggle. DNS is a list of addresses
(`dhcpd_dns_1..4`), so there is no second state to toggle *to*; a one-click
cell would have to invent one.

This does not fight the isolation tool: `isolated_networks` is derived purely
from the native flags with no ownership marker, so a network isolated from the
matrix, from the isolate form, or from the UniFi UI all read identically.

## MEASURED 2026-09-16: the blocked-attempts panel was under-reporting badly

Reported as "I don't believe this data". Correct instinct — two independent
bugs were eating more than half of it.

**Bug 1: the fetch stopped at one page.** `get_blocked_flows()` sent
`pageNumber: 0, pageSize: 200` and returned whatever came back. The response
carries `has_next` and `total_element_count`, both ignored. Measured: page 0 at
size 200 returned *exactly* 200 flows with `has_next: true`, while the real
total was 249 flows / 788 attempts. Now paginated, with a `max_pages` ceiling.

**Bug 2: flows blocked by a replaced policy were silently dropped.** Two
policies existed with the identical name
`House Arrest: Roku2 - no LAN` but different ids:

```
  6aaad4a7c0c0564963fb0b2b   519 attempts   (live, owned by the tool)
  6aaabcd0c0c0564963faf8ec   274 attempts   (not on the controller any more)
```

The second is the leftover of an earlier lockdown of the same device.
`summarize_blocked()` attributed strictly by live policy id and threw the rest
away, losing 87 flows / 274 attempts — over a third of that device — with no
indication anything had been discarded.

Attribution is now a tier, not a filter: `ours` (live policy id), `stale`
(policy name matches `NAME_PREFIX` + this device's label, id no longer owned)
and `other`. The headline counts `ours` + `stale`; every row names the rule
that stopped it and says when that rule was an earlier one. The `stale` tier is
name-based and therefore weaker than id attribution, which is exactly why it is
reported as its own tier and never folded in as though the current rule did it.

Combined, the device went from a reported 425 attempts to a true 798.

## MEASURED 2026-09-16: that device's blocked traffic is all return traffic

Over 7 days, the same locked-down Roku: 246 flows, 778 attempts, **100% UDP**,
and **not one destination port below 32768**. Every packet was aimed at an
ephemeral port on one of exactly four hosts — the PC and phones that actually
use that Roku.

A device probing the LAN does not look like that. It contacts services on
well-known ports (8060 Roku ECP, 1900 SSDP, 5353 mDNS, 53, 443) and it spreads
across hosts. Traffic to a scatter of high ports on precisely the devices that
talk to it has the shape of the far side of a conversation they opened.

INFERRED, not measured: that these are specifically replies whose UDP conntrack
entry expired and so re-entered as NEW. The obvious test — querying flows with
the Roku as DESTINATION — returned zero rows, but the `destination_mac` filter
is unverified and may simply be ignored, so **that null result proves nothing
and is not cited as evidence** (see rule 9).

The operational conclusion does not depend on the mechanism: these rows are not
the device reaching out, and listing them as "what it tried to reach" is
misleading. `flow_kind()` splits rows into `connection` (TCP, or UDP to a port
below 32768) and `return_traffic` (UDP to an ephemeral port). The panel leads
with connection attempts and says plainly when there are none; return traffic
is parked behind a disclosure with its count stated. **It is never dropped** —
hiding data silently is the bug this section exists to record.

## DHCP name servers CAN be written, and now are (opt-in)

Confirmed against a live network document: `dhcpd_dns_1..4` are plain string
fields gated by `dhcpd_dns_enabled`, on the same document the tool already
read-modify-PUTs. So yes, the tool can set them.

`set_network_flags()` could not — it verified with `bool(stored) == bool(sent)`,
which would call `'8.8.8.8'` and `'1.1.1.1'` equal. Split into
`set_network_fields()` (exact comparison) over a shared `_write_network()`.

This is exposed as a separate **"Also fix DHCP"** action on the DNS tab, always
previewed, never folded into Apply. Rationale: the firewall rules decide which
resolver a device may talk to and DHCP decides which one it is told to use;
nothing links them, so leaving them inconsistent is the main way to take a
network's DNS out. But changing what every device on a network is told is a
wider blast radius than a firewall rule, so it gets its own confirmation — and
the UI says the change lands on lease renewal, not immediately.

Unused slots are written as empty strings rather than left alone, or a resolver
the user just removed keeps being advertised.

## SOLVED 2026-09-16: mDNS forwarding IS writable - via v2 global/config/network

**This section previously read "FAILED: mDNS forwarding cannot be written through
any API route found". That conclusion was wrong.** The routes tried were the wrong
ones; the failure history is kept below because the *shape* of the failure is the
diagnostic lesson. Superseded by the measured result at the end of this section.

`mdns_enabled` on the network document is a **read-only projection**. Writing
it the ordinary way returns `200 {"meta":{"rc":"ok"},"data":[]}` and the value
reads back unchanged at 0s, 2s and 5s. The tool's verification caught this
correctly and refused to claim success — which is what the user saw as "the
toggle isn't working". The report was accurate; the toggle genuinely could not
work.

The underlying control is the site-level setting:

```json
{"key": "mdns", "enabled_for": "some", "mode": "all",
 "enabled_for_network_ids": ["<network-id-1>", "<network-id-2>", "<network-id-3>", "<network-id-4>"]}
```

Removing a network id from `enabled_for_network_ids` was attempted four ways.
**All four returned 200 and echoed back the UNCHANGED list** — the controller
accepts the request and ignores the field:

| Attempt | Result |
|---|---|
| `PUT  /api/s/{site}/rest/setting/mdns/{_id}` | 200, list unchanged |
| `PUT  /api/s/{site}/rest/setting/mdns` | 200, list unchanged |
| `POST /api/s/{site}/set/setting/mdns` | 200, list unchanged |
| `POST /api/s/{site}/set/setting/mdns/{_id}` | 200, list unchanged |
| `PUT  /v2/api/site/{site}/lan/{network_id}` | 404 |

Note the echo: the response body itself carries the old list, so this is an
inline rejection, not slow provisioning. That read was correct, and it was the
clue: an endpoint echoing an unchanged document is one that parsed the request
and recognised none of the fields in it.

### The answer

The console was observed (Chrome, 2026-09-16) saving this setting with **two**
requests, of which only the first carries the change:

| Request | Role |
|---|---|
| `PUT  /proxy/network/v2/api/site/{site}/global/config/network` | the real write |
| `POST /proxy/network/api/s/{site}/set/setting/mdns` | the no-op we had been imitating |

The v2 document names the same data with **different field names**, which is why
every earlier attempt was accepted and discarded:

| Legacy `setting/mdns` (ignored) | v2 `global/config/network` (works) |
|---|---|
| `enabled_for` | `mdns_enabled_for` |
| `enabled_for_network_ids` | `mdns_enabled_for_network_ids` |

A partial payload carrying only those two fields is sufficient - the rest of the
document does not need to be echoed back.

**MEASURED 2026-09-16** against the live UCG-Fiber, using the toolkit's own
`X-API-KEY` auth (no session cookie, **no CSRF token required**):

```
GET  200  ids=4  media-vlan=YES
PUT  200  ->  re-read 200  ids=3  media-vlan=no     WRITE WORKED
restore PUT 200  ->  ids=4  media-vlan=YES          RESTORED CORRECTLY
```

A PUT from an authenticated *browser* session returns **403 Forbidden** without a
CSRF token. That 403 is a browser-session artefact and does not apply to the
toolkit. Note its shape: an honest rejection, structurally unlike the
200-and-ignore, and itself evidence the endpoint is the live one.

### Two corrections to earlier claims in this document

1. `mode: "all"` alongside `enabled_for: "some"` was recorded as "unexplained and
   may be relevant". It is explained and it is **not** relevant to VLAN scoping.
   The UI has two independent axes: **VLAN Scope** (`enabled_for` /
   `enabled_for_network_ids`) and **Service Scope** (`mode`, All vs Specific).

2. mDNS is **not a per-network setting**. It is one site-level "Gateway mDNS
   Proxy" control (Auto / Off / Custom) whose Custom mode holds the VLAN list.
   `mdns_enabled` on a network document remains a read-only projection of it -
   that part of the original finding stands.

**Consequence for the tool:** the mDNS column no longer needs to be read-only,
and the hover text saying the change must be made in the UniFi UI is now wrong.
Because the control is site-level, a per-network switch writes a *shared* list,
so removing one network's mDNS is a site-scoped edit and must be presented as
one - and released by restoring the exact prior list, not by re-adding blindly.

## MEASURED 2026-09-16: UPnP is off site-wide, so the per-network flag is inert

`rest/setting/usg` reports `upnp_enabled: false`. While that master switch is
off, `upnp_lan_enabled` on a network does nothing. The matrix now reads the
site setting, shows the cell as "Off (site-wide)" with that explanation, and
does not offer it as a toggle.

This is why matrix editability moved from a per-COLUMN judgement in the browser
to a per-CELL `editable` flag decided on the server: whether UPnP can be
changed depends on site state, not just on which column it is.

## CORRECTED 2026-09-16: flow_kind polarity — a ping sweep was being hidden

The first version listed what counted as a connection and defaulted everything
else to return traffic:

```python
if proto == "TCP": return "connection"
if isinstance(port, int) and port < EPHEMERAL_PORT: return "connection"
return "return_traffic"          # <- ICMP has no port, so it landed here
```

An ICMP host-discovery sweep carries no port at all and therefore fell through
to the hidden bucket. A sweep is precisely the thing this panel must not bury.

Inverted: demote **only** the pattern actually measured — UDP aimed at a port
>= 32768 — and treat everything else as the device reaching out. Default to
showing. Covered by a case table including TCP at any port, SSDP/mDNS/ECP/DNS,
ICMP with a null and a zero port, and unknown protocols.

## UPnP column removed 2026-09-16

UniFi ships UPnP off, and nobody should be turning it on. The column was
surfacing a setting that is off by default, inert on this console anyway
(`rest/setting/usg` -> `upnp_enabled: false`), and not something the tool
should invite anyone to change. Removed rather than left read-only: an
always-"Off" column is noise in a table meant to show what is actually open.

The per-cell `editable` flag introduced for it stays — it is the right shape
regardless, because editability can depend on site state rather than only on
which column a cell is in.

## The LG TV story, and what this tool would and would not have shown

[REFERENCE, from press coverage — not verified on the bench here.] In early
September 2026 a Gamers Nexus / Level1Techs investigation reported that LG
smart TVs sweep the local network and profile what they find. Reported details:
one TV enumerated 38 devices (phones, smartwatches, a 3D printer, an air
purifier, thermostats), collecting device names, MAC addresses, internal IPs and
signal strength, plus nearby Wi-Fi SSIDs and channels. Coverage names **mDNS and
SSDP** as the discovery mechanism, with reverse DNS to name whatever does not
announce itself. LG has publicly denied the central claims.

**Would the blocked-traffic panel show this?** Only when the traffic crosses the
gateway, and with an important gap:

* mDNS (udp/5353), SSDP (udp/1900) and reverse DNS (53) are all below
  `EPHEMERAL_PORT`, so they classify as `connection` and appear in the panel by
  default. Any TCP probe does too, at any port. An ICMP sweep does after the
  polarity correction above — before it, that case was being hidden.
* **But a sweep of the TV's OWN VLAN is invisible to this tool and always will
  be.** mDNS and SSDP are multicast and link-local; that traffic never reaches
  the gateway, so no firewall policy sees it and nothing appears in the flow
  data. This is the same measured limitation the `peers` path already reports
  as "Devices on its own VLAN: still reachable". A TV sharing a VLAN with the
  phones it is profiling is the worst case and the panel would stay empty.
* Cross-VLAN discovery is only possible at all where **mDNS forwarding** is on
  for the network — which makes it the single switch most relevant to this
  behaviour. It is now known to be writable (see the mDNS section above); the
  column stays read-only only because the control is site-level, which is a
  presentation problem rather than an API one.

**What this means for the tool's advice.** A dedicated, isolated VLAN remains
the right answer for a TV, and for the right reason: it changes which peers
exist rather than trying to filter traffic the gateway never sees. (Since the
2026-09-17 removal, the VLAN assignment itself happens natively in UniFi; the
tool then isolates and DNS-locks that VLAN.) Worth stating plainly in any user-facing writing: House
Arrest can stop a TV phoning home and can stop it reaching other VLANs, but it
cannot stop it profiling devices sitting next to it on the same VLAN. Only
per-network Device Isolation or per-SSID Client Isolation does that.

## UI corrections 2026-09-16 (round 4)

**Current DNS per network, on the DNS tab.** Choosing which networks to force
onto a resolver means knowing what they already advertise, which meant
switching to the Networks tab and back. `NetworkInfo` now carries `dhcp_dns`,
and a compact table sits under the picker. Two things it does beyond echoing
the Networks tab: the row for a selected network is highlighted, and an
advertised resolver that is NOT on the approved list is drawn in red with a
count beneath. That combination — selected network, unapproved resolver — is
precisely the self-inflicted outage the DHCP checkbox exists to prevent, so it
is worth showing at the moment of the decision rather than after.

**The DNS form resets after a successful apply.** It previously kept the
network ticked, both checkboxes set and the resolver list populated, which
invites applying the same lockdown twice without noticing — and that had
already happened on the bench console, where Guests showed **10 rules** for
what should be a 5-rule lockdown. Now: network selection, DoT and the DHCP
option all reset; the approved resolver list stays, because it is almost always
the same for the next network. The green confirmation and the refreshed
"currently enforcing" list were already correct.

**Hardened one template expression.** `p.name.replace(...)` in the rules
preview threw on a payload without a name. An uncaught throw inside an Alpine
expression kills reactivity for the whole component, not just that node, so it
is guarded even though real payloads always carry a name.

## Dashboard layout 2026-09-16

Four tools made `repeat(auto-fit, minmax(350px, 1fr))` reflow the fourth onto a
row of its own, stranding the info cards and the Rogue Support banner far down
the page. Now an explicit `repeat(3, 1fr)` with the two info cards moved INTO
the same grid, giving exactly two rows of three:

```
Wi-Fi Stalker | House Arrest  | Network Pulse
Threat Watch  | About         | Getting Started
```

House Arrest and Threat Watch swapped so the active tool leads. `.info-row` is
gone; `.info-card-grid.info-in-grid` gives the info cards the tool cards'
footprint while staying visually lighter (no icon, no button, smaller heading).
Breakpoints: 2 columns under 1200px, 1 under 768px.

## UI corrections 2026-09-16 (round 3)

**Networks tab is three sub-sections, in the order you work in them.** Isolate
a network -> Networks currently isolated -> Wi-Fi client isolation, each with a
heading and a 2px rule. The "currently isolated" list had drifted to the very
bottom of the tab, under a Wi-Fi heading it has nothing to do with; "what did I
just do" belongs directly under the control that did it.

While moving it, two real bugs:

* The list was wrapped in `<template x-if>` *and* the new sub-section carried
  the same `x-show`. The x-if was redundant, and worse — when its closing tag
  was lost in the move, the Wi-Fi block was parsed INTO the template. Alpine
  only clones a template's first root element, so **the entire Wi-Fi section
  silently stopped rendering** while the HTML still contained it. Tag-balance
  counting caught the imbalance; the DOM walk proved the block was absent.
  Lesson: `<template x-if>` must wrap exactly one root element, and a lost
  closing tag there fails silently rather than loudly.
* An orphaned `</div></template>` pair was left behind after the move, which
  closed `.isolate-block` early.

**"Also fix DHCP" is now a checkbox, not a button.** It sits directly above
"Also block DNS-over-TLS" in the same format, with the same kind of
explanation, because it is an option ON a DNS lockdown rather than a separate
task. As a button with a tooltip it was both misaligned and buried — and it is
the single most consequential option on that tab, since getting it wrong is how
a network loses DNS entirely. Previewing now shows both halves together, and
applying does the rules first: they are the half that can fail and roll itself
back, and there is no sense repointing every device on a network at resolvers
whose allow rule did not survive.

The preview also distinguishes "will change" from "already match" per network,
rather than rendering `a, b -> a, b` under a heading claiming a change.

**Devices under arrest now show which lockdown they are under.** The row said
"Enforcing" without ever saying what was being enforced, so a device on
Internet only and one on Full lockdown looked identical. `preset_from_policy()`
reads it back out of the description (`[HouseArrest] <preset> for <label>`) and
returns it **only** when it matches a known preset name — an unrecognised value
shows nothing rather than guessing at a lockdown level.

## Built 2026-09-16: the blind spot, and Wi-Fi client isolation

Two changes, shipped together on purpose.

**The blind spot is now a first-class element** on the Devices tab, not a grey
footnote. "Devices on its own VLAN: still reachable" was technically present
and practically invisible, which let the page imply a completeness it does not
have. It now states what no rule on that page can stop, and names the only two
things that do: a dedicated VLAN of the device's own (assigned natively in
UniFi), or Client Isolation on its SSID.

One deliberate omission: the callout does NOT name the device's VLAN. The first
version did, and printed **"Default"** for a Roku measured to be on IoT —
straight into the documented `stat/sta` wrong-network quirk. A callout whose
entire job is honesty must not print a fact it cannot stand behind, so it says
"its own VLAN" and stops there.

**Wi-Fi client isolation** is on the Networks tab: every SSID with its client
count and isolation state, behind a confirm dialog. It is kept out of the
device presets on purpose — isolation belongs to the SSID, so containing one
television also stops every phone on it casting or printing. The dialog leads
with that count ("all 31 devices on this SSID, not just the one you are worried
about") because that number is the decision.

`client_count` comes from `get_clients()`, which returns a dict keyed by MAC
rather than a list; iterating it directly yields MAC strings and silently
counts zero. Iterate `.values()`.

## MEASURED 2026-09-16: what is and is not buildable against the LG threat model

Probed while looking for gaps the LG story exposes. The negative results matter
as much as the positive one — they close off three plausible-sounding features.

### `l2_isolation` on a WLAN is real and IS writable  [Measured]

Per-SSID client isolation is `l2_isolation` on the `rest/wlanconf` document.
Tested on `Sherwood_guest` (0 clients, so nothing to disrupt): PUT flipped it
True -> False, confirmed at 0s/2s/4s, and it was restored. Unlike
`mdns_enabled`, this one actually takes.

This is **the only lever found that stops a device profiling peers on its own
VLAN**, which is the central LG behaviour. Current site state:

| SSID | l2_isolation | clients |
|---|---|---|
| Sherwood_forest | False | 8 |
| IoT | False | 31 |
| Sherwood_guest | True | 0 |
| Elgato | False | 3 |

Limits to state plainly wherever this is offered: it is **wireless only**, it
applies to **every client on that SSID**, and it breaks casting, AirPlay and
local printing for all of them. The IoT SSID carrying 31 clients with
isolation off is the realistic version of that trade-off.

### ~~There is NO per-network Device Isolation field~~  [CORRECTED 2026-09-29]

**The original claim was wrong because it over-generalised a null result.**
What was measured: the *network document* (`rest/networkconf`) carries only
`network_isolation_enabled`. What was written: "no per-network Device
Isolation field" and "switch-port ACL not found in the API surface examined".
The field exists — it lives in the site-wide `rest/setting` → `global_switch`
document as `acl_device_isolation: [<network ids>]`, which was never read. And
switch ACLs had already been found (see "VIABLE, NOT BUILT" above), so this
entry contradicted the same document. A negative finding must name where it
looked: "not on networkconf, checked 2026-09-16" was the true statement.
See "MEASURED 2026-09-29" at the end of this file for the tested behaviour.

### `traffic-flows` returns ONLY blocked flows  [Measured]

This kills the idea of a pre-lockdown audit ("show me what this TV is doing
before I lock it down"). Queried with no `action` filter at all:

* Roku, locked down: 363 flows, every one `action: blocked`
* VENGEANCE, an active PC that is NOT locked down: **0 flows**

The endpoint is the firewall log, not a netflow record. There is no "what is
this device talking to" data to draw on unless a policy is already stopping it.

### DPI is not a fallback  [Measured]

`stat/stadpi` and `stat/sitedpi` both return 200 with an empty payload on this
console, so per-client application breakdown is unavailable without the user
first enabling Traffic Identification. Blocked flows also carry an empty
`domains[]`, so domain-level visibility is not available either.

### Consequence for the roadmap

"Show what the device is doing" can only ever be a **post**-lockdown view here:
"since you locked this down, it has tried to reach N distinct devices". That is
still the number the LG story makes concrete (the investigation reported 38),
and it only counts attempts that crossed the gateway — same-VLAN sweeping stays
invisible no matter what.

## Scenario infographics (UI)

The Devices tab draws each preset as a picture beside the verdict list, in
`tools/house_arrest/static/images/`. Two invariants keep the pictures honest:

1. **There is one image per `(preset, inbound)` pair, not one per preset.**
   The inbound direction is a checkbox rather than a preset property, so a
   single per-preset picture starts contradicting the row list the moment the
   box is unticked. Eight files: `scenario-<preset>-<inbound|noinbound>.png`.
   `scenarioKey()` in `app.js` builds the filename from the same two values
   `pathRows()` reads, so the list and the picture cannot drift apart.

2. **The drawn spokes must match `PRESET_EFFECTS`.** Each image draws four
   spokes — Internet, Other networks, Same VLAN, You — in the same fixed
   positions, so switching presets changes only the colours. Solid green is
   allowed, red dashed with an X is blocked, amber with a relocation glyph is
   `moved` (historical: only the removed quarantine preset used it, redrawing
   the bottom group as "New VLAN" in a dashed amber pen because relocating
   changes *which* peers exist rather than cutting peer traffic; no current
   image uses the amber state).

**If you add or change a preset, regenerate its two images.** A preset with no
matching file renders a broken image; worse, a preset whose effects changed but
whose picture did not is the tool claiming protection it is not delivering.
The `alt` text is generated from the rendered verdicts rather than written by
hand, so it stays correct on its own.

Images were generated with Gemini (Nano Banana) and are flat-vector art on a
white ground in both themes, framed in their own white card. They are cropped,
resized to 900px wide and palette-quantised (~40 KB each).

Two more diagram families were added in the same style:

- **DNS Lockdown** — one static diagram (`dns-lockdown.png`) on the DNS tab,
  showing the approved resolver reachable on 53 while every other resolver, DoT
  on 853, and an app's hardcoded DNS are cut. It is preset-independent, so a
  single image is correct.
- **Network isolation** — one image per network preset
  (`isolation-<preset>.png`: `isolate_networks`, `no_internet`,
  `full_isolation`), swapped by `isoImage()` off `isoPreset`, exactly like the
  device scenario images. The internet and other-VLAN paths flip between allowed
  and blocked per preset, and every variant keeps the green same-VLAN peer loop
  visible so the picture never implies peer traffic is filtered. **If a network
  preset's effects change, regenerate its image too.**

## Open items before building

1. **[Measured 2026-09-16]** `client_macs` DOES accept multiple MACs in one
   policy in practice — created and read back a disabled two-MAC BLOCK policy on
   the live UCG-Fiber (Roku + testclient), both MACs echoed and stored. The
   device picker's multi-select relies on this.
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

## MEASURED 2026-09-17: zone_key and firewall_zone_id — the custom/renamed-zone fix

**The brittleness.** `_zone_ids()` matched zones by display name ("internal" /
"external", case-folded). Both bench consoles use the default names, so every
test passed — but a user who renames a zone, or whose networks sit in a custom
zone, would get policies written into zone pairs their traffic never crosses.
Since policy ordering (and matching) is scoped to the (source zone,
destination zone) pair, that is silent non-protection: every index check
passes, the health check sees the policies present, and nothing is enforced.

**[Measured] on the home UCG-Fiber (read-only dump of `/firewall/zone` and
`rest/networkconf`):**

- Every default zone document carries a stable **`zone_key`**: `internal`,
  `external`, `gateway`, `vpn`, `hotspot`, `dmz` — plus `default_zone: true`
  and a `network_ids` membership list. The display `name` is a separate field,
  which is what the user renames; `zone_key` is the reliable handle.
- Every LAN network document carries **`firewall_zone_id`** pointing at its
  zone's `_id` (a WAN-failover entry was the only network without one).
- `rest/user` known-client records carry **`last_connection_network_id`**
  (272 of 338 records on this console) — the only per-MAC network attribution
  available without trusting `stat/sta`.

**The fix (this session):**

- `find_zone_id(zones, key)` matches `zone_key` first, display name only as a
  fallback for firmware without `zone_key`. Verified live: identical ids to
  the old name lookup on the home console (parity check).
- DNS lockdown scopes `client_zone_id` to the chosen networks' actual zone via
  `zone_of_network()` (`firewall_zone_id`, falling back to the zone's
  `network_ids` list). A selection spanning two zones is refused — one
  lockdown per zone — because a single rule set cannot cover two source zones.
- Device lockdown attributes each MAC through known-client →
  `last_connection_network_id` → `firewall_zone_id`. That record shares
  stat/sta's staleness problems, but the measured misreports swapped VLANs
  *within* the Internal zone, so zone-granularity attribution is safer than
  hardcoding Internal — and the scoping is stated as a caveat on the review,
  not applied silently. Unattributable MACs fall back to Internal.
- `classify_resolvers()` gained a third bucket: an approved resolver on a LAN
  network in a *different* zone than the locked networks gets **no allow at
  all** (the blocks never cover that pair, so an allow there does nothing) and
  a caveat noting that every other DNS server in that zone stays reachable
  too. A foreign-only resolver set builds blocks-only, and
  `dns_order_is_safe(expect_allow=False)` accepts the intentional absence of
  an allow instead of rolling it back.

**Honest-coverage caveats added.** The LAN block covers the client zone's own
pair only. On a console with further populated LAN zones (the home console's
Vpn zone holds the Crosstalk Office network, for example), a full lockdown's
"no LAN" genuinely does not cut traffic to those zones. The tool now says so
on the review instead of overclaiming. Extending the blocks to one-per-LAN-zone
would close this and is left as a flagged follow-up — it multiplies policies
and touches release/attribution, so it should not ride along in a fix.

## BUILT 2026-09-17: editable mDNS scope from the matrix

The mDNS matrix cell is now editable. Presentation rule it was blocked on —
"a per-network switch must not quietly write site-scoped state" — is honoured
by the confirm dialog, which states that the toggle adds/removes the network
from the ONE site-wide Gateway mDNS Proxy list.

Mechanics: `UniFiClient.get_global_network_config()` /
`set_mdns_networks(ids)` on the v2 `global/config/network` route. The writer
always sends `{"mdns_enabled_for": "some", "mdns_enabled_for_network_ids":
[...]}` (partial payload, measured sufficient 2026-09-16) and verifies by
polling the stored list — never the 200. `mdns_effective_ids()` expands the
current config: "some" → stored list [Measured]; "all" → every non-WAN
network [Inferred from the UI's All-networks option, not measured — degrades
gracefully because removing one network under "all" writes "some" with the
rest]; anything else → empty.

**[Measured 2026-09-17]** Full round trip through the new code path on the
home console: removed the OpenClaw lab VLAN from a 4-network scope, stored
list confirmed without it, restored the original list, confirmed identical,
and the per-network `mdns_enabled` projection tracked both writes.

## MEASURED 2026-09-18: gateway-level DNS interception (CyberSecure)

**The field report.** At the studio, a Pi-hole + AdGuard setup silently
stopped being used after switching resolvers; disabling CyberSecure fixed it
(Encrypted DNS the prime suspect, Content Filter the other). Meanwhile
House Arrest's DNS Lockdown would have reported green throughout: every
firewall rule correct, resolution hijacked upstream of them.

**[Measured] API locations (home UCG-Fiber):**

- `rest/setting/doh` = CyberSecure Encrypted DNS. `{"state": "off",
  "server_names": [], "custom_servers": []}` when off; any other state means
  the gateway resolves through its own DoH upstreams.
- v2 `content-filtering` = per-filter docs with `enabled`, `categories`,
  `network_ids`, `client_macs`, `safe_search`. Redirects covered networks'
  DNS through UniFi's filtering resolvers.
- `rest/setting/ips` -> `ad_blocking_enabled` — ad blocking also intercepts
  DNS at the gateway.

**Built the same day:** `get_content_filters()` on the client;
`dns_interception_caveats()` + `content_filtered_ids()` (pure, tested);
StateResponse carries `encrypted_dns_on` / `ad_blocking_on` /
`content_filtered_network_ids` (None/empty = read failed = UNKNOWN, never
"off" — the null-result rule); the DNS tab shows a warning banner when
Encrypted DNS is on, a Content Filter chip on covered networks in the
picker, and all three appear as caveats on review.

## FIXED 2026-09-18: Default (untagged) network missing from the pickers

`list_networks()` excluded any network with `vlan: None` — a leftover from
the removed Quarantine preset, whose picker chose VLAN move targets. That
silently kept the untagged Default network out of DNS Lockdown everywhere
(spotted on NOMAD2, where Default is the primary network; reproduced at
home). WANs stay excluded; untagged networks now appear as "(untagged)".

## MEASURED 2026-09-29: switch isolation, per-device ACLs, and UniFi Objects

Test rig: two Raspberry Pis (`testclient` dc:a6:32:08:36:42, NOMAD10
d8:3a:dd:d1:e4:cf) on Guests (VLAN 10), moved between a USW-Pro-Max-16-PoE
(ACL-capable) and a USW Ultra (not). Topology: Ultra → Pro Max → Pro XG 8 →
UCG-Fiber. Each result below had a before/after control on the same ports.
Network 10.6.106. Scope decision the same day: **IPv6 is out of scope for
House Arrest** (the gateway serves no IPv6 on these LANs; the predefined
"Isolated Networks" rule matches IPv4 source subnets only — revisit if IPv6
is ever brought in scope).

### Device Isolation (ACL) — site-level list, switch-enforced  [Measured]

* Stored at `rest/setting` → `global_switch.acl_device_isolation` as a plain
  list of network ids. `acl_l3_isolation` sits beside it (list of
  source→destinations entries), plus an unexplained `switch_exclusions: []`.
* **Writable with the toolkit API key**: read-modify-write PUT of the whole
  `global_switch` doc to `rest/setting/global_switch/{_id}`; response echoes
  the change, re-read agrees, no other field changed. Pro Max applied it in
  ~10 s.
* Which switches enforce it is readable: `stat/device` →
  `switch_caps.max_custom_mac_acls` / `max_custom_ip_acls` / `max_global_acls`
  > 0 on exactly the switches the UniFi UI does NOT list as unsupported (Pro
  Max 16, Pro XG 8, Lite 8 PoE here); 0 or absent on Ultra, Flex, Flex 2.5G,
  Flex Mini, Industrial. This answers `[VERIFY]` #1 of the ACL section above:
  the Flex 2.5G generation is **not** ACL-capable.
* Results (Guests on the list vs off):

  | Layout | Same-VLAN peer traffic |
  |---|---|
  | both Pis on Pro Max | **blocked** (ARP FAILED, ping/nc fail; gateway fine) |
  | one on Pro Max, one on Ultra | **blocked** |
  | both on the same Ultra | **passes** despite the setting |
  | setting off, any layout | passes |

* The UI's "not applied to" note refers to the switch-level L3 setting, NOT
  the gateway's `network_isolation_enabled`: a Guests device on the Ultra
  still could not reach Default (gateway isolation holds). The existing
  Network isolation column is honest.
* Gateway network isolation blocks **both directions** (Default could not
  start connections into IDIoT/Guests either).

### Per-device MAC ACL rules (`v2/acl-rules`)  [Measured]

* CRUD with the API key: POST `v2/api/site/{site}/acl-rules` (201),
  DELETE `…/acl-rules/{id}` (200). Stored shape: `type: "MAC"`,
  `mac_acl_network_id`, `traffic_source` / `traffic_destination` each
  `{type: "CLIENT_MAC", specific_mac_addresses: [...]}` (empty = Any),
  `action`, `acl_index`, `specific_enforcers` ([] = all switches).
  User-created rules have **no description field** and names are capped at
  **32 chars** — a marker must live in the name.
* `acl_index` sent on create IS honoured (0 and 1 stored as sent). Answers
  `[VERIFY]` #3 above for the v2 route.
* **"Block source → Any" also blocks the gateway.** The device lost
  everything, SSH from the LAN included; restored 2 s after the delete.
* **Enforced in transit, not only at the edge port.** `testclient` on the
  (non-ACL) Ultra was still cut off, because its traffic crosses the Pro Max
  and Pro XG on the way to the gateway. Coverage = "an ACL-capable switch lies
  between the device and what it talks to", not "its own switch is capable".
* **The working per-device pattern:** `acl_index 0` ALLOW device → gateway's
  MAC *on that network* (`a8:9c:6c:90:e3:85` on Guests — NOT the device MAC
  `…:80` the controller reports), then `acl_index 1` BLOCK device → Any.
  Result: peer blocked (ARP INCOMPLETE), gateway / internet / DNS / HTTPS all
  working. Control after delete: peer reachable again.
* Wireless-to-wireless on one AP is still unmeasured (`[VERIFY]` #2 above).

### UniFi Objects (Object Oriented Networking)  [Measured]

Settings → Policy Engine → Objects, introduced in Network 9.4 (release
notes / LazyAdmin, not tested on 9.4 itself). House Arrest requires 9.0+, so
9.0–9.3 users lack it.

* API: POST `v2/api/site/{site}/object-oriented-network-config` (201), GET
  `…/object-oriented-network-configs`, DELETE `…-config/{id}` (204). All with
  the toolkit API key. Delete removes every generated rule.
* Compact document: `targets: [{type: "MAC", value}]`, `target_type:
  "CLIENTS"`, `secure.internet.mode` ∈ {TURN_OFF_INTERNET, ALLOWLIST,
  BLOCKLIST} with `everything: true` + `apps/domains/ip_addresses/regions`
  `{enabled, values}` and a `schedule`; `secure.local.mode` ∈ {INHERIT?,
  BLOCKLIST, ALLOWLIST, QUARANTINE}. `route` and `qos` blocks are REQUIRED
  even when disabled. Internet "allowed" is ALLOWLIST + everything;
  BLOCKLIST + everything means block all. Minimal accepted create body
  (as stored by the UI, `id` removed):

  ```json
  {"enabled": true, "name": "...", "target_type": "CLIENTS",
   "targets": [{"type": "MAC", "value": "aa:bb:cc:dd:ee:ff"}],
   "secure": {"enabled": true,
     "internet": {"mode": "TURN_OFF_INTERNET", "schedule": {"mode": "ALWAYS"}},
     "local": {"mode": "QUARANTINE"}},
   "route": {"enabled": false,
     "apps": {"enabled": false, "values": []}, "domains": {"enabled": false, "values": []},
     "ip_addresses": {"enabled": false, "values": []}, "regions": {"enabled": false, "values": []}},
   "qos": {"enabled": false, "all_traffic": true, "mode": "LIMIT",
     "apps": {"enabled": false, "values": []}, "domains": {"enabled": false, "values": []},
     "ip_addresses": {"enabled": false, "values": []}, "regions": {"enabled": false, "values": []},
     "download_limit": {"burst": "DISABLED", "enabled": false, "limit": 10000},
     "upload_limit": {"burst": "DISABLED", "enabled": false, "limit": 10000}}}
  ```

  An internet ALLOWLIST/BLOCKLIST block instead carries `"everything": true`
  plus the same four `{enabled, values}` lists.
* One Object expands into many `predefined: true` firewall policies
  (`origin_type: object_firewall_rule`, `origin_id` = object id, BLOCK by
  client MAC across every zone pair incl. **Internal → Gateway**) plus one
  predefined ACL (`origin_type: object_acl_rule`, device → **Any**, no
  gateway allow). No+Quarantine produced 13 policies; Quarantine-only 9.
  Quarantine-only produced **no Internal → Internal policy** — whether other
  VLANs in the same zone stay reachable is `[VERIFY]` (untestable from
  Guests, which is already isolated).
* **UniFi's Quarantine tooltip ("Isolate targets from the local network.
  Internet is unaffected.") is wrong on this setup.** Quarantine-only
  (internet ALLOWLIST + everything) killed gateway, internet and DNS in the
  same second it was saved, and peers ~30 s later when the ACL landed. Same
  result as No Internet + Quarantine. One device, on an isolated network —
  repeat on a non-isolated network before stating it publicly.
* Firewall rules land within ~4 s; the ACL half within ~30 s.

### Objects preset mapping, tested 2026-09-29 (afternoon)  [Measured]

`secure.local` has no INHERIT value: "Inherit" in the UI = the `local` key
omitted. Local ALLOWLIST/BLOCKLIST take `everything: true` plus `devices`,
`networks`, `mac_addresses`, `ip_addresses` `{enabled, values}` lists. All
three Objects below were created via the API with the toolkit key (201).

| Object | Generated | Peer | Gateway ping | Internet | DNS (Pi-hole) |
|---|---|---|---|---|---|
| No Internet, local omitted ("LAN only") | 3 BLOCK → External, no ACL | ok | ok | **blocked** | ok |
| Internet ALLOWLIST+everything, Local BLOCKLIST+everything ("Internet only") | 9 BLOCK (incl. Internal → Gateway, no Internal → Internal) + ACL pair | **blocked** | **blocked** | ok | ok |
| Quarantine (either internet mode) | 9–13 BLOCK + ACL device → Any | blocked | blocked | **blocked** | blocked |

* Local BLOCKLIST generates the ALLOW-then-BLOCK ACL pair automatically, and
  more completely than the hand-built one: the ALLOW lists the gateway's MAC
  on every network, broadcast `ff:ff:ff:ff:ff:ff`, and IPv6 multicast
  `33:33:00:00:00:02` / `33:33:00:01:00:02`. Quarantine omits the ALLOW —
  that is why it is a total cutoff.
* Local BLOCKLIST's Internal → Gateway BLOCK sits after only "Allow mDNS" in
  that pair, so traffic to the gateway itself is blocked — **including DHCP
  [Measured 2026-09-29]**. Under the Object, `sudo nmcli con up` failed
  ("IP configuration could not be reserved"; NM journal 12:22:38 "no lease").
  Object deleted 12:23:13; NM's own 5-minute auto-retry at 12:27:38 got a
  lease at once. So an "Internet only" device under Local Blocklist works
  until its lease expires (~24 h here), then has no address until the Object
  is removed. Any House Arrest use of Local Blocklist must add a DHCP allow
  (or not use it). Correction recorded: an earlier same-session report said
  the device "did not recover on its own"; the reachability poll had simply
  ended 79 s before NM's retry.
* Timing: firewall part ~4–10 s after save; ACL part ~10–30 s.
* Candidate mapping: LAN only → No Internet (local omitted) — matches exactly.
  Internet only → Allowlist+everything + Local Blocklist — matches except the
  gateway question. Full lockdown → No Internet + Local Blocklist — untested.
  "Let others still reach it" (block NEW only) — no Objects equivalent found.

### Objects on a NON-isolated network (HA-Test, VLAN 24)  [Measured 2026-09-29]

Repeat of the preset mapping with both Pis on HA-Test (192.168.3.0/24,
Internal zone, isolation off; DHCP hands out the GATEWAY as DNS — the UniFi
default). `testclient` 192.168.3.73 on Pro Max p3, NOMAD10 .74 on Ultra p3.
"Default LAN" = ping Pihole1 192.168.200.50 (another VLAN, same zone).
Created/deleted via API; 70 s hold, 50 s recovery; full recovery each time.

| Object | Peer | Gateway | Default LAN | Internet | DNS @gw | DNS @Pi-hole | HTTPS |
|---|---|---|---|---|---|---|---|
| Quarantine (internet allowed) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Local Blocklist (internet allowed) | ✗ | ✗ | **✓** | ✓ | **✗** | ✓ | **✗** |
| No Internet + Local Blocklist | ✗ | ✗ | **✓** | ✗ | ✗ | ✓ | ✗ |

* **Quarantine's "Internet is unaffected" is wrong on a normal network too**
  — now measured on both an isolated and a non-isolated VLAN. Safe to say.
* **"Local" in Objects means the device's own VLAN plus the gateway — NOT
  your other networks.** Local Blocklist left a different VLAN in the same
  zone fully reachable (no Internal → Internal policy is generated). So
  "No Internet + Local Blocklist" is NOT House Arrest's Full lockdown, which
  blocks the whole Internal zone.
* **Local Blocklist breaks name resolution on a default UniFi network.** It
  blocks the gateway itself, and by default DHCP advertises the gateway as
  the DNS server — so internet by IP works but anything using a hostname
  fails (HTTPS 000). On Guests it only looked fine because Guests' DHCP hands
  out the Pi-holes. Together with the DHCP block above, Local Blocklist is
  not a safe "Internet only" engine as shipped.
* Firewall part lands in ~2–5 s after save, ACL part in ~20 s; recovery after
  delete within ~10 s.

**Net for the engine decision:** only "LAN only" (No Internet, local omitted)
maps cleanly onto an Object. The other presets would need Objects plus
House Arrest's own allow rules (DHCP + gateway DNS) and its own Internal →
Internal blocks — at which point the Object is not simplifying anything.
Keep House Arrest's own enforcement for Internet only / Full lockdown; use the
hand-built ALLOW-gateway + BLOCK-Any ACL pair (with broadcast added, per the
list UniFi itself generates) for the optional same-VLAN block.

### Switch ACLs and Wi-Fi clients  [Measured 2026-09-29]

`testclient` wlan0 (dc:a6:32:08:36:43, IDIoT, AP U6+) vs VENGEANCE Wi-Fi
(IDIoT, AP U7-Pro-Max Attic). Uplink paths: U6+ → Ultra 210W → USW
Industrial; U7 Attic → USW Industrial; both → Pro Max [ACL] → Pro XG [ACL] →
gateway. The two APs meet at the Industrial, which has no ACL capability.

| ACL on testclient's Wi-Fi MAC | Wi-Fi peer | Gateway | Internet |
|---|---|---|---|
| none (baseline + control) | ok | ok | ok |
| ALLOW gw/broadcast + BLOCK Any | ok | ok | ok |
| BLOCK Any only (positive control) | **ok** | **blocked** (ARP INCOMPLETE) | blocked |

* Switch ACLs DO match Wi-Fi clients' traffic — but only where it crosses an
  ACL-capable switch. This answers `[VERIFY]` #2 of the ACL section: the
  "coverage = path" rule holds for wireless too.
* Consequence: a Wi-Fi device's coverage depends on where its peers' APs
  meet. Two devices on the SAME AP (not tested — predicted never to touch a
  switch) or on APs joined below any ACL switch are not covered; per-SSID
  Client Isolation is the only control for those.
* A coverage verdict must therefore be computed per device PAIR/path, or
  stated conservatively per device: "covered only for traffic that crosses
  <switch>". The honest one-line UI version is probably the conservative one.

### Port Isolation (per switch port)  [Measured + UI text]

`port_overrides[].isolation` on the switch device. UI (UniFi Devices → switch
→ port → Port settings): "Allows you to prohibit traffic between isolated
ports. This only applies to ports on the same device." Measured: with only
NOMAD10's USW Ultra port isolated, `testclient` on the Pro Max reached it
normally. The Ultra honours it (`port_table.isolation: true`) even though it
has no ACL capability. Out of scope for House Arrest (decided 2026-09-29).

### Consequence for the product (decided 2026-09-29)

House Arrest's value is being the easy, one-place front end and the honesty
layer — not the enforcement engine. The video stays "you can do all of this
in UniFi, but this makes it easy". Candidate direction, not yet built:

* Per-device lockdown could be expressed as a UniFi Object (so the UniFi UI
  and the tool can never disagree — the same principle as network
  isolation), BUT Quarantine as shipped over-blocks, so a "cut it off from
  its neighbours" option should use the measured ALLOW-gateway + BLOCK-Any
  ACL pair, not Quarantine, until UniFi's behaviour matches its tooltip.
* Coverage must be reported per device from `switch_caps` + uplink path, in
  one plain sentence. No ACL vocabulary in the UI.
* DNS Lockdown, the audit matrix, coverage verdicts and blocked-traffic
  attribution are the things UniFi does not provide; they are the product.
* Other controls surfaced by the settings walk, not yet evaluated: firewall
  destinations by App / Domain / Region; Simple App Blocking; Region
  Blocking; per-SSID PPSK, MAC filter and mDNS proxy; `lan/mdns` service
  filter (mDNS proxy passes only the selected service types); Default
  Security Posture (Allow All / Block All). Raw API dumps were kept out of
  the repo (home-network detail); re-dump rather than trust old copies.

## BUILT 2026-09-29: Device isolation column + per-device neighbour block

Local build for UI polish; not yet on `:edge`.

* **Networks matrix → "Device isolation" column.** Editable for local
  (`corporate`/`guest`) networks only — UniFi's own picker offers nothing
  else; VPN / transit rows show "—". Writes the site-wide
  `global_switch.acl_device_isolation` list (read-modify-write, poll-verified,
  `set_device_isolation_networks`). The cell never says a bare "On" when
  coverage is incomplete: "On · N of M", amber, from `switch_caps` + each
  online client's switch / AP uplink path (`network_isolation_coverage`).
  Verified end to end on HA-Test: toggled on from the tool, the Pro Max Pi lost
  its neighbour (0/3) and kept the gateway; toggled off, 3/3.
* **Devices tab → "Also cut it off from devices on its own network"**
  (Full lockdown and Internet only; LAN only refuses it, server-side too).
  Writes the measured ACL pair per network: ALLOW device → gateway LAN MACs +
  broadcast + IPv6 multicast (`acl_index` n), BLOCK device → Any (n+1), named
  `[HouseArrest] <label>` (32-char cap). Written after the firewall policies;
  any failure rolls back everything. Release deletes BLOCK before ALLOW and
  stops if a BLOCK delete fails, so a lone BLOCK (total cutoff) can never be
  left behind. State reports `neighbours` ok / broken / disabled and flags a
  lone rule as broken. Coverage verdicts (covered / partial / none / unknown)
  shown in the picker before applying and on the lockdown card, in plain
  sentences. Verified end to end: Internet only + neighbour block on
  `testclient` → neighbour and Default LAN blocked, gateway / internet / HTTPS
  working, card "Fully enforced"; release removed all 3 rules, connectivity
  restored. DHCP renewal under the pair not measured (needs sudo on the Pi);
  the pair allows gateway MACs + broadcast and House Arrest never blocks the
  Gateway zone, so it is expected to work `[VERIFY]`.
* Tests: `tests/test_house_arrest_acl.py` (23) on the measured topology.
* **Open for the polish pass:** the scenario infographics still draw "Same
  VLAN" green; a neighbour-block variant of each `(preset, inbound)` image is
  needed or the picture contradicts the list. Version must be bumped before
  `:edge` (asset cache-busting is keyed to it).

### Added 2026-09-29 (later): honest coverage on networks that can't do it

* **No capable switch on the site** (`site_acl_capable()` False — read from
  every device's `switch_caps`, never a model list): Device isolation cells
  read "Not supported" (grey, locked, even if switched on in UniFi); the
  neighbour checkbox is disabled with the reason and the Wi-Fi client
  isolation alternative; the toggle endpoint returns 409 and the lockdown
  endpoint refuses the neighbour block. None (unreadable) is unknown, never
  "not supported". Verified end to end against the live controller with a
  wrapper that zeroed every `switch_caps` (read + dry run only).
* **Capable switches exist but none of the selected devices are reached
  through one**: the lockdown endpoint refuses rather than writing rules that
  do nothing. Not exercised live (every device here reaches the Pro Max).
* **Shared switch port** → "Partly blocked": another wired client on the same
  `sw_mac` + `sw_port` means unmanaged gear or a VM host that UniFi can't see.
  Measured on this network: `bignas2` and `homeassistant` share one Pro Max
  port (HA as a VM on the NAS), so the wording names both causes.
* **Unfollowable uplink path → "Unknown", not "Not blocked".** Measured: the
  "UK Ultra Shed" AP still names "USW-Lite-8-PoE Tall Desk" as its uplink,
  a switch absent from every device list. Five devices were being reported
  "not covered"; they now read Unknown with the reason.
* Live distribution after these fixes: 80 online devices → 8 fully, 67 partly,
  5 unknown.

### Added 2026-09-29 (later): network settings vs per-device lockdowns

* **Decision: the Devices tab never writes an ALLOW.** Custom ALLOWs (10000s)
  evaluate before UniFi's predefined "Isolated Networks" BLOCK (30004), so a
  per-device exception would reopen an isolated network. The unused
  `build_exception` / `build_inbound_exception` were deleted.
* **Networks tab → isolation exceptions.** `isolation_exceptions()` lists every
  enabled custom ALLOW that gets through a network's isolation: outbound
  (source can be this network, destination another local network or "Any")
  and inbound (destination named inside this network; its generated
  "(Return)" policy sits ahead of the isolation block). The cell stays a green
  "On"; the hover names each one. Live on this network: Guests 3, IDIoT 4,
  OpenClaw 3 — including a leftover "TEST ANY to Elgato2" that opens
  192.168.107.133:8123 to every local network. Only the DNS-allow hole was
  measured (Guests → Pi-hole :53); the rest follow from rule ordering.
* **Devices tab → network-aware verdicts.** Each picker client carries its
  network's isolation / internet / Device Isolation flags and exception
  count. When every selected device's network agrees, the rows show the real
  result ("Blocked by its network settings, except 4 rules listed on the
  Networks tab"; "Only from its own network"); mixed selections get one note;
  a preset that can't deliver (Internet only on a no-internet network, LAN
  only on an isolated one) gets a warning under the preset choice.

## MEASURED 2026-10-01: the neighbour block cuts DNS to a same-VLAN resolver

Rig: `nomad10` (d8:3a:dd:d1:e4:cf, wired, Default 192.168.200.197, USW Ultra,
coverage "Partly blocked") resolving through Pihole1/Pihole2
(192.168.200.50/.51, same VLAN, on a USW Flex 2.5G; path crosses the
USW-Pro-Max-16-PoE). Preset: Internet only + neighbour block, allow_inbound
on. Applied and released three times via the toolkit API; every release
deleted all 3 rules and SSH returned within ~10 s.

| Check (cache flushed before name tests) | Before | Locked |
|---|---|---|
| Control: dig @1.1.1.1 over the internet | PASS | PASS |
| Gateway ping | PASS | PASS |
| DNS @Pihole1 / @Pihole2 (same VLAN), UDP and TCP | PASS | **FAIL** |
| DNS @gateway (.1) | PASS | PASS |
| System resolver (resolvectl, .50/.51) | PASS | **FAIL** |
| Internet by IP (ping 1.1.1.1) | PASS | PASS |
| HTTPS by name | PASS | **FAIL** |

Packet capture on nomad10 under the lockdown: queries leave addressed to
the Pi-hole's real MAC (dc:a6:32:2b:88:66) and nothing comes back, so the
block is at L2 on the Pro Max, as designed. ICMP and SSH to the Pi-hole fail
the same way. A same-VLAN neighbour (the workstation, 192.168.200.230) lost
SSH to nomad10 within ~30 s of applying.

* **Consequence:** "Internet only keeps its internet access" is false with
  the neighbour block on whenever the device's resolver sits on its own VLAN,
  the most common Pi-hole layout. The card still shows "Fully enforced".
  Before this was measured, the Devices tab checked no resolvers at all
  (resolver logic exists only in DNS Lockdown).
* **Failed probe, recorded so it isn't repeated:** the first probe scored DNS
  as PASS under lockdown. It checked `dig +short ... | grep -q .`, and dig
  prints its ";; communications error ... timed out" line to stdout, so a dead
  resolver matched. Name-based tests also passed off systemd-resolved's cache
  from the baseline run. A DNS check must require dig exit 0 AND an address
  in the answer, with the cache flushed (rule 9: a result is only evidence
  once the command is known to work).
* **Not measured, same shape `[VERIFY]`:** Internet only's firewall "no LAN"
  block should also cut DNS to a resolver on a *different* VLAN in the same
  zone, for a device on a network without a DNS Lockdown allow ahead of it.
  (Guests and IDIoT here both carry House Arrest DNS allows at lower indexes,
  which would mask it.) Disproof: Internet only on a device whose network
  advertises a cross-VLAN Pi-hole and has no DNS Lockdown; resolve by name.
* False alarm, same session: a policy name looked mojibaked (`â€”`) in
  output. It was the Windows pipe decoding UTF-8 as cp1252; decoded
  properly, the stored name is `—`.

### FIXED 2026-10-01: same-VLAN resolvers join the neighbour block's ALLOW  [Measured]

`same_network_resolvers()` reads the network's DHCP DNS (`dhcpd_dns_1..4`,
gated by `dhcpd_dns_enabled`), keeps the ones inside its own `ip_subnet`, and
maps each to a live client's MAC. Those MACs join the ALLOW beside the
gateway's. Resolvers on other networks need nothing here (they are routed
via the gateway, which the ALLOW already covers). A same-subnet resolver with
no known MAC (offline) makes the apply REFUSE with a plain reason, rather than
silently cut DNS. The picker (`neighbour_dns_note`) and card
(`neighbours_dns_note`, read back from the stored ALLOW rule by
`acl_allowed_resolvers()`, so it reports what is enforced) both say "DNS keeps
working: it can still reach pihole1 and pihole2 on its own network", plus
the honest caveat that an L2 rule can't filter by port.

Re-measured on the same rig, 14:58: under Internet only + neighbour block,
DNS @Pihole1/2, system resolver (cache flushed), and HTTPS by name all PASS;
gateway and internet PASS; the control held (the workstation, a same-VLAN
non-resolver neighbour, still timed out SSHing to nomad10 at 14:58:50,
between the two locked runs).

Side observation, resolved: the controller placed nomad10 on USW Ultra
Behind Network Rack at ~14:30 and on USW-Pro-Max-16-PoE port 7 from 14:58.
Chris confirmed he physically moved it during the session, so `stat/sta` was
correct both times (not a staleness bug). The move time wasn't recorded, so
which of the pre-fix runs (14:40-14:52) were on which switch is unknown; the
post-fix run (14:58) was on Pro Max p7 ("Fully blocked").

## MEASURED 2026-10-01 (afternoon): Internet only cuts cross-VLAN DNS, and the result depends on click order

Rig: `testclient` wired (dc:a6:32:08:36:42) on HA-Test (VLAN 24,
192.168.3.0/24, Internal zone, network isolation OFF), USW-Pro-Max-16-PoE
port 4. Pi-holes on Default (192.168.200.50/.51, same Internal zone, different
VLAN). Probe: raw DNS queries bound to eth0 (192.168.3.73) so the Pi's Wi-Fi
on IDIoT can't mask the result; a query passes only on a well-formed answer
with an A record. Negative-controlled first (a dead address and an NXDOMAIN
both score FAIL). Lockdown-live control: ping nomad10 (Default) must FAIL
while the device block is in force. No caching resolver on the Pi.

| Case | Rule order (Internal→Internal) | DNS @Pi-holes | System resolver / HTTPS by name | Internet by IP |
|---|---|---|---|---|
| 1. Internet only, no DNS Lockdown, DHCP DNS = gateway | block 10010 | **FAIL** | n/a (resolv.conf had the gateway first) | PASS |
| A. DNS Lockdown on HA-Test (DHCP → Pi-holes) applied FIRST, then Internet only | DNS allow 10010, device block 10013 | PASS | PASS | PASS |
| B. Internet only FIRST, then DNS Lockdown re-applied | device block 10013, **DNS allow 10014** | **FAIL** | **FAIL** | PASS |

Times: case 1 locked 15:24:07–15:26:04 (5 passes), recovered 15:26:34.
Case A locked 15:36:53–15:41:00 and again 15:59:23–16:00:07. Case B from
16:00:35 (allow created 16:00:25).

* **Case 1 confirms the `[VERIFY]` above:** Internet only's "no LAN" BLOCK
  (device → Internal zone, NEW/INVALID) stops DNS to a resolver on another
  VLAN in the same zone. A device whose DHCP points there loses name
  resolution while its card says "Enforcing".
* **Cases A and B: the same two features give opposite results depending on
  which is applied first.** New policies are appended to the end of their
  zone pair, so whichever rule is created later loses. DNS Lockdown verifies
  its allow precedes its OWN blocks only; nothing compares it with House
  Arrest's device blocks. In case B the device card said "Internet only,
  Enforcing", the DNS Lockdown row said "Enforcing", and
  `precedence_warnings` was silent (it only looks for USER allows ahead of
  our blocks).
* Guests and IDIoT avoid this today only because their DNS Lockdowns were
  created before any device lockdown on them.
* DNS Lockdown on HA-Test also blocks DNS to 1.1.1.1 (by design), so a
  public resolver can't serve as the probe's control once it is on.

## BUILT 2026-10-02: Devices tab redesign and the Internet only DNS fixes

Decided with Chris after the measurements above. Measured results for the
built code are still pending (see "Not yet measured" below).

* **Presets** (most to least permissive): Internet only, LAN only, No
  internet (the old `full_lockdown` key, relabelled from "Full lockdown"),
  Quarantine (new key `cut_off`). The inbound checkbox was removed: each
  preset fixes `inbound` in `PRESET_EFFECTS`; Quarantine is the only one that
  blocks it (connection_state_type ALL on both blocks). Quarantine always
  applies the neighbour block and degrades with a plain caveat when it can't
  (no capable switch, device unplaced); Internet only keeps it as the one
  checkbox and treats the same problems as errors, because the user chose it.
  Quarantine never allows same-VLAN resolvers in its ACL ALLOW: with no
  internet, a resolver hole is only an opening.
* **Why `cut_off` and not `quarantine`:** release() calls
  `requires_network(preset_from_policy(pol))` to clear the removed VLAN-move
  preset's override. Reusing the key would make releasing a new Quarantine
  try to undo a move that never happened. `preset_from_policy()` now matches
  "<label> for " exactly, longest first, so "Quarantine for X" and
  "Quarantine + VLAN move for X" can never be confused (the same shape as the
  2026-09-16 shadow bug).
* **Fix 1, ordering:** after a DNS Lockdown is created and its own order
  verified, `_requeue_shadowing_blocks()` re-creates any device "no LAN"
  block that sits ahead of a DNS allow covering that device's network (copy
  created and position checked before the original is deleted). Results are
  returned as `notices` and shown in the apply message.
* **Fix 2, Internet only DNS allow:** `device_dns_resolvers()` takes the
  device network's DHCP DNS, keeps resolvers on other networks in the same
  zone, and skips isolated networks (reported instead). The allow is created
  before the block; stored indexes are re-read and the lockdown rolled back
  if the allow landed behind.
* **Fix 3, health:** `get_state` flags a lockdown whose block sits ahead of
  one of its own DNS allows as `dns_blocked`, with a release-and-reapply
  suggestion.
* **UI:** a collapsible **Compare the presets** grid under the preset cards
  (built from preset effects); the verdict list + picture folded behind a
  **What this blocks** one-line summary that names both directions. Six
  scenario pictures instead of ten, all renamed from existing files. A
  plain-language pass replaced bare it/its/them and "resolver" across all
  three tabs (rule now in brand-voice.md, product docs mode).

### MEASURED 2026-10-02 (Chris driving the GUI, v0.15.6)

Rig as on 2026-10-01: wired `testclient` on HA-Test (DHCP DNS now the Default
Pi-holes, from the DNS Lockdown's DHCP option), probe bound to eth0, plus one
throttled HTTPS download started before Quarantine.

* **Fix 2 works.** Internet only applied with no DNS Lockdown on HA-Test
  created `testclient - DNS to its resolvers` (ALLOW, 10010) before its
  block. At 09:55:20, block live (ping nomad10 FAIL), Pi-hole DNS, the
  system resolver and HTTPS by name all PASS. Same setup failed 2026-10-01.
* **Fix 1 works.** DNS Lockdown re-applied with testclient still locked
  (test B order): allow created 09:55:40 at 10012, testclient's block
  re-created 09:55:41 at 10014. DNS PASS on every pass 09:55:46-09:57:06.
  The apply message read "Re-created the device lockdown for testclient so
  this DNS Lockdown's allow rule runs first and those devices keep their
  DNS." Test B failed on 2026-10-01.
* **Quarantine** 10:08:07 to ~10:45 (49 passes): internet by IP, HTTPS by
  IP and by name FAIL; other networks FAIL; neighbour block "Fully blocked";
  release restored everything by 10:45:58.
* **Quarantine cuts open connections (now Measured, was Inferred).** The
  download grew steadily to 10:08:11 and froze by 10:08:21, never resuming.
  (Earlier, an unlocked run of the same download ended by itself after 694 s,
  most likely a server-side limit on slow connections: unrelated.)
* **CORRECTION: Quarantine does not stop name lookups.** Gateway DNS PASS
  (the gateway zone is never blocked, by design), and DNS to the Pi-holes on
  Default PASS, because the HA-Test DNS Lockdown's network-scoped ALLOW
  (10012) runs before the Quarantine block (10014), the order Fix 1
  deliberately keeps. The doc line written earlier the same day, "Quarantine
  deliberately keeps none of these DNS paths open", was wrong and is
  replaced; the Quarantine caveat now says lookups still work and names the
  DNS-tunnelling path. **Decided (Chris): no behaviour change.** A
  quarantined device resolves names but cannot connect to anything on the
  internet, which is the protection that matters.
* Side note: `api/release` with kind=device and NO label would delete every
  device rule AND every DNS Lockdown rule (DNS policies are not network
  policies). The UI always sends a label, so it is unreached; worth
  tightening before anything else calls the endpoint.
