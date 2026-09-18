# House Arrest UX-Redundancy Audit — 2026-09-18

Lens: two control surfaces for one state, two displays of one truth, dead
weight, stale/duplicated copy, ordering confusion. Excluded by prior
agreement (already being fixed in a separate pass): the Networks-tab
isolation preset dropdowns + "Networks currently isolated" list, the Wi-Fi
section's conversion to a matrix-style table, and relocating the isolation
infographics into the toggle dialog.

All evidence tiers are **Read** (file:line cited) unless marked otherwise.

---

## F1 — HIGH: A disabled policy still shows as "Enforcing"

> **FIXED 2026-09-18** (same day): `check_breakage()` returns `disabled`,
> `DnsLockdownEntry` carries `disabled_count`, rows and trust strip render it.
> Measured live round trip: disable one Guests rule -> "1 of 5 rules disabled
> in UniFi" + alert; restore -> green, controller confirmed re-enabled.

**Lens 2 (two displays of one truth), and a violation of the tool's core
promise** (never claim protection that is not being delivered).

Nothing in the app reads `policy.enabled`:

- Device arrests: `check_breakage()` (`policies.py:1818`) checks only whether
  each MAC still exists in the client list. A policy toggled OFF in the UniFi
  UI keeps `status: ok` → green dot, "Enforcing".
- DNS lockdowns: `DnsLockdownEntry` (`models.py:155-163`) carries no enabled
  state at all, and the row hardcodes the green state
  (`index.html:500-503`: `<span class="state ok">…Enforcing`).

**Measured, real occurrence 2026-09-17/18:** Chris disabled
"House Arrest DNS: IDIoT — block other DNS (LAN)" in the UniFi UI while
troubleshooting. The live controller returned `enabled: false` for it while
the DNS tab showed that lockdown as "Enforcing".

**Smallest fix:** carry `enabled` through both paths — `check_breakage()`
returns a new `disabled` status when any policy in a set has
`enabled == false`; `DnsLockdownEntry` gains a `disabled_count`; both rows
render an amber "Partly disabled (N of M rules)" state instead of green.
(The "Networks currently isolated" list hardcodes "Enforcing" too, but it is
derived from UniFi's own native flags — if the flag is on, it is enforcing —
and that list is being removed anyway.)

---

## F2 — MEDIUM-HIGH: Networks tab copy still describes a read-only matrix

**Lens 4 (stale copy contradicting behavior).**

`index.html:130-147`: the chip says "CONTEXT", the heading asks "Is your
network already isolated?", and the card-note opens with **"Read-only audit
of your VLANs."** Since the editability work, the matrix toggles isolation,
internet access, and mDNS — and after the consolidation pass it becomes the
tab's *only* control surface. A user is told the table is read-only while
half its cells carry edit pencils.

**Smallest fix:** reword the card-note (e.g. "The live control panel for your
VLANs — green means locked down, and cells with a pencil can be changed right
here"), retitle the heading to match its new job, and retire or rename the
"CONTEXT" chip.

---

## F3 — MEDIUM: The same-VLAN explanation appears twice, back to back

**Lens 4 (explanatory copy repeated).**

On the Devices tab, `pathNote()` (`app.js:791-798`, rendered at
`index.html:897`) is a full paragraph explaining that same-VLAN peers never
pass the gateway and that the fix is a dedicated VLAN. Directly beneath it,
the blindspot box (`index.html:905-934`) explains the same mechanism and the
same two fixes at greater length. The blindspot box is the *deliberate*
full-size statement (per project rules); the pathNote paragraph is a second,
older rendering of the same content one scroll-line above it.

**Smallest fix:** delete the `path-note` paragraph and `pathNote()`. Keep the
blindspot box untouched.

---

## F4 — LOW-MEDIUM: Quarantine remnants in the UI layer

**Lens 3/4 (dead weight; stale references to a removed feature).** None of
this renders for users today, so severity is cleanup-only — but each remnant
is a trap for future edits:

- Legend item "Depends where you move it" (`index.html:874-881`), gated on
  `currentPreset().requires_network`, which no offered preset sets.
- Dead `networkId` state in JS, still sent as `network_id` on every lockdown
  request (`app.js:64, 927, 956, 974`).
- `moved` verdict branches (`app.js:779, 785-787`) with no preset that can
  produce them.
- `/networks` endpoint docstring still says "House Arrest moves a device into
  an existing VLAN" (`routers/arrest.py:936-941`).

**Smallest fix:** strip the legend item and the dead JS paths; correct the
docstring. Do NOT touch the server-side quarantine *recognition* (labels,
release, override cleanup) — that must stay for pre-removal policies.

---

## F5 — LOW: Header subtitle still pitches a single-purpose app

**Lens 5 (hierarchy/framing no longer matches).**

`index.html:35-39`: "Put a device under House Arrest: choose how to lock down
your device's LAN and WAN access…" — written when the app was per-device
only. The tool switcher directly below it says there are three tools, two of
which are network-wide. Mild dissonance for a first-time user.

**Smallest fix:** one broader sentence, e.g. "Lock down a device, a network,
or DNS — built from UniFi firewall policies and settings, reversible in one
click."

---

## F6 — LOW: The DHCP-mismatch trap is explained three times on the DNS tab

**Lens 4 (repeated copy) — partially by design.**

The same trap (rules police which resolver a device may TALK to; DHCP decides
which it is TOLD to use) is stated in the stale-address hint under the
current-DNS table (`index.html:579-585`), in the "Also point DHCP at these
resolvers" checkbox hint (`index.html:593-604`), and again in the server's
post-review caveats (`dhcp_dns_conflicts`). It IS the likeliest
self-inflicted outage, so emphasis is defensible, and the three statements
cross-reference each other coherently. Still, three tellings on one screen.

**Smallest fix (optional):** shorten the checkbox hint to one sentence and
let the table highlight + server caveat carry the detail. Fine to leave.

---

## Deliberate or acceptable — checked, not findings

- **Blindspot box at full size on the Devices tab** — by design (project
  rule); the *duplication* above it is F3, the box itself stays.
- **Verdict list + scenario image showing the same four verdicts** — same
  data drawn twice on purpose; alt text and captions are generated from the
  same rows, so they cannot drift.
- **DNS tab "What each network hands out now" table vs the Networks-tab DNS
  column** — same fact in two places, but labeled as such ("Same data as the
  Networks tab") and genuinely useful in context. Note: they arrive via two
  code paths (`/api/networks` vs `/api/inspect`), which is a latent drift
  risk; if either rendering ever changes, derive both from one field.
- **Existing DNS lockdowns listed above the creation form** — status where
  you act; the picker greys out covered networks from the same data. Fine.
- **Precedence warning riding the Devices tab only** — correct scoping,
  documented in-template.
- **Trust strip counting only device arrests** ("N under arrest") while DNS
  lockdowns and isolation live elsewhere — arguably undercounts "what is this
  tool doing right now", but the label is precise ("under arrest"). Revisit
  only if F1's disabled-state work touches the strip anyway.

## Cosmetic notes (invisible to users)

- Both confirm modals are defined inside `.matrix-wrap`
  (`index.html:210-288`) even though the Wi-Fi one serves a section far
  below; harmless (fixed positioning) but worth moving during the Wi-Fi
  table rework.
- HTML comment banners still carry the pre-redesign section numbering
  ("============ 3. Inspection ============" appears first on the page).
