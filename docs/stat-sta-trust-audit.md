# stat/sta Location-Trust Audit — Wi-Fi Stalker, Network Pulse, Dashboard

Date: 2026-09-18 (overnight audit). Read-only — no code was changed.

## Scope and trust model

Measured background (House Arrest bench, 2026-09-16/17): `stat/sta` and the
Integration API both reported the wrong **network and IP** for a live client
(device on IoT-VLAN/.107.129 reported as "Default" with a null IP), while
v2 traffic-flow records carried the correct source address. `rest/user`
records are "last connection" data with an unreliable `last_seen`.

The nuance that shapes this audit: stat/sta is the controller's *radio/session*
table. Its **radio-level facts** (AP association, SSID, radio band, signal,
switch/port for wired) are what it is authoritative for, and no better source
exists. Its **L3 facts** (`ip`, `network`, `network_id`) are the measured-wrong
class. Its **row presence** (is the MAC listed at all) sits in between —
no measurement shows a live device missing from the list, but nothing
guarantees it either.

## Executive summary (worst first)

1. **[Stalker] A failed `rest/user` read is treated as "not blocked"** and the
   scheduler fires an `unblocked` webhook on the transition — a null result
   taken as evidence. Wrong-alert class, and it also flips the UI state.
2. **[Stalker] Online/offline is one poll's list membership with no debounce**
   — a single missed row fires a `disconnected` webhook, closes the history
   entry, and fragments presence analytics. (Inferred; no measurement of
   stat/sta dropping a live row, but there is no protection if it does.)
3. **[Network Pulse] Per-client signal displays `rssi`, not `signal`** — the
   exact console-mismatch already fixed in Wi-Fi Stalker in v1.9.17 (#60).
   Cosmetic but user-visible, and the fix is two lines.
4. **[Stalker] A transiently missing `ap_mac` mis-types the next event** —
   the device is marked connected without a history entry, and when `ap_mac`
   appears the tool fires `roamed` instead of `connected`.
5. **[Stalker/NP] Stored/displayed client IP and network come straight from
   stat/sta** — the measured-wrong fields. Cosmetic-to-history severity; the
   UniFi console shows the same values, so the tools at least never disagree
   with the console.

Everything else examined (counts, bands, SSID aggregation, top-client
bandwidth, AP tables, dashboard client_count) either uses radio-level facts
stat/sta is authoritative for, or matches what the console itself displays.
Notably, nothing anywhere builds timing logic on `rest/user.last_seen` — the
known trap is not present.

---

## Wi-Fi Stalker (tools/wifi_stalker/)

### WS-1: `is_client_blocked()` returns False on failure; scheduler fires webhooks on it

> **FIXED 2026-09-18:** returns Optional[bool] (None on failed read); the
> scheduler and device-detail endpoint skip the compare-and-fire on None.
- **Where:** `shared/unifi_client.py:654-679` (non-200 → `return False`; MAC
  absent from `rest/user` → `return False`), consumed by
  `tools/wifi_stalker/scheduler.py:428-437` (fires `blocked`/`unblocked`
  webhook on every transition of `device.is_blocked`).
- **Tier:** Read (both paths); the trigger condition (transient rest/user
  failure mid-poll) is Inferred.
- **Consequence:** (c) wrong alert. One non-200 (auth blip, controller
  restart) reads as "every blocked device is now unblocked": spurious
  `unblocked` webhook + UI flip, then a spurious `blocked` webhook next cycle.
  A device the controller has purged from its client DB reads permanently
  unblocked. This is the null-result rule verbatim: absence of the record is
  not evidence of an unblocked device until the read is known good.
- **Recommendation:** Make `is_client_blocked` return `Optional[bool]` (None
  for non-200/exception — keep False only for a *successful* read where
  `blocked` is falsy), and have the scheduler skip the compare-and-fire on
  None. Small, contained, no behavior change on the happy path.

### WS-2: Online/offline = single-poll list membership, no debounce
- **Where:** `tools/wifi_stalker/scheduler.py:225-231` (`client =
  active_clients.get(mac)`), offline branch at `:407-425` (closes history,
  fires `disconnected` webhook immediately).
- **Tier:** Read (mechanism); Inferred (that stat/sta ever transiently drops
  a live client — not measured, but one bad poll = one false alert).
- **Consequence:** (c) wrong alert + (b) wrong stored history — the
  connection-history entry is closed and a new one opened on reappearance, so
  presence analytics (`aggregate_hourly_presence`, AP time rollups) fragment.
  Also: one *failed* `get_clients()` call aborts the whole refresh (good —
  `:89` raises rather than treating empty as offline), so the exposure is a
  device missing from an otherwise-successful response.
- **Recommendation:** Flag only. If flapping is ever reported: require two
  consecutive misses before declaring offline (one extra column, no schema
  pain). Do not change silently — it alters alert timing users may rely on.

### WS-3: Missing `ap_mac` on an online wireless client mis-types the next event
- **Where:** `tools/wifi_stalker/scheduler.py:319` (`if ap_mac:` gates the
  entire connect/roam bookkeeping) then `:405` (`device.is_connected = True`
  unconditionally).
- **Tier:** Read (code path); Inferred (stat/sta serving a row without
  `ap_mac` during association — plausible, unmeasured).
- **Consequence:** (c) minor. Device flips to connected with no history entry
  and no `connected` webhook; next poll `was_offline` is False so the AP
  appearing registers as `roamed` — wrong event type, no offline-duration.
- **Recommendation:** Treat a wireless row without `ap_mac` as "not online
  yet" (skip the `is_connected = True`), or move the `was_offline` capture
  above the `if ap_mac:` gate. Either is a few lines.

### WS-4: `current_ip_address` trusted from stat/sta
- **Where:** `tools/wifi_stalker/scheduler.py:243-256` (`ip_address =
  client.get('ip')` → stored + broadcast), displayed in device list/detail.
- **Tier:** Measured class — this is the field stat/sta was measured
  reporting null/stale for a live device.
- **Consequence:** (a)/(b) — wrong displayed IP, wrong IP in the row the
  moment it matters (user clicks through to the device). No decisions or
  alerts hang off it.
- **Recommendation:** Leave as-is. The console shows the same value, and the
  traffic-flow fallback House Arrest uses is only available for devices with
  blocked traffic. Worth one line in README/UI ("IP as reported by the
  controller") at most.

### WS-OK: What checked out
- AP name, SSID, radio band, signal, switch/port — radio-level facts stat/sta
  is authoritative for; roaming detection compares `ap_mac`, not L3 fields.
- Signal uses `signal` with `rssi` fallback (`scheduler.py:245`) — the
  v1.9.17 fix is in place here.
- `network`/`network_id` from get_clients are *not* used by Stalker at all.
- Detail endpoint live fields (`routers/devices.py:178-201`) are rates/radio
  facts; fine.

---

## Network Pulse (tools/network_pulse/)

### NP-1: Per-client signal displays `rssi`, not `signal`

> **FIXED 2026-09-18:** both TopClient constructions use
> `client.get('signal') or client.get('rssi')`.
- **Where:** `tools/network_pulse/scheduler.py:187` and `:222`
  (`rssi=client.get('rssi')` into `TopClient`), rendered by
  `static/js/ap_detail.js:188-195` and the AP-detail client table.
- **Tier:** Read; the underlying `rssi`≠`signal` mismatch vs the console is
  Measured (that was #60, fixed for Stalker in v1.9.17 — `get_clients()` has
  captured both fields since).
- **Consequence:** (a) cosmetic, but it is the same bug a user already
  reported once against Stalker, now living in the sibling tool.
- **Recommendation:** `client.get('signal') or client.get('rssi')` in both
  TopClient constructions. Rename downstream only if cheap — the JS treats it
  as a dBm number either way.

### NP-2: Per-client `network` and `ip` display from stat/sta
- **Where:** `tools/network_pulse/scheduler.py:191,225` (`network=`), `:184,
  219` (`ip=`).
- **Tier:** Measured class (same fields as the bench misreport).
- **Consequence:** (a) cosmetic — client rows on AP detail pages can show a
  stale VLAN/IP. Matches the console's own display, so the two never
  contradict each other.
- **Recommendation:** Leave as-is; not worth traffic-flow plumbing for a
  display column.

### NP-OK: What checked out
- Client counts, wired/wireless split, by-band and by-SSID charts
  (`scheduler.py:145-152, 232-244`): list-membership aggregates, same source
  the console's own counters use. Cosmetic by construction.
- AP status table is `stat/device` data (uptime, satisfaction, num_sta) — a
  different, device-reported table; not in this trust class.

---

## Dashboard / shared (app/main.py, shared/unifi_client.py)

- `get_system_info()['client_count'] = len(get_clients())`
  (`shared/unifi_client.py:1248`): cosmetic count, matches console. OK.
- `get_client_by_mac()` (`:433-442`) is a thin lookup over get_clients; its
  consumers are the surfaces above.
- Nothing in `app/main.py` reads stat/sta directly.
- House Arrest already implements the preferred pattern (observed
  traffic-flow location first, stat/sta second, with the source labelled —
  `tools/house_arrest/routers/arrest.py`, ArrestSummary.location_source).
  WS-4/NP-2 deliberately do NOT copy it: those are display columns, and the
  flow fallback only exists for devices with blocked traffic.

## Suggested order if any of this gets built

1. WS-1 (null-result → spurious webhook) — small and it is the only finding
   where the tool actively tells the user something false.
2. NP-1 (rssi→signal) — two lines, closes a known reported bug class.
3. WS-3 (event mis-typing) — small; improves webhook fidelity.
4. WS-2 (debounce) — only with Chris's sign-off, it changes alert timing.
5. WS-4 / NP-2 — doc-note only.
