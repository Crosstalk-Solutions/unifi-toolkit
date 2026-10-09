# UniFi Toolkit

## Overview
FastAPI-based web dashboard for UniFi network management and monitoring. Deployed via Docker (Synology NAS, Unraid, etc.).

## Tech Stack
- **Backend:** Python 3.9+, FastAPI, SQLAlchemy (async, SQLite), Alembic migrations, aiohttp (UniFi API)
- **Frontend:** Jinja2 templates, vanilla JS (main dashboard), Alpine.js (Network Pulse)
- **Auth:** Optional session-based auth (production mode)

## Architecture
```
app/
├── main.py              # FastAPI app, /api/system-status endpoint, lifespan
├── __init__.py          # __version__
├── routers/             # auth, config endpoints
├── templates/           # Jinja2 (dashboard.html is the main UI)
├── static/              # CSS, JS assets
shared/
├── unifi_client.py      # UniFi API client (1800+ lines) — core data fetching
├── unifi_session.py     # Shared singleton session management
├── database.py          # Async SQLite via SQLAlchemy
├── cache.py             # In-memory cache with TTL
├── config.py            # Settings via environment
├── crypto.py            # Password/API key encryption
tools/
├── wifi_stalker/        # Client tracking tool
├── threat_watch/        # IDS/IPS monitoring
├── network_pulse/       # Network health dashboard (Alpine.js frontend)
├── house_arrest/        # Per-device + per-network lockdown via zone-based firewall
```

## Key Patterns

### Version Management
Version is maintained in THREE files — keep them in sync:
- `pyproject.toml` → `version = "X.Y.Z"`
- `app/__init__.py` → `__version__ = "X.Y.Z"`
- `app/main.py` → `version="X.Y.Z"` (FastAPI constructor)

### UniFi API Client (`shared/unifi_client.py`)
- **UniFi OS only** — legacy standalone controller support was removed in v1.11.0 (aiounifi dependency dropped)
- All API calls use `/proxy/network/api/` prefix via aiohttp
- Health endpoint returns subsystems: wan, wan2+, lan, wlan, vpn, www
- WAN detection is dynamic via `startswith('wan')` — supports N WANs
- **Signal strength:** UniFi API returns separate `rssi` and `signal` fields — use `signal` (matches console display) with `rssi` fallback
- **v2 traffic-flows payload:** The v2 endpoint supports a filtered payload format with `pageNumber`/`pageSize`/`timestampFrom`/`timestampTo` and a `policy_type` array for server-side filtering (e.g., `["INTRUSION_PREVENTION"]` for IPS-only events). The old `limit`/`offset`/`timeRange` format returns ALL flows unfiltered. Auto-detection via `_v2_uses_new_payload` flag handles both formats.

### House Arrest (`tools/house_arrest/`)
- Locks a device or a whole network down using zone-based firewall policies
- **`docs/house-arrest-design.md` is the source of truth** — it records every
  measured API behaviour and the corrections to earlier wrong assumptions. Read
  it before changing lockdown behaviour rather than re-deriving from the API.
- Core rule: the tool must never claim protection it is not delivering. Health
  checks, precedence warnings, blocked-traffic attribution and the measured
  caveat list all exist to enforce that.
- Every policy carries `[HouseArrest]` in its `description`; release deletes
  exactly those and refuses anything else. Sub-markers `[Network]` and `[DNS]`
  distinguish the policy kinds.
- Network isolation uses UniFi's native `network_isolation_enabled` /
  `internet_access_enabled` flags, NOT parallel policies, so the tool and the
  UniFi UI can never disagree.
- **Same-VLAN peer traffic never passes the gateway, so no FIREWALL POLICY sees
  it** — the tool's firewall-based presets cannot block it, and the Devices tab
  says so at full size. CORRECTED 2026-09-29: it is NOT unblockable in UniFi.
  Wired peers can be blocked by **switch ACLs** (site-level Device Isolation, or
  per-device MAC ACL rules), but only where an ACL-capable switch lies in the
  traffic path; Wi-Fi peers need per-SSID Client Isolation; a dedicated VLAN
  removes the peers. The earlier "only a dedicated VLAN or Client Isolation"
  wording was wrong. Details + measurements: design doc "MEASURED 2026-09-29".
  The Quarantine preset that moved devices was REMOVED 2026-09-17 (see the
  wired virtual-network override quirk). Do not confuse it with UniFi's own
  Objects "Quarantine", which is a different thing (see quirks below).
- **Direction (2026-09-29):** House Arrest is the easy one-place front end and
  honesty layer over UniFi's own controls, not a parallel enforcement engine.
  The video framing is "you can do all of this in UniFi, but this makes it
  easy". Keep switch ACLs, Objects, isolation lists etc. out of the UI
  vocabulary — one plain option and one plain coverage sentence.
- **IPv6 is out of scope for House Arrest** (decided 2026-09-29).
- **The Devices tab only ever ADDS restrictions — it never writes an ALLOW
  that could reopen something the Networks tab closed** (decided 2026-09-29).
  Custom ALLOWs evaluate before UniFi's "Isolated Networks" block, so a
  per-device exception silently punches through network isolation. The unused
  `build_exception` / `build_inbound_exception` builders were deleted for this
  reason. Users who need a hole write the firewall rule themselves; the
  Networks tab's isolation hover then lists it as an exception
  (`isolation_exceptions()`). The neighbour block's ACL ALLOW is L2-only and
  only to the gateway plus the network's own same-VLAN DHCP DNS servers, so
  it can't reopen anything across networks. The ONE firewall ALLOW the
  Devices tab writes (since 2026-10-02) is Internet only's DNS rule: this
  device -> its network's DHCP DNS servers on other VLANs, port 53 only,
  created before the block and index-verified after. It is never written on
  an isolated network (`device_dns_resolvers()` skips those), so it still
  can't reopen anything the Networks tab closed.
- **Devices tab presets (redesigned 2026-10-02):** Internet only, LAN only,
  No internet, Quarantine (most to least permissive). The inbound checkbox
  is gone; `PRESET_EFFECTS[...]["inbound"]` fixes it per preset (only
  Quarantine is False). Quarantine always applies the neighbour block;
  Internet only offers it as a checkbox. **Quarantine's key is `cut_off`,
  NOT `quarantine`** - that key still means the removed VLAN-move preset, and
  release() clears a VLAN override for it. "No internet" is the old
  `full_lockdown` key, relabelled; `LEGACY_PRESET_LABELS` keeps old "Full
  lockdown" descriptions recognised. `preset_from_policy()` matches
  "<label> for " exactly, longest label first (a bare startswith let
  "Quarantine" swallow "Quarantine + VLAN move").
- **A DNS allow must run before every device block it serves.** New
  policies append to the end of their zone pair, so a DNS Lockdown applied
  after a device lockdown landed behind it and cut the device's DNS
  (measured 2026-10-01, test B). `_requeue_shadowing_blocks()` re-creates
  such blocks after a DNS Lockdown (copy, verify, then delete the original);
  `shadowed_dns_allows()` drives both that and the `dns_blocked` health
  status.
- **The neighbour block must allow same-VLAN resolvers** (measured
  2026-10-01): without them, BLOCK device → Any cut a same-VLAN Pi-hole and
  Internet only lost name resolution while the card said "Fully enforced".
  `same_network_resolvers()` adds them; an unknown resolver MAC refuses the
  apply. When testing DNS, require `dig` exit 0 AND an address, with the
  resolver cache flushed: `dig +short` prints its timeout error to stdout.
- **Never stack a lockdown on itself.** `dns_locked_network_ids()` and
  `arrested_macs()` guard both apply paths; the DNS picker also greys out networks
  that already have one. This was a real bug — a 5-rule lockdown got applied twice.
- **Editability of an inspection-matrix cell is decided server-side**, per cell, via
  `EDITABLE_COLUMNS` plus a per-cell `editable` flag. The UI must never offer a
  switch the controller will ignore.
- Scenario infographics are one image per `(preset, inbound)` pair — six files
  (quarantine's two were deleted with the preset). If a preset changes, regenerate
  both of its images or the picture starts contradicting the verdict list. The
  network-isolation diagrams follow the same rule (one per isolation preset).

### Schema Repair (`run.py → _repair_schema()`)
- Runs on every startup after Alembic migrations
- Safety net for when `create_all` causes Alembic to stamp-to-head, skipping ADD COLUMN ops
- Must cover ALL migration-added columns — when adding a new Alembic migration that adds a column, also add it to `_repair_schema()`
- Uses `_add_missing_columns()` helper — pass table name and dict of `{col_name: col_sql}`

### Threat Watch Retention & Purge
- Events older than 30 days are auto-purged by the scheduler (runs at most once per hour, piggybacks on the 60s refresh cycle)
- `RETENTION_DAYS` and `PURGE_INTERVAL_SECONDS` constants in `tools/threat_watch/scheduler.py`
- Frontend defaults to 7-day view via `time_range` filter; backend supports `24h`, `7d`, `30d`

### Debug Info (`/api/debug-info`)
- Returns non-sensitive system info (versions, deployment, gateway, firmware) for issue reporting
- Dashboard footer has "Debug Info" link → modal with copy-to-clipboard
- "Report Issue" link also uses this endpoint to pre-populate GitHub issues

### Firmware Compatibility
- **Only stable/GA UniFi firmware is supported** — Early Access (EA) firmware frequently changes API endpoints without notice
- Do NOT suggest users switch firmware channels or attempt to support EA builds
- When users report API issues, firmware version is the first thing to check (now included in debug info)

### Data Flow (Dashboard)
```
UniFi Controller → unifi_client.py (get_health, get_system_info)
  → /api/system-status endpoint (main.py)
  → dashboard.html JS (fetches every 60s)
```

### Threat Watch Data Flow
```
UniFi Controller → get_traffic_flows() → _normalize_v2_event() (flattens to legacy field names)
  → get_ips_events() returns normalized events
  → scheduler.parse_unifi_event() → _parse_legacy_ips_event() (single parser for both v2 and legacy)
  → ThreatEvent DB model
```
All v2 events are normalized before the scheduler sees them — the scheduler only has one parser.

### Network Pulse
- Uses its own scheduler for background polling
- Alpine.js for reactive frontend
- Models in `tools/network_pulse/models.py`
- Extra WANs stored in `NetworkHealth.extra_wans` dict

## Completed Work

### v1.13.0 (branch `feat/house-arrest`, PR #122)
- Fix DNS lockdown false rollback — ordering is per zone pair, not site-wide
- Fix public resolvers silently killing DNS — one ALLOW per zone pair that holds one
- Fix blocked-attempt under-reporting — paginate `traffic-flows`, and stop discarding
  flows blocked by a since-replaced policy (one device was under-reported by 47%)
- Separate ephemeral-port UDP return traffic from real connection attempts; ICMP
  sweeps and any TCP/service-port probe always show
- Correct "You reaching in to it" → "Other devices reaching in to it"; `allow_inbound`
  is not scoped to one person
- Add Wi-Fi client isolation (`l2_isolation`), DHCP name server writes, duplicate
  guards, per-arrest preset chips, the current-DNS table on the DNS tab
- Warn when DHCP advertises a resolver the lockdown is about to block
- Dashboard: explicit 3-column grid, House Arrest ↔ Threat Watch swapped, info cards
  moved into the grid so it is two clean rows
- Correct the mDNS "unwritable" finding: it IS writable via v2
  `global/config/network`. The legacy `setting/mdns` routes discard the fields
  silently. Removed the on-screen text claiming the controller ignores the change.
  Column stays read-only because the control is site-level, not per-network.

### v1.13.0 (PUBLIC BETA since 2026-09-22 — on `main`/`:edge`, still untagged)
Beta announced on Discord 2026-09-22. Tag + GitHub Release come after the bake
(docs/RELEASING.md). Hold Dependabot PRs #125–129 until then — a mid-beta
dependency rebuild is how the v1.11.3 outage happened.
- **House Arrest 0.15.6 (`7190e56`, 2026-10-02)** — Devices tab redesign:
  four presets (Internet only, LAN only, No internet, Quarantine), inbound
  checkbox removed, compare grid + collapsible diagram; Internet only DNS
  fixes (cross-VLAN DNS allow, DNS Lockdown re-queues device blocks,
  `dns_blocked` health); plain-language pass on all three tabs. All live
  tests passed on testclient with Chris driving the GUI (design doc
  "MEASURED 2026-10-02"). Quarantine still lets name lookups through
  (gateway DNS, DNS Lockdown allows): decided acceptable, documented.
- **House Arrest 0.14.0 (`6bec3ec`, 2026-10-01)** — Device isolation
  column, per-device neighbour block, same-VLAN resolver fix.
- **`WEBHOOK_ALLOW_PRIVATE_IPS` env var (#124)** — opt-in for LAN webhook
  targets (Home Assistant, n8n, ntfy). The SSRF validator in
  `shared/url_validator.py` now splits ALWAYS_BLOCKED ranges (link-local,
  metadata, multicast) from PRIVATE ranges the flag can allow (RFC1918,
  loopback, CGNAT/Tailscale). Tests in `tests/test_url_validator.py`.
- House Arrest bumped to 0.13.0 and added to the run.py startup banner.

Earlier post-merge pass (after PR #122, cleared by JB's `:edge` run). Detail in
CHANGELOG.md and `docs/house-arrest-design.md`.
- **Zone-key fix** — resolve firewall zones by stable `zone_key`, not display
  name; scope DNS lockdowns to the chosen networks' actual `firewall_zone_id`
  and device lockdowns to the MAC's attributed zone; refuse mixed-zone
  selections; honest caveats for foreign-zone resolvers and other LAN zones.
- **Editable mDNS scope** from the matrix (writes the site-wide Gateway mDNS
  Proxy list via v2 `global/config/network`, poll-verified).
- **Networks tab consolidated** onto the editable matrix — removed the isolate
  dropdown flow + "currently isolated" list (two surfaces for one truth);
  isolation diagrams moved into the toggle confirm dialog (resulting-state).
- **Disabled-policy detection** — a rule toggled off in the UniFi UI now shows
  "not enforcing", never green (`check_breakage` returns `DISABLED`;
  `DnsLockdownEntry.disabled_count`).
- **DNS interception warnings** — DNS tab warns when CyberSecure Encrypted DNS
  / Content Filter / Ad Blocking is intercepting DNS at the gateway (competes
  with any resolver scheme; invisible to `traffic-flows`).
- **Untagged networks** (Default) now appear in DNS Lockdown — the `vlan is
  None` exclusion was dead code from the removed Quarantine preset.
- Always-visible DoH caveat on the DNS tab; Wi-Fi-isolation honesty note on the
  Devices tab (keyed to live SSID isolation state).
- DNS tab rebuilt as a two-column workbench; whitespace/symmetry pass; tooltip
  clipping fix; re-read button `undefined`-disabled fix; footer Report-an-issue
  + Docs links with real fallback hrefs.
- **Rogue Support** header button + `/rogue-support` promo page → live
  `rogue.support/toolkit` landing page, `TOOLKIT25` Stripe code (see
  [[rogue-support-help-button]]).
- Docs: new `docs/HOUSE-ARREST.md`, `docs/RELEASING.md`; pre-beta accuracy pass
  on README + platform docs; brand-voice scrub (no em-dashes in user docs).

### v1.11.3 (hotfix, tagged + released)
- Fresh pulls of `:latest` 500'd on every page (#123): a Dependabot merge
  rebuilt the 1.11.2 image under the OLD (push-to-main) publish workflow with
  unpinned deps → fastapi 0.141 / starlette 1.6, which dropped the old
  `TemplateResponse` signature. Fixed all 8 call sites to request-first,
  pinned `fastapi>=0.115.6,<0.116` + `starlette>=0.40,<0.42`, removed the
  conflicting `starlette>=0.47.2` line, and carried the tag-driven workflow.
  NOTE: the v1.11.3 tag tree accidentally contains the two internal audit docs
  (`git add -A` sweep; left in place with approval, now gitignored on `main` —
  see [[bulk-add-swept-audit-docs]]).

### v1.11.2
- Fix Network Pulse chart panels not resizing responsively (#96) — `min-width: 0` on `.chart-card` and `overflow: hidden` on `.chart-container` fix CSS Grid min-width:auto gotcha that prevented canvas-based chart cards from shrinking on narrow viewports
- Remove legacy standalone controller references from README and INSTALLATION.md (#97) — added UniFi OS requirement callout, removed port 8443 examples, lifted Python 3.13 restriction, reordered auth to lead with API key

### v1.11.1
- Fix Threat Watch missing geo/category data from v2 API (#79) — `source.region` mapped to country code (was looking for nonexistent `source.country`), `ips.category_name` mapped to category (was using `ips.ips_category` which only exists in `policies[]`)
- Document that `unifi.ui.com` cloud access is not supported — controller URL must be a local IP/hostname (README.md and INSTALLATION.md)
- Merged Dependabot PRs #93 (docker/metadata-action v5 → v6) and #94 (docker/build-push-action v6 → v7)
- Remove dead `_parse_v2_traffic_flow()` from Threat Watch scheduler — was unreachable since v2 events are pre-normalized to legacy format by `_normalize_v2_event()` before reaching the scheduler

### v1.11.0
- Drop legacy standalone controller support (#92) — removed aiounifi dependency entirely, all API calls now use direct aiohttp requests to UniFi OS endpoints
- Remove Python 3.13 version block from `setup.sh` — the aiounifi constraint was the only reason for the block
- Simplify `shared/unifi_client.py` — removed all `if self.is_unifi_os:` URL conditionals and legacy `else` branches
- Update Dependabot config — removed aiounifi ignore rules and Python version pinning

### v1.10.3
- Fix UAP-AC-LR model mapping (#89) — `U7LR` model code was incorrectly mapped to "U7 LR" (WiFi 7 product); corrected to "UAP AC LR" and added `G7LR` → "U7 LR" for the actual WiFi 7 U7 Long-Range AP
- Add access point model codes to debug info — `/api/debug-info` now includes AP names, raw model codes, and display names; shown in Debug Info modal and Report Issue template for faster diagnosis
- Closed #85 (all reporters confirmed on EA firmware — not supported)

### v1.10.2
- Enhance Threat Watch test-fetch diagnostics (#85) — test both v2 payload formats independently, capture rejection body, total flow count, sample flow keys, and nested structure for faster remote debugging
- Add gateway firmware version to debug info — `get_gateway_info()`, `/api/debug-info` endpoint, Debug Info modal, and Report Issue template
- Closed #90 (shipped in v1.10.1)
- #85 root cause identified for one reporter: Early Access firmware (UniFi OS 5.0.16, Network 10.2.78) — EA not supported, v2 traffic-flows endpoint doesn't exist on EA builds

### v1.10.1
- Add `_FILE` env var support for Docker Swarm secrets (#86) — reads secret values from files (e.g., `ENCRYPTION_KEY_FILE=/run/secrets/key`) for orchestrators that mount secrets as files
- Supported vars: `ENCRYPTION_KEY`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`, `DATABASE_URL`, `UNIFI_PASSWORD`, `UNIFI_API_KEY`
- `_FILE` takes precedence if both `VAR` and `VAR_FILE` are set
- Resolved at startup in `run.py` before `.env` loading, so all downstream code (pydantic-settings, `os.getenv()`) works without modification
- Merged Dependabot PR #88 (actions/stale v9 → v10)
- Fix Express in AP-only mode missing from Network Pulse AP detail list (#90) — `get_ap_details()` now includes `device_mode_override=mesh` check matching `get_access_points()` and `get_system_info()`
- Remove UI Product Selector card from dashboard (service shut down) — info cards moved to dedicated full-width `.info-row` for balanced 3+2 layout

### v1.10.0
- Add multi-WAN support to Network Pulse (#83) — per-WAN IP (click-to-reveal), throughput tabs, latency, and uptime for dual/multi-WAN setups
- WAN tab selector in Current Throughput section (hidden for single-WAN, zero visual change)
- Extra WAN entries in WAN Status card and Network Health panel with availability and latency
- Fix Threat Watch external links not opening (#79) — `@click.prevent` modifier was unconditionally blocking navigation on AbuseIPDB, VirusTotal, and Shodan links
- Closed #71 (shipped in v1.9.21), #78 (acknowledged, closed as not planned), #83 (shipped), #80 (moved to Discussions)
- #79 partially fixed (links); geo/category data issues pending reporter feedback on raw API response

### v1.9.21
- Fix UniFi Express in AP-only mode not detected as AP (#71) — Express reports `type: "udm"` with `device_mode_override: "mesh"` when in AP mode
- Skip Express with `device_mode_override: "mesh"` as gateway candidate in `get_system_info()`, `get_gateway_info()`, and `has_gateway()`
- Count Express in AP mode as AP in device counts and `get_access_points()`
- Merged PR #68 (greenlet dependency), closed PR #69 (auto dark mode — not needed after v1.9.19 theme fix)
- Closed #55 (user resolved), #75 (shipped in v1.9.20), #77 (shipped in v1.9.20)

### v1.9.20
- Add Threat Watch time range dropdown — 24h / 7d (default) / 30d filter in filter bar, scopes both events table and stat cards (#75)
- Add `time_range` query param to `/api/events` and `/api/events/stats` endpoints
- Auto-purge threat events older than 30 days — runs hourly via scheduler to keep DB size in check
- Fix Threat Watch webhook delivery — scheduler was calling WiFi Stalker's `deliver_webhook` instead of `deliver_threat_webhook`, causing `custom_message` kwarg error on real alerts while test webhooks worked fine (#77)
- Closed #66 (feature request — not planned), #73 (shipped in v1.9.19), #74 (shipped in v1.9.19)

### v1.9.19
- Remove placeholder text from form inputs for accessibility — users with cognitive disabilities may confuse placeholders with filled-in fields (#73)
- Replace format-hint placeholders with visible `<small>` hint text below inputs; add `aria-describedby` for screen readers
- Keep search box placeholders (standard UX pattern); remove all others across dashboard, login, WiFi Stalker, and Threat Watch
- Add "update available" notification badge in dashboard header (#74)
- New `/api/update-check` endpoint fetches latest GitHub release, compares against running version, caches result for 1 hour
- Badge appears left of theme toggle with version number and links to GitHub release page
- Graceful failure: badge silently hidden if GitHub is unreachable, network is isolated, or no GitHub releases exist yet
- Fix Network Pulse theme default — was defaulting to dark mode instead of matching dashboard's light default

### v1.9.18
- Fix Threat Watch getting 0 IPS events — use correct v2 traffic-flows payload format with server-side `policy_type: ["INTRUSION_PREVENTION"]` filtering instead of paginating all flows and filtering client-side (#63)
- Pass scheduler timestamps through to v2 API (previously hardcoded to `timeRange: "24h"`)
- Add backward-compatible fallback (`_v2_uses_new_payload` flag) for older firmware that may not support the filtered payload format
- Add `payload_format` diagnostic field to debug endpoint
- Fix WiFi Stalker table overflow — long hostnames no longer push delete button off-screen (#72)
- Add `curl` dependency check to `upgrade.sh` preflight (#70)
- Responded to #71 (Express in AP mode) requesting debug info from reporter

### v1.9.17
- Fix WiFi Stalker signal strength mismatch — use UniFi API `signal` field instead of `rssi` to match console display (#60)
- `get_clients()` now captures both `signal` and `rssi` fields; scheduler and client summary prefer `signal` with `rssi` fallback
- Closed #58, #62, #65 with v1.9.16 fixes confirmed

### v1.9.16
- Fix dashboard gateway detection: prioritize dedicated gateways over Express devices in AP mode (#58)
- Add `UDMA69B` as UX7 actual API model code — confirmed by reporter in #62
- Move `EXPRESS_MODEL_CODES` to module level in `unifi_client.py` for shared use between `get_system_info()` and `get_gateway_info()`
- Fix Network Pulse accessibility contrast — bumped `--text-muted` and `--text-secondary` to meet WCAG AA (#65)
- Add stale issues GitHub Actions workflow (7d stale warning, 7d auto-close)

### v1.9.15
- Fix schema repair to cover all 18 migration-added columns — existing users upgrading were hitting missing column errors (#64)
- Add UniFi Express 7 (UX7) IDS/IPS support — model code added to supported gateways (#62)
- Add "Debug Info" modal to dashboard footer — one-click copy of system info for issue reporting

### v1.9.14
- WiFi Stalker: display radio band (2.4/5/6 GHz) in Signal/Type column (#60 partial)
- Added `current_radio` column to TrackedDevice + Alembic migration
- Signal mismatch part of #60 resolved in v1.9.17

### v1.9.13
- Fix Threat Watch column sorting — wired up sort/sort_direction params from frontend to backend API (#61)

### v1.9.12
- Dynamic multi-WAN support for 3+ WAN interfaces (#59)
- Version sync across all three version files

## Known Environment Issues

- **`shared/unifi_client.get_clients()` returns a dict keyed by MAC, not a list.**
  Iterating it directly yields MAC strings, so `st.get(...)` either raises or
  silently counts nothing. Iterate `.values()`.
- **`run.py` does not enable auto-reload.** Jinja templates and static files are
  picked up on refresh, but any Python change needs the process restarted before
  it takes effect.
- **Packages can vanish from the system Python between sessions** (bcrypt went
  missing 2026-09-22, cause unknown — no venv, other tools share the install).
  If `run.py` dies with `ModuleNotFoundError`, re-run
  `pip install -r requirements.txt` before digging deeper.
- **House Arrest mounts at `/arrest/`**, not `/house-arrest` (see the
  `app.mount` calls in `app/main.py` for all tool paths).
- **`/api/debug-info` returns every `gateway` field as null** on both the local
  instance and NOMAD2 even while the controller is connected (seen
  2026-09-29). It is not a sign of a lost connection — use `/api/system-status`
  (`connected`, `gateway_model`) for that. Likely a debug-info bug; unfixed.
- **Bash heredocs choke on apostrophes in inline Python/JS** in this
  environment (`unexpected EOF while looking for matching '`). For any script
  with quotes in it, write it to the scratchpad with the Write tool and run
  the file. The same goes for Python one-liners that build JS strings: a
  `\'` inside a heredoc can come out as a bare `'` and break app.js, so run
  `node --check` on app.js after any scripted edit.
- **Live test rig for House Arrest DNS/lockdown tests** (2026-10-02):
  `testclient` wired on HA-Test (VLAN 24) at `csherwood@192.168.3.73`, key
  `~/.ssh/claude_hapi`; no sudo, no `dig` (use a Python raw-DNS probe with a
  negative control), and its Wi-Fi is also up on IDIoT, so bind probes to
  `eth0`. A lockdown can cut the SSH session: start probes as `nohup` jobs
  BEFORE applying and read the log after release.
- **`pkill -f <pattern>` over SSH kills its own session** when the pattern
  appears in the remote command line (it matched twice). Anchor it:
  `pkill -f "^python3 /tmp/ha_probe3"`.
- **`api/release` with `kind=device` and no `label` deletes every device
  rule AND every DNS Lockdown rule** (DNS policies are not network
  policies). The UI always sends a label, so it is unreached; tighten before
  anything else calls the endpoint.

- **`TemplateResponse` uses the request-first signature.** `TemplateResponse(request,
  "name.html", {...})`, never `TemplateResponse("name.html", {"request": request, ...})`.
  The old form was removed in starlette 1.0 and 500s every template route with
  `TypeError: unhashable type: 'dict'`. The new form works on 0.29+ and on 1.x.
  (Fixed in v1.12.0 — `requirements.txt` previously paired `fastapi>=0.115.6` with
  `starlette>=0.47.2`, which fastapi caps below, so pip jumped to a much newer
  fastapi and pulled starlette 1.x. A fresh install produced a dead app.)

## Troubleshooting UniFi API

### Reverse-Engineering Undocumented Endpoints
The UniFi v2 API is largely undocumented by Ubiquiti. When an endpoint isn't behaving as expected or you need to discover supported parameters:

1. Open the UniFi Network web UI in **Chrome**
2. Right-click → **Inspect** → **Network** tab
3. Navigate to the relevant page in the UI (e.g., Insights → Flows → Threats tab)
4. Find the POST request to the endpoint in the Network tab
5. Click it → **Payload** tab to see the exact JSON body the console sends

This is how we discovered the v2 `traffic-flows` filtered payload format (`policy_type`, `timestampFrom`/`timestampTo`, `pageNumber`/`pageSize`) — the console sends a completely different payload than what was publicly known.

### Known API Quirks

- **A 200 that echoes back an UNCHANGED document means the endpoint recognised
  none of the fields you sent** — wrong endpoint or wrong field names, not slow
  provisioning. This cost a session on mDNS: the v2 and legacy endpoints hold the
  same data under different field names (`mdns_enabled_for_network_ids` vs
  `enabled_for_network_ids`), and the legacy one accepts and discards the other's
  spelling. When a write "succeeds" and nothing changes, diff the field names
  against what a GET on that same endpoint returns before assuming a controller bug.
- **When an API route is a mystery, watch the console do it.** Chrome DevTools, or
  a fetch/XHR interceptor, on the real UniFi UI. Note the console often sends
  several requests per save and only one carries the change.
- The legacy `stat/ips/event` endpoint returns 0 on Network 10.x+ — effectively deprecated
- Express in AP-only mode reports `type: "udm"` (not `uap` or `ux`) with `device_mode_override: "mesh"` and `model: "UX"` — detect via `device_mode_override` field
- The `rssi` and `signal` fields are separate values; the console displays `signal`
- **The stored firewall policy `index` is not the one you send.** Indexes sent as
  10004/10005 came back as 10000/10003, colliding with an existing rule. Relative
  creation order was preserved in a later test. Verify stored indexes; never assume placement.
- **Policy ordering — and the `index` counter — is scoped to a (source zone,
  destination zone) PAIR, not the site.** Measured: two *enabled* policies both at
  index 10000, one Internal→Internal and one Internal→External. If ordering were
  site-wide that collision could not exist. Never compare indexes across zone pairs;
  a rule only competes with rules in its own pair. `PUT
  /v2/api/site/{site}/firewall-policies/batch-reorder` exists and requires
  `sourceZoneId` + `destinationZoneId`, which confirms the same thing.
- **A resolver must be allowed in the zone pair it is reached through.** An ALLOW in
  the Internal pair does nothing about a BLOCK in the Internal→External pair, so a
  public resolver (1.1.1.1) needs its own allow on the External side or the network
  loses DNS entirely — with every index check passing.
- **v2 `traffic-flows` returns BLOCKED flows only.** An active, unlocked client
  returns zero rows even with no `action` filter. It is the firewall log, not
  netflow — there is no "what is this device talking to" data unless a policy is
  already stopping it. `stat/stadpi` / `stat/sitedpi` return empty unless the user
  has enabled Traffic Identification, and blocked flows carry an empty `domains[]`.
- **`traffic-flows` paginates.** The response carries `has_next` and
  `total_element_count`; reading page 0 only truncated one device's 24h history by
  more than 20%.
- **mDNS is writable, but only via v2 `global/config/network`.** `PUT
  /proxy/network/v2/api/site/{site}/global/config/network` with
  `{"mdns_enabled_for": "some", "mdns_enabled_for_network_ids": [...]}` works
  (measured: write + restore round trip, API-key auth, no CSRF needed). A partial
  payload is enough. The legacy `rest/setting/mdns` / `set/setting/mdns` routes use
  the field names `enabled_for` / `enabled_for_network_ids` and silently discard
  them, returning 200 with the unchanged list - that field-name mismatch was the
  cause of the long-standing "toggle does nothing". `mdns_enabled` on a network
  document is still a read-only projection. Note mDNS is a **site-level** control
  (one shared VLAN list), not per-network, so any per-network UI writes shared
  state. A browser-session PUT returns 403 without a CSRF token; the toolkit's
  API key is unaffected.
- **`l2_isolation` on a WLAN (`rest/wlanconf`) IS writable** and is the only control
  found that reaches same-VLAN peer traffic. Verified True→False→restored on an SSID
  with no clients.
- **`dhcpd_dns_1..4` are plain strings** gated by `dhcpd_dns_enabled`, writable via
  the same read-modify-PUT as the boolean network flags — but verification must
  compare values, not truthiness, or `'8.8.8.8'` and `'1.1.1.1'` look equal.
- **UPnP has a site-wide master switch** (`rest/setting/usg` → `upnp_enabled`). While
  it is off, a network's `upnp_lan_enabled` does nothing.
- **`create_allow_respond` is sometimes refused when source and destination
  share a zone** — `FirewallPolicyCreateRespondTrafficPolicyNotAllowed`.
  CORRECTED 2026-10-08: not universal. A NETWORK → IP ALLOW in Internal →
  Internal was accepted with it and UniFi generated a predefined `(Return)`
  policy ahead of `Isolated Networks`. Which source shapes are refused is
  unmeasured; check the stored result. Otherwise use connection-state
  scoping instead: `connection_state_type: ALL | RESPOND_ONLY | CUSTOM`,
  `connection_states: NEW | RELATED | INVALID | ESTABLISHED`.
- **A saved per-client VLAN override is not a completed move.** A wired client keeps
  its VLAN and DHCP lease until it reconnects — measured unchanged for 150s+.
  Verify the client's actual network, not the write.
- **The per-client virtual-network override can HALF-APPLY on a wired client
  (measured 2026-09-17, why the Quarantine preset was removed).** After a reboot
  the wired Pi obtained a DHCP lease on the target VLAN (192.168.107.177) but had
  no working L2 at all: ARP to its own gateway and to a same-VLAN peer both failed
  ("destination host unreachable"), while `stat/sta` kept reporting the OLD
  network/IP (Default/192.168.200.234) and the UniFi UI showed network=IoT-VLAN with
  the old IP simultaneously. Do not build features on this override for wired
  clients; move wired devices by changing the switch port's network instead.
- **`stat/sta` and the Integration API can both report the wrong network for a client.**
  A device on 192.168.107.129/IoT-VLAN was reported as "Default" with a null IP by both.
  Traffic-flow data carried the correct source IP, network and subnet.
- **Controller changes provision asynchronously.** Verify writes by polling with a
  retry; a single immediate re-read reports false failures.
- **UniFi DNS policies (`integration/v1/.../dns/policies`) are site-wide.** No scoping
  field exists in the schema, so they cannot express per-device or per-VLAN behaviour.
- Integration API base is `/proxy/network/integration/v1`, the site id there is a
  **UUID** (not `default`), and the existing toolkit API key authenticates against it.
- Blocked traffic is queryable via v2 `traffic-flows` with `action: ["blocked"]`
  (lowercase enum; `BLOCK`/`BLOCKED` are rejected) and `source_mac`. Each flow's
  `policies[]` names the exact policy that blocked it, so blocks can be attributed by id.
- **Zones carry a stable `zone_key`** (`internal`/`external`/`gateway`/`vpn`/
  `hotspot`/`dmz`) that survives the user renaming the zone; each LAN network
  document carries `firewall_zone_id`. Resolve zones by `zone_key`, not display
  name (measured 2026-09-17). A VLAN is not a firewall zone — several VLANs share
  the Internal zone.
- **The gateway itself intercepts DNS in three ways, none visible to
  `traffic-flows`** (measured 2026-09-18): CyberSecure Encrypted DNS
  (`rest/setting/doh`, `state != "off"` → gateway resolves via its own DoH
  upstreams and a LAN Pi-hole silently stops being used); Content Filter (v2
  `content-filtering`, per-network docs with `enabled`/`network_ids`); Ad
  Blocking (`rest/setting/ips` → `ad_blocking_enabled`). A DNS lockdown can be
  fully green while resolution is hijacked upstream of every firewall rule.
- **A filtering resolver (Pi-hole/AdGuard) is invisible to the firewall too.**
  If it NXDOMAINs a domain a device needs, the gateway logs nothing — suspected
  cause of a Valheim crossplay failure under DNS lockdown (unconfirmed; disproof
  = check the resolver's own query log, not `traffic-flows`).
- **`is_client_blocked()` returns `Optional[bool]`** — `None` on a failed
  `rest/user` read. A failed read is NOT "unblocked"; callers must skip their
  compare-and-fire on `None` (a plain `False` fired spurious webhooks).
- **Alpine `:disabled` leaves the attribute in place when the expression is
  `undefined`** (only an explicit `false` removes it). A state object replaced by
  an API response lacking the bound key stays disabled forever — set the key
  explicitly. (This dead-disabled the House Arrest re-read button.)
- **A null result proves only where you looked.** "No Device Isolation field"
  was recorded as Measured after checking `rest/networkconf` only; the field
  was in `rest/setting` → `global_switch` all along, and the UI had it. Write
  negatives as "not on X, checked DATE". When a control is suspected, find it
  in the UniFi UI first, then trace which request the page makes.
- **Device Isolation (ACL)** = `global_switch.acl_device_isolation` (list of
  network ids; `acl_l3_isolation` beside it). Writable via PUT of the whole
  `global_switch` doc. Enforced only by switches with
  `switch_caps.max_custom_mac_acls > 0` — read that, never hardcode models.
- **MAC ACL rules (`v2/acl-rules`)**: "device → Any" also blocks the GATEWAY
  (total cutoff). Per-device peer isolation that keeps internet = ALLOW device
  → gateway MAC *for that network* (not the device MAC the controller shows)
  at `acl_index` 0, then BLOCK device → Any at 1. Enforced by any ACL-capable
  switch the traffic crosses, not just the edge port. No description field;
  32-char name limit.
- **UniFi Objects (`v2/object-oriented-network-config[s]`, Network 9.4+)** are
  fully API-writable and expand into many read-only `predefined` policies
  (`origin_type: object_*`, `origin_id`). **Objects "Quarantine" cut gateway,
  internet and DNS on 2026-09-29 despite its "Internet is unaffected" tooltip**
  (one device, isolated network — repeat before stating publicly). Local
  **Blocklist** is the well-behaved one: internet + DNS kept, peers blocked, via
  an auto ALLOW-gateway/broadcast + BLOCK-Any ACL pair — but it also blocks the
  gateway itself, **including DHCP (measured: no lease under the Object)** —
  the device drops off at lease expiry — and gateway DNS, which is the
  default DHCP-advertised resolver (HTTPS fails by name). "Local" also means
  only the device's own VLAN + gateway: other VLANs in the same zone stay
  reachable. "Inherit" = omit `secure.local`. Net (2026-09-29): only "No
  Internet, local omitted" maps cleanly onto a House Arrest preset (LAN only).
  **Decided 2026-09-29: House Arrest does not use Objects at all.**
- **The gateway's LAN MAC is not its device MAC.** LAN devices ARP the gateway
  as `network_table[].mac` (`…e3:85`, the same on every LAN here), not the
  `…e3:80` the controller reports as the device MAC. `ethernet_table[].mac`
  lists every interface. `P.gateway_lan_macs()` reads both — never match the
  gateway at L2 by the device MAC alone. (Corrects an earlier note that said
  the MAC "differs per network".)
- **Static assets are cache-busted by the tool version** (`app.js?v=0.13.0`).
  Changing JS/CSS without bumping House Arrest's version serves new templates
  with stale scripts to anyone who has loaded the page before (measured: Alpine
  "neighbourOffered is not defined"). Bump the version with any frontend change
  that ships.
- **UniFi's mDNS proxy filters by service type** (`v2/lan/mdns`, "Service
  Scope: Specific"). "mDNS on" in the matrix does not mean every service
  crosses.
