# UniFi Toolkit

## Overview
FastAPI-based web dashboard for UniFi network management and monitoring. Deployed via Docker (Synology NAS, Unraid, etc.).

## Tech Stack
- **Backend:** Python 3.9+, FastAPI, SQLAlchemy (async, SQLite), Alembic migrations
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
```

## Key Patterns

### Version Management
Version is maintained in THREE files — keep them in sync:
- `pyproject.toml` → `version = "X.Y.Z"`
- `app/__init__.py` → `__version__ = "X.Y.Z"`
- `app/main.py` → `version="X.Y.Z"` (FastAPI constructor)

### UniFi API Client (`shared/unifi_client.py`)
- Supports both UniFi OS (modern) and legacy controller APIs
- Auto-detects controller type during `connect()`
- UniFi OS uses `/proxy/network/api/` prefix; legacy uses `/api/`
- Health endpoint returns subsystems: wan, wan2+, lan, wlan, vpn, www
- WAN detection is dynamic via `startswith('wan')` — supports N WANs
- **Signal strength:** UniFi API returns separate `rssi` and `signal` fields — use `signal` (matches console display) with `rssi` fallback
- **v2 traffic-flows payload:** The v2 endpoint supports a filtered payload format with `pageNumber`/`pageSize`/`timestampFrom`/`timestampTo` and a `policy_type` array for server-side filtering (e.g., `["INTRUSION_PREVENTION"]` for IPS-only events). The old `limit`/`offset`/`timeRange` format returns ALL flows unfiltered. Auto-detection via `_v2_uses_new_payload` flag handles both formats.

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
- Returns non-sensitive system info (versions, deployment, gateway) for issue reporting
- Dashboard footer has "Debug Info" link → modal with copy-to-clipboard
- "Report Issue" link also uses this endpoint to pre-populate GitHub issues

### Data Flow (Dashboard)
```
UniFi Controller → unifi_client.py (get_health, get_system_info)
  → /api/system-status endpoint (main.py)
  → dashboard.html JS (fetches every 60s)
```

### Network Pulse
- Uses its own scheduler for background polling
- Alpine.js for reactive frontend
- Models in `tools/network_pulse/models.py`
- Extra WANs stored in `NetworkHealth.extra_wans` dict

## Completed Work

### v1.10.1
- Add `_FILE` env var support for Docker Swarm secrets (#86) — reads secret values from files (e.g., `ENCRYPTION_KEY_FILE=/run/secrets/key`) for orchestrators that mount secrets as files
- Supported vars: `ENCRYPTION_KEY`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`, `DATABASE_URL`, `UNIFI_PASSWORD`, `UNIFI_API_KEY`
- `_FILE` takes precedence if both `VAR` and `VAR_FILE` are set
- Resolved at startup in `run.py` before `.env` loading, so all downstream code (pydantic-settings, `os.getenv()`) works without modification
- Merged Dependabot PR #88 (actions/stale v9 → v10)

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
- The legacy `stat/ips/event` endpoint returns 0 on Network 10.x+ — effectively deprecated
- Express in AP-only mode reports `type: "udm"` (not `uap` or `ux`) with `device_mode_override: "mesh"` and `model: "UX"` — detect via `device_mode_override` field
- The `rssi` and `signal` fields are separate values; the console displays `signal`
