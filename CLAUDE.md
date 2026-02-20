# UniFi Toolkit

## Project Overview
A suite of tools for UniFi network management, deployed via Docker.

**Current Version:** 1.9.11

## Tools

### Threat Watch (v0.5.0)
IDS/IPS monitoring dashboard for UniFi networks.
- Supports both Network 10.x (v2 traffic-flows API) and legacy firmware (stat/ips/event)
- **Ignore List:** Filter events by IP address and severity level to reduce noise from known devices
- Debug endpoint: `/threats/api/events/debug/test-fetch`

### Wi-Fi Stalker (v0.12.0)
Device presence tracking and monitoring.
- **SSID Tracking:** Shows which Wi-Fi network each device is connected to

### Network Pulse (v0.3.0)
Real-time network statistics and charts.

## Architecture

- **Backend:** Python/FastAPI with async SQLAlchemy
- **Frontend:** Vanilla JS with Chart.js
- **Database:** SQLite (default) or PostgreSQL
- **Deployment:** Docker Compose with Caddy reverse proxy

## Key Files

- `shared/unifi_client.py` - UniFi API client (supports UniFi OS + legacy controllers)
- `tools/threat_watch/scheduler.py` - IPS event fetching and parsing
- `tools/threat_watch/routers/events.py` - Threat Watch API endpoints
- `docker-compose.yml` - Docker deployment config

## UniFi API Notes

### Network 10.x Changes
- IPS events moved from `stat/ips/event` to v2 `traffic-flows` endpoint
- New endpoint: `POST /proxy/network/v2/api/site/{site}/traffic-flows`
- Events with IPS data have an `ips` object containing signature, category, etc.
- Legacy endpoint still works on older firmware

### Authentication
- API Key (recommended): `X-API-KEY` header
- Username/Password: Session-based with CSRF token

## Testing

```bash
# Run tests
pytest

# Test UniFi connection
curl -k -X POST -H "X-API-KEY: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"limit": 5, "timeRange": "24h"}' \
  "https://CONTROLLER_IP/proxy/network/v2/api/site/default/traffic-flows"
```

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python run.py

# Docker build and run
docker build -t unifi-toolkit:local .
docker run -d --name unifi-toolkit -p 8000:8000 \
  -v "C:/users/chris/claude/unifi-toolkit/data:/app/data" \
  -v "C:/users/chris/claude/unifi-toolkit/.env:/app/.env:ro" \
  --restart unless-stopped unifi-toolkit:local
```

## Current Local Test Environment

**Container:** `unifi-toolkit:local` running on port 8000

**Test Controller:** UCG-Fiber at 192.168.200.1
- Network version: 10.0.162
- Gateway model: UDMA6A8
- IDS/IPS: Enabled (IDS mode)
- API Key: `fqAWzoA26EjVN9VHIVy0XWZSr2Xq2-ju`

**Verified Working (v1.8.7):**
- v2 traffic-flows API returning IPS events
- Threat Watch scheduler polling and storing events
- Debug endpoint confirms v2 API in use
- Ignore List filtering by IP and severity

**Useful Endpoints:**
- Dashboard: http://localhost:8000
- Threat Watch: http://localhost:8000/threats
- Health: http://localhost:8000/health
- System Status: http://localhost:8000/api/system-status
- Threat Debug: http://localhost:8000/threats/api/events/debug/test-fetch

**Container Management:**
```bash
# View logs
docker logs unifi-toolkit --tail 50

# Restart
docker restart unifi-toolkit

# Stop and remove
docker stop unifi-toolkit && docker rm unifi-toolkit

# Rebuild after code changes
docker build -t unifi-toolkit:local . && docker restart unifi-toolkit
```

## Recent Session (2026-02-20)

### Issue Triage & Fixes (v1.9.11)
- **Fixed API key auth regression** (#55) — Merged community PR #57 from dvselas. The config modal rework in `f58d1e7` (collapsible legacy auth, removed "admin" default) caused `username: null` to be sent for API key users, but the Pydantic model required `username: str`. FastAPI returned 422. Fix: made `username` Optional, added validation that username+password are required when no API key. Also improved frontend error parsing (safeParseJson, formatApiError). 11+ users affected. Removed unrelated `greenlet` pin from requirements.txt that was included in the PR.
- **Fixed 1970 dates in Threat Watch** (#48) — Legacy API `timestamp` field is in seconds, `time` field is in milliseconds. Parser was dividing both by 1000, turning seconds values into 1970 epoch dates. Added `_normalize_timestamp()` helper that detects format by magnitude (>10 billion = ms). Applied to both legacy and v2 parsers.
- **Moved security headers to FastAPI middleware** (#54) — `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy` now set by `SecurityHeadersMiddleware` in `app/main.py` instead of Caddy config. Ensures headers present for bare Docker users. HSTS and `-Server` remain Caddy-specific.
- **Merged PR #56** — setup.sh portability fix: removed bash 4+ `${VAR^^}` syntax (from dvselas).
- **Merged PR #52** — Community Unraid setup guide at `docs/UNRAID.md` (from devzwf).
- Tagged `v1.9.11` and pushed.

### Open Issue Status
- **#58** — Wrong gateway: UniFi Express in AP mode detected instead of UDM Pro Max. Asked user for debug endpoint output. Likely a missing model code. Waiting.
- **#59** — Multi-WAN IP display: already supported (WAN2 rows hidden by default, shown when health API returns `wan2`). Asked user to confirm if it's working or share system-status output. Waiting.

### Notes
- CI builds `:latest` on every push to main (not just tags). This is how the config regression shipped before a tag was cut. Worth remembering for future — breaking changes on main go live immediately to `:latest` users.
- Community contributor dvselas is active — submitted both the config fix (PR #57) and setup.sh fix (PR #56). Good quality contributions.

## Previous Session (2026-02-19)

### Dashboard Layout Cleanup
- **Consolidated info section into tools grid** — moved "About UI Toolkit" and "Getting Started" cards from a separate section below the tools grid into the grid itself, filling empty slots next to UI Product Selector on wider screens.
- **Removed System Requirements card** — redundant for users who already have the app running.
- Rogue Support banner shifts up naturally with the info section gone.
- CSS: replaced `.info-section` / `.info-card` with `.info-card-grid` class inside the tools grid.

## Previous Session (2026-02-16)

### Wi-Fi Stalker SSID Tracking (v0.12.0)
- **Added SSID tracking** (#43) — user aszajlai requested SSID and VLAN visibility. SSID was already in the UniFi API response (`essid` field) but never stored or displayed. Added `current_ssid` to `TrackedDevice`, `ssid` to `ConnectionHistory`, display in device table (parenthesized after AP name), detail modal, connection history, CSV export, and search filter.
- **Schema repair** — added SSID columns to `_repair_schema()` in `run.py` to handle the stamp-to-head edge case where Alembic skips ADD COLUMN operations on existing tables.
- **Migration:** `alembic/versions/20260216_0000_add_ssid_to_wifi_stalker.py` (revision `a3f8d1c4e9b2`, down from `785d812e2ea3`)
- **Tested** against local UCG-Fiber controller — SSID `IDIoT` confirmed showing for Pixel-8 on all endpoints.
- Closed #43, commented with feature summary.

### Issue Triage & Fixes (v1.9.8)
- **Added Gateway Max (`UXGB`)** to `IDS_IPS_SUPPORTED_MODELS` and `UNIFI_MODEL_NAMES` (#35) — user kenpratte reported Threat Watch saying "Gateway Max doesn't support IDS/IPS" despite IPS being enabled. Same pattern as the UXG Fiber fix.
- **Fixed legacy controller port detection** (#40) — `_try_legacy_login()` defaulted to port 8443 when no explicit port in URL. For users running self-hosted controllers on port 443 (e.g. `jacobalberty/unifi-docker` with `UNIFI_HTTPS_PORT: 443`), the legacy fallback would try port 8443 and fail. Now uses scheme default (443 for https, 80 for http). User ThomDietrich confirmed the 401→verify→legacy fallback path works but legacy login was hitting wrong port.
- **Replied to #42** (Teams webhook request) — pointed user to generic webhook approach via Teams incoming webhooks/Power Automate. No native integration planned.
- **Re-closed #30** (UDM SE) — user masterofdesasterit confirmed read-only SQLite permissions fix resolved all symptoms (missing events, can't add Wi-Fi Stalker clients, config save failure).
- Tagged `v1.9.8` and pushed.

### Open Issue Status
- **#35** — 516Noord (UXG Fiber) fixed. northwarks (UDM Pro) parked — lost Integrations menu after UniFi OS 5.0.12 update, can't create API key, waiting on firmware. kenpratte (Gateway Max) fix shipped in v1.9.8.
- **#40** — ThomDietrich's self-hosted controller auth. Port fix shipped in v1.9.8. Awaiting confirmation. Also has non-default site ID (`rmwkckxb`).
- **#42** — Teams webhook feature request. Replied with generic webhook workaround. Not planned for native support.
- **#43** — Closed. SSID tracking shipped in Wi-Fi Stalker v0.12.0. VLAN ID declined (SSID maps to VLAN already).
- **#26** — sharknitsh-web confirmed working after Synology image cache issue resolved.

### Notes
- Legacy controller support is on thin ice — Chris has considered removing it entirely. Not investing heavily in legacy-specific bugs beyond simple fixes.
- Recurring theme: users confused by UNIFI_* env vars in `.env` that are dead code. Template cleaned up but some users still hit old docs/examples.
- Synology users frequently have stale image cache issues — Synology Container Manager doesn't auto-pull latest.

## Previous Session (2026-02-12, evening)

### Issue Triage & Fixes (v1.9.2)
- **Fixed legacy controller SSL regression** (#26) — v1.9.1 removed the `ssl_context` variable but left a reference to it in `_try_legacy_login()` call at line 256 of `unifi_client.py`. Caused NameError that broke ALL legacy controller connections. Fixed by passing `ssl_param` instead. User sharknitsh-web confirmed the regression; still waiting on confirmation of v1.9.2 fix.
- **Fixed FastAPI deprecation warnings** (#32) — `Query(regex=...)` deprecated in favor of `Query(pattern=...)`. Fixed in `devices.py:563` and `events.py:262`.
- **Closed resolved issues** — #21 (UDR7 confirmed fixed), #28 (U7 Pro XGS fixed in v1.9.0), #30 (UDM SE explained — Threat Watch only pulls IPS events, not DNS filtering/ad blocking)
- **Replied to #32** (container won't start) — SQLite "unable to open database file" is a volume mount issue. User needs `data/` directory created and writable by UID 1000.
- **Replied to #34** (k8s .env not loading config) — explained that UNIFI_* env vars in `.env` are unused at runtime; config lives in the database and must be submitted via the web UI once. User got it working with PVC + Volsync backups.
- **Closed #31** (minimal docker-compose) — provided a compose example without Caddy/setup script.
- **Closed PR #33** (Python 3.13+ bump) — rationale cited aiounifi dependency which this project doesn't use directly; 3.13+ minimum too aggressive for LTS distros.
- Tagged `v1.9.2` and pushed.

### Architecture Notes
- **Config loading:** UNIFI_* env vars in `.env` are loaded into `ToolkitSettings` (Pydantic) but never read at runtime. All UniFi credentials come from the `unifi_config` DB table (single row, encrypted with ENCRYPTION_KEY). The config form must be submitted once via the web UI to seed the database.
- **Platform scope:** Docker is the supported deployment method. Not maintaining platform-specific configs for Kubernetes, Helm, etc. — users can adapt the minimal docker-compose example.

## Previous Session (2026-02-12)

### Issue Triage & Fixes (v1.9.0, v1.9.1)
- **Fixed UDR7 IDS/IPS detection** (#21) — UDR7 reports model code `UDMA67A` via API, not `UDR7`. Added `UDMA67A` to `IDS_IPS_SUPPORTED_MODELS` and `UNIFI_MODEL_NAMES`. Debug output from user confirmed the mismatch.
- **Added U7 Pro XGS device name** (#28) — model code `UAPA6A4` was showing raw code in Network Pulse instead of friendly name. Added to `UNIFI_MODEL_NAMES`.
- **Fixed verify_ssl DB default** (#26) — SQLAlchemy default was `True` but Pydantic default was `False`. Changed DB default to `False` since most UniFi deployments use self-signed certs. Replied with instructions to re-save config with SSL verification unchecked.
- **Linked community QNAP guide** (#29) — user contributed full QNAP Container Station deployment guide. Added links in README.md and docs/INSTALLATION.md.
- **Replied to #27** (Raspberry Pi 5) — Docker should work on ARM64 but untested on Pi.
- **Replied to #30** (UDM SE Threat Watch) — asked for debug endpoint output.
- Tagged `v1.9.0` and pushed to trigger Docker image builds.
- **Fixed SSL verification for self-signed certs** (#26) — `ssl.create_default_context()` with `CERT_NONE` could enforce TLS version/cipher requirements that legacy controllers don't meet. Replaced with aiohttp's `ssl=False` which skips verification entirely. Removed unused `import ssl`. Tagged `v1.9.1`.

## Previous Session (2026-02-11, evening)

### Docker Version Tagging & Issue Triage
- **Added git tag `v1.8.9`** and pushed to trigger versioned Docker image builds (GitHub #24). CI workflow already had `type=semver` patterns in `docker/metadata-action` — just needed actual tags. Images now tagged `1.8.9`, `1.8`, `latest`, and commit SHA.
- **Closed #25** (camera privacy toggle) — out of scope, toolkit focuses on UniFi Network not Protect/surveillance.
- **Replied to #21 reopening** (UDR7 Threat Watch) — user on Synology likely pulling cached pre-fix image. Synology Container Manager updates images ~once/day; told them to watch for "Update Available" badge and verify v1.8.9 via footer or `/health`.

## Earlier Session (2026-02-11)

### Bug Fixes & New Device Support (v1.8.9)
- **Fixed gateway detection for Express AP users** — `get_gateway_info()` in `shared/unifi_client.py` was matching UniFi Express (type `ux`) before actual gateways (`ugw`, `udm`, `uxg`). Now does two-pass: dedicated gateways first, Express as fallback for standalone setups. (GitHub #19)
- **Fixed dark mode chart legend in Wi-Fi Stalker** — Chart.js `generateLabels` callback wasn't passing `fontColor`, so legend text fell back to global default `#666`. Added `fontColor: textColor` to each generated label in `tools/wifi_stalker/static/js/app.js`. (GitHub #18)
- **Added Dream Router 7 (UDR7)** to `IDS_IPS_SUPPORTED_MODELS` and `UNIFI_MODEL_NAMES` in `shared/unifi_client.py`. (GitHub #21)
- **Closed PR #20** — incorrect DATABASE_URL path change (would have double-nested to `/app/app/data/`)
- **Debian 13 Trixie note** — ships Python 3.13 which hits the `setup.sh` version block. Docker is the recommended path.
- FastAPI version string in `app/main.py` was stale at 1.8.5, updated to 1.8.9

### Unraid Template & Flexible Config (v1.8.8)
- Added `unraid/unifi-toolkit.xml` template for Unraid deployment
- Updated `run.py` to skip `.env` file requirement when env vars are passed directly (supports Unraid, Portainer, Kubernetes)
- Responded to GitHub issues #16 (Unraid template - done) and #17 (Proxmox helper script - declined, closed)

### Docs & Security Sweep
- Removed Claude Code agents sections from README.md and CHANGELOG.md
- Fixed stale test counts in README and CHANGELOG (22/18/13/15)
- Added missing v1.8.7 changelog entry for Threat Watch v0.5.0 Ignore List
- Updated FastAPI version string from 1.5.2 to 1.8.5 in `app/main.py`
- Fixed `chmod 777` → `chown 1000:1000 || chmod 755` on data dir in `setup.sh`
- Security audit confirmed: no secrets in git history, .env never committed, auth middleware gates all non-public paths including debug endpoint
- Network Pulse version in code is 0.3.0 but CHANGELOG only documents up to 0.2.0 (gap to fill)

## Repository
https://github.com/Crosstalk-Solutions/unifi-toolkit
