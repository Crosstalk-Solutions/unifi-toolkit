# Changelog

All notable changes to UI Toolkit will be documented in this file.

## [1.9.17] - 2026-02-21

### Fixed
- **Wi-Fi Stalker signal strength mismatch** - Use UniFi API `signal` field instead of `rssi` for accurate dBm display that matches the UniFi console. `get_clients()` now captures both fields; scheduler and client summary prefer `signal` with `rssi` fallback. (#60)

---

## [1.9.16] - 2026-02-21

### Fixed
- **Dashboard gateway detection** - Prioritize dedicated gateways over UniFi Express devices in AP mode, preventing misidentification when both are present. (#58)
- **Network Pulse accessibility** - Bumped `--text-muted` and `--text-secondary` color contrast to meet WCAG AA requirements. (#65)

### Added
- **UX7 actual API model code** - Added `UDMA69B` as reported model code for UniFi Express 7, confirmed by community reporter. (#62)
- **Stale issues workflow** - GitHub Actions workflow to auto-mark issues stale after 7 days of inactivity and close after 7 more days.

---

## [1.9.15] - 2026-02-20

### Fixed
- **Schema repair coverage** - Expanded `_repair_schema()` to cover all 18 migration-added columns across 4 tables. Existing users upgrading were hitting missing column errors. (#64)

### Added
- **UniFi Express 7 (UX7) IDS/IPS support** - Added UX7 model code to the Threat Watch supported gateways list. (#62)
- **Debug Info modal** - Dashboard footer now has a "Debug Info" link that opens a modal with non-sensitive system info (version, deployment type, gateway) and one-click copy-to-clipboard for issue reporting.

---

## [1.9.14] - 2026-02-20

### Added
- **Wi-Fi Stalker radio band display** - Signal/Type column now shows the radio band (2.4 GHz, 5 GHz, 6 GHz) for each tracked device. Added `current_radio` column to TrackedDevice with Alembic migration. (#60)

---

## [1.9.13] - 2026-02-20

### Fixed
- **Threat Watch column sorting** - Wired up `sort` and `sort_direction` parameters from the frontend to the backend API, enabling clickable column headers in the events table. (#61)

---

## [1.9.12] - 2026-02-20

### Added
- **Dynamic multi-WAN support** - Dashboard and Network Pulse now display 3+ WAN interfaces dynamically instead of being hardcoded for dual-WAN. (#59)

---

## [1.9.11] - 2026-02-20

### Fixed
- **UniFi Express detection** - Detect Express devices by model code instead of device type for more reliable identification. (#47)
- **Legacy IPS timestamps** - Handle both seconds and milliseconds timestamp formats in legacy IPS events. (#48)
- **Security headers** - Moved security headers (X-Content-Type-Options, X-Frame-Options, etc.) from Caddy to FastAPI middleware so they apply in both local and production deployments. (#54)
- **API key auth** - Username is now optional when using API key authentication; improved config error handling. (#55)
- **setup.sh portability** - Removed bash 4+ syntax for compatibility with older systems (macOS, some NAS platforms). (#56)

### Changed
- **Dashboard layout** - Consolidated info cards into the tools grid and removed standalone System Requirements card.
- **Config modal** - Legacy auth (username/password) section is now collapsible, defaulting to the cleaner API key flow.

---

## [1.9.9] - 2026-02-17

### Added
- **Wi-Fi Stalker SSID tracking** - Track which SSID each device connects to. Added `current_ssid` field to device data and connection history. (#43)

### Fixed
- **Gateway Max support** - Added UXGB model code to supported gateways. (#40)
- **UXG Fiber support** - Added UXGA6AA model code to IDS/IPS supported models. (#35)
- **Legacy controller port detection** - Fixed issue where port was not correctly detected for self-hosted controllers. (#35)

---

## [1.9.7] - 2026-02-15

### Changed
- **Shared UniFi session** - All three schedulers (Threat Watch, Wi-Fi Stalker, Network Pulse) now share a single persistent UniFi controller session instead of each creating a new connection every polling cycle. This reduces login attempts from 3/minute to 1 total, preventing fail2ban lockouts on username/password auth controllers. The session reconnects automatically if it goes stale and invalidates when config is saved via the web UI. (#35)

---

## [1.9.5] - 2026-02-13

### Fixed
- **Docker: python-dotenv not found on some platforms** - The multi-stage Docker build installed Python packages to user site-packages (`~/.local`), which depends on Python's `site` module resolving the correct path at runtime. On some platforms (notably Synology), this lookup failed, causing `python-dotenv` to not be found even though it was installed. Packages are now installed to `/usr/local` (system site-packages) which is always on Python's path. (#39)

---

## [1.9.4] - 2026-02-13

### Fixed
- **Legacy controller misdetected as UniFi OS** - Self-hosted controllers that return 401 (instead of 404) on `/api/auth/login` were incorrectly identified as UniFi OS, causing "invalid credentials" errors with no fallback to legacy auth. Now verifies UniFi OS by probing `/proxy/network/` before giving up. (#38)
- **Footer version display** - The `app/__init__.py` version string was never updated past 1.8.9, causing the footer on all pages to show v1.8.9 regardless of the actual running version. This led to incorrect troubleshooting advice telling users they were on an old image when they were actually up to date. (#26, #35)

---

## [1.9.2] - 2026-02-12

### Fixed
- **Legacy controller SSL regression** - v1.9.1 removed the `ssl_context` variable but left a reference to it in the legacy controller login path, causing a NameError that broke all legacy controller connections. (#26)
- **FastAPI deprecation warnings** - `Query(regex=...)` deprecated in favor of `Query(pattern=...)`. (#32)

---

## [1.9.1] - 2026-02-12

### Fixed
- **SSL verification for self-signed certs** - Replaced custom `ssl.create_default_context()` with aiohttp's built-in `ssl=False` for more reliable self-signed cert handling on legacy controllers. (#26)

---

## [1.9.0] - 2026-02-12

### Fixed
- **UDR7 IDS/IPS detection** - The Dream Router 7 reports model code `UDMA67A` via the API, not `UDR7`. Added the correct model code to the supported models list. (#21)
- **verify_ssl database default** - SQLAlchemy default was `True` but Pydantic default was `False`. Changed DB default to `False` since most UniFi deployments use self-signed certs. (#26)

### Added
- **U7 Pro XGS device name** - Added model code `UAPA6A4` to the friendly name map so it displays correctly in Network Pulse. (#28)
- **QNAP deployment guide** - Linked community-contributed QNAP Container Station guide in README and installation docs. (#29)

---

## [1.8.9] - 2026-02-11

### Fixed
- **Threat Watch gateway detection** - Fixed issue where a UniFi Express AP could be misidentified as the gateway, causing Threat Watch to incorrectly report "doesn't support IDS/IPS" even when a capable gateway (like UCG-Max) was present. Gateway detection now prioritizes dedicated gateways over Express devices. (#19)
- **Dark mode chart legend** - Fixed unreadable text in the Wi-Fi Stalker Dwell Time chart legend when using dark mode. Chart.js was ignoring the theme-aware color config for custom legend labels. (#18)

### Added
- **Dream Router 7 support** - Added UDR7 to the IDS/IPS supported models list for Threat Watch compatibility. (#21)

---

## [1.8.8] - 2026-02-11

### Added
- **Unraid template** - Added `unraid/unifi-toolkit.xml` for Unraid users to easily deploy via Community Applications or manual template import.

### Improved
- **Flexible config loading** - The app no longer requires a `.env` file if environment variables are passed directly to the container. This enables deployment on platforms like Unraid, Portainer, and Kubernetes that inject env vars natively.

---

## [1.8.7] - 2026-02-11

### Threat Watch v0.5.0

#### Added
- **Ignore List** - Filter out noise from known devices by IP address and severity level. Manage ignored IPs and severity thresholds directly from the Threat Watch UI.

---

## [1.8.6] - 2026-02-02

### Threat Watch v0.4.0

#### Fixed
- **Network 10.x support** - Fixed Threat Watch not displaying any IPS events on UniFi Network 10.x. Ubiquiti moved IPS events from the legacy `stat/ips/event` endpoint to a new v2 `traffic-flows` API. Threat Watch now tries the v2 API first and falls back to legacy for older firmware. (#10)

#### Improved
- **Debug endpoint** - The `/threats/api/events/debug/test-fetch` endpoint now tests both APIs and reports which one is working, making it easier to diagnose issues.

---

## [1.8.5] - 2025-01-12

### Wi-Fi Stalker v0.11.4

#### Fixed
- **Device status notifications** - Fixed a bug where connection/disconnection toast notifications were not triggering because the status comparison happened after the device data was already updated.
- **Byte formatting edge case** - Fixed dead code where the `bytes === 0` check was unreachable because it was placed after a falsy check that already caught zero values.

#### Improved
- **Code cleanup** - Removed unused imports, simplified display name logic, consolidated repetitive code into loops, and modernized string concatenation to template literals.

---

## [1.8.4] - 2025-01-11

### Wi-Fi Stalker v0.11.3

#### Improved
- **Faster device details modal** - Modal now opens instantly with cached data while live UniFi data loads in the background. Previously, clicking a device would wait for the API call to complete before showing the modal.

---

## [1.8.3] - 2025-01-10

### Wi-Fi Stalker v0.11.2

#### Improved
- **Condensed Presence Pattern heat map** - Reduced heat map from 24 rows to 12 by aggregating data into 2-hour blocks. Cells are now shorter rectangles instead of squares, allowing the entire heat map to fit within the modal without scrolling.

---

## [1.8.2] - 2025-01-10

### Wi-Fi Stalker v0.11.1

#### Fixed
- **Presence Pattern days calculation** - Fixed incorrect "days of data" display in Presence Pattern analytics. Previously showed "1 day(s)" even after 10+ days of tracking because it was incorrectly calculating from sample counts instead of the device's actual tracking start date.

---

## [1.8.0] - 2025-12-23

### Testing Infrastructure

#### Added
- **Comprehensive test suite** - 69 tests across 4 test modules covering core shared infrastructure
  - `tests/test_auth.py` - Authentication, session management, rate limiting (23 tests)
  - `tests/test_cache.py` - In-memory caching with TTL expiration (19 tests)
  - `tests/test_config.py` - Pydantic settings and environment variables (13 tests)
  - `tests/test_crypto.py` - Fernet encryption for credentials (14 tests)
- **Test configuration** - pytest.ini with asyncio mode and test path settings
- **Development dependencies** - requirements-dev.txt with pytest, pytest-asyncio, pytest-mock
- **Test fixtures** - conftest.py with shared fixtures for async database testing

---

## [1.7.0] - 2025-12-21

### Network Pulse v0.2.0

#### Added
- **Dashboard charts** - Three new Chart.js visualizations:
  - Clients by Band (2.4 GHz, 5 GHz, 6 GHz, Wired) doughnut chart
  - Clients by SSID doughnut chart
  - Top Bandwidth Clients horizontal bar chart
- **AP detail pages** - Click any AP card to view detailed information:
  - AP info (model, uptime, channels, satisfaction, TX/RX)
  - Band distribution chart for that AP's clients
  - Full client table with name, IP, SSID, band, signal strength, bandwidth
- **Real-time chart updates** - Charts update automatically via WebSocket when data refreshes
- **Theme-aware colors** - Charts adapt to dark/light mode toggle

---

## [1.6.0] - 2025-12-15

### Wi-Fi Stalker v0.10.0

#### Added
- **Offline duration in webhooks** - Connected device webhooks now include how long the device was offline (e.g., "1h 21m")

### Network Pulse v0.1.1

#### Changed
- **Theme inheritance** - Removed standalone theme toggle, now inherits from main dashboard

### Dashboard

#### Fixed
- **Race condition** - Fixed gateway check timing issue on dashboard load using shared cache

---

## [1.5.2] - 2025-12-05

### Wi-Fi Stalker v0.9.0

#### Fixed
- **Manufacturer display** - Now uses UniFi API's OUI data instead of limited hardcoded lookup. Manufacturer info (Samsung, Apple, etc.) now matches what's shown in UniFi dashboard. (#1)
- **Legacy controller support** - Fixed "Controller object has no attribute 'initialize'" error when connecting to non-UniFi OS controllers. Updated to use aiounifi v85 request API. (#3)
- **Block/unblock button state** - Button now properly updates after blocking/unblocking a device. (#2)

#### Improved
- **Site ID help text** - Added clarification that Site ID is the URL identifier (e.g., `default` or the ID from `/manage/site/abc123/...`), not the friendly site name.

### Dashboard

#### Improved
- **UniFi configuration modal** - Added clearer help text for Site ID field explaining the difference between site ID and site name.

---

## [1.5.1] - 2025-12-05

### Dashboard
- Fixed status widget bounce on 60-second refresh

### Wi-Fi Stalker v0.8.0
- Added wired device support (track devices connected via switches)

---

## [1.5.0] - 2025-12-02

### Dashboard
- Fixed detection of UniFi Express and IDS/IPS support
- Simplified IDS/IPS unavailable messaging

### Threat Watch v0.2.0
- Automatic detection of gateway IDS/IPS capability
- Appropriate messaging for gateways without IDS/IPS (e.g., UniFi Express)

---

## [1.4.0] - 2025-11-30

### Initial Public Release
- Dashboard with system status, health monitoring
- Wi-Fi Stalker for device tracking
- Threat Watch for IDS/IPS monitoring
- Docker and native Python deployment
- Local and production (authenticated) modes
