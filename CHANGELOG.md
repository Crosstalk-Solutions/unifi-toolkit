# Changelog

All notable changes to UI Toolkit will be documented in this file.

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
- **Comprehensive test suite** - 68 tests across 4 test modules covering core shared infrastructure
  - `tests/test_auth.py` - Authentication, session management, rate limiting (23 tests)
  - `tests/test_cache.py` - In-memory caching with TTL expiration (20 tests)
  - `tests/test_config.py` - Pydantic settings and environment variables (13 tests)
  - `tests/test_crypto.py` - Fernet encryption for credentials (12 tests)
- **Test configuration** - pytest.ini with asyncio mode and test path settings
- **Development dependencies** - requirements-dev.txt with pytest, pytest-asyncio, pytest-mock
- **Test fixtures** - conftest.py with shared fixtures for async database testing

### Claude Code Agents

#### Added
- **Wrapup agent** (`/wrapup`) - End-of-session workflow for documentation updates, version bumps, clean commits, and git push
- **Test-changes agent** (`/test-changes`) - Analyzes git changes and writes comprehensive tests with mocking and error handling

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
