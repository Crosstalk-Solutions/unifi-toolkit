# Changelog

All notable changes to UI Toolkit will be documented in this file.

## [1.13.0] - unreleased

### Added
- **House Arrest** - New tool for locking a device or a whole network down using UniFi's zone-based firewall. Three tabs: Networks (isolation and a status matrix), DNS Lockdown, and Devices.
  - **Device lockdown** - Per-device by MAC, so wired and wireless are covered identically. Three presets (Full lockdown, Internet only, LAN only), always previewed before applying, and release removes exactly the policies it created and refuses anything else. Verified end to end against a real device.
  - **Blocked traffic view** - Shows what each lockdown actually stopped, attributed to our own policy by id, so another rule's blocks are never counted as ours.
  - **Network isolation** - Uses UniFi's own `network_isolation_enabled` / `internet_access_enabled` settings rather than parallel rules, so this tool and the UniFi UI can never disagree.
  - **Isolation matrix** - Networks against security settings, each intersection explaining itself on hover. The DNS column compares each advertised resolver against the network's own subnet, because a resolver inside the network cannot be filtered by the gateway.
  - **DNS Lockdown** - Force chosen networks onto approved resolvers and block DNS to anywhere else, optionally including DNS-over-TLS. Rule order decides whether this works at all, so the stored order is verified after applying and the whole set rolled back if the allow rule did not land ahead of the blocks.
  - Known limits are shown next to the claims they qualify rather than left to be discovered: same-VLAN traffic cannot be filtered by any firewall policy, DNS survives a lockdown when the resolver is on the device's own subnet, established connections continue, and DNS-over-HTTPS is not covered.
- **Multi-select device picker (House Arrest)** - The Devices-tab picker is now a searchable combo box: filter by name, IP, or MAC (separator-insensitive), filter by VLAN, and select several devices to lock down together under a single policy. Each row shows the device's IP, MAC tail, and network so identically-named devices (e.g. three "Samsung"s) are distinguishable, and any device already under arrest is greyed out.
- **Editable mDNS scope from the isolation matrix (House Arrest).** The mDNS column can now be toggled per network. Under the hood it edits the one control that actually exists: the site-wide Gateway mDNS Proxy scope list, written through the v2 `global/config/network` route (the only route that applies; the legacy `setting/mdns` endpoints return 200 and change nothing). The confirm dialog says plainly that it edits that shared site-wide list, the write is verified by re-reading the stored list rather than trusting the 200, and a full remove-and-restore round trip was measured live before shipping.
- **Mechanism diagrams (House Arrest)** - Inline flat-vector diagrams for DNS Lockdown and for each network-isolation preset, showing exactly what the mode allows and blocks — including the same-VLAN peer-traffic blind spot no firewall policy can close.

- **Rogue Support "Get Help With Your Network" button.** A tasteful, orange-outlined button at the far right of the dashboard header, with the Rogue Support mascot, linking to a new in-app promo page (`/rogue-support`). The page pitches on-demand networking help ($120/hour billed in 6-minute increments, any brand of gear) with 25% off the first engagement, and its outbound links carry UTM tags so signups from the toolkit are attributable.

### Fixed
- **A rule disabled in the UniFi UI no longer shows as "Enforcing" (House Arrest).** Nothing read `policy.enabled`, so a lockdown whose rules were toggled off kept its green dot -- which happened in practice with a paused DNS rule. Device-arrest health now reports a `disabled` status (outranking MAC-rotation detection, since "re-enable it" is the fix), DNS lockdown rows count disabled rules and show "N of M rules disabled in UniFi" instead of green, and the trust strip counts a partly-disabled DNS lockdown as not enforcing. Measured live: disable one rule -> the row and strip flip; restore -> clean.

- **A failed client-database read no longer reads as "unblocked" (Wi-Fi Stalker).** `is_client_blocked()` returned False on any failure, so one auth blip or controller restart mid-poll looked like every blocked device being unblocked -- firing a spurious `unblocked` webhook, then a spurious `blocked` one the next cycle. The check now returns unknown on a failed read, and both the scheduler and the device-detail endpoint keep the stored state instead of flipping on unknown.
- **Network Pulse per-client signal now uses the `signal` field** with `rssi` fallback, matching what the UniFi console displays -- the same mismatch fixed for Wi-Fi Stalker in v1.9.17 (#60), still present in the sibling tool.

- **The "Re-read from controller" button was permanently disabled after the first page load (House Arrest).** Its disabled binding tracked `inspection.loading`, but the API response that replaces the state object carries no `loading` key -- and Alpine leaves a bound `disabled` attribute in place when the expression evaluates to undefined (measured), so the button never re-enabled. `loadInspection()` now sets `loading` to an explicit false on every path.

### Changed
- **Networks tab consolidated around the matrix (House Arrest).** The "Isolate a network" dropdown flow and the separate "Networks currently isolated" list are gone: both were a second control surface and a second display of the same native flags the now-editable matrix already shows and changes, and two views of one truth is exactly the drift this tool exists to avoid. The per-preset isolation infographics moved into the matrix toggle dialog, where they now show the exact state the click you are confirming lands the network in (both flags read off the row, the toggled one overridden). Wi-Fi client isolation is now a matrix-style table in the same visual language as the network matrix, and the copy above the matrix no longer calls it a read-only audit. The `api/isolate` and `api/release-network` endpoints remain for now.

### Removed
- **The "Quarantine + VLAN move" preset.** It moved the device with UniFi's per-client virtual-network override, and on a wired client that mechanism was measured half-applying: the device obtained a DHCP lease on the target VLAN and then sat with no working L2 at all — ARP to its own gateway and to same-VLAN peers failed — while the controller and the UniFi UI reported contradictory locations for it. A quarantine whose outcome the platform cannot report coherently cannot be verified, so the preset is gone. The UI now says it plainly: a device that truly needs quarantining gets a dedicated VLAN assigned natively in UniFi (its switch port's network, or a dedicated Wi-Fi network), which House Arrest can then isolate and DNS-lock reliably. Release still recognises pre-removal quarantine policies and clears their VLAN override.

### Fixed
- **Zones are now found by `zone_key`, not display name (House Arrest).** The Internal/External lookup matched the zone's display name, so a console with a renamed zone (or devices/networks in a custom zone) got rules written into zone pairs their traffic never crosses -- silent non-protection. Zones are now resolved by the stable `zone_key` field (measured: survives renames), DNS lockdowns are scoped to the chosen networks' actual zone via `firewall_zone_id`, and device lockdowns attribute each MAC's zone through its known-client record. Selections spanning two zones are refused with instructions to apply per zone, an approved resolver living in a different zone than the locked networks is called out instead of receiving an allow in a pair where it does nothing, and consoles with additional LAN zones get an explicit caveat that those zones stay reachable.
- **Quarantine release could silently strand a device (House Arrest).** A duplicate `preset_from_policy` definition shadowed the real one and returned the preset's display label instead of its key, so `requires_network()` never recognised a quarantine and the device's VLAN override was left in place on release — leaving the device parked in the quarantine VLAN after an apparently successful release. Removed the duplicate; the arrest-row chip now maps the key to its label at the router.
- Repaired the House Arrest policy test suite (12 tests left red by the earlier DNS resolver-split refactor) and hardened `dns_order_is_safe` to require a block as well as an allow, so an allow-only set is never reported as a safe lockdown.

### Security
- **Anti-DNS-rebinding Host check.** New middleware rejects requests whose Host header is not an IP literal, localhost, a local-network suffix (`.local`/`.lan`/`.internal`/`.home[.arpa]`), the configured `DOMAIN`, or listed in `ALLOWED_HOSTS`. This stops a web page the user merely visits from rebinding its own hostname to the toolkit's LAN IP and driving the firewall-rewriting endpoints from the victim's browser. Runs in every mode; `/health` is exempt.
- **CSRF coverage for House Arrest.** `/arrest/api/` was missing from the CSRF prefix list, so its state-changing requests skipped the `X-Requested-With` check the other tools enforce. Added.
- **Controller-URL SSRF validation.** Save and test endpoints across the dashboard, Wi-Fi Stalker, and Threat Watch reject non-http(s) schemes and embedded credentials. Private IPs stay allowed — a controller legitimately lives there.
- **Webhook SSRF hardening.** Webhook URLs are re-validated at delivery, not only at save, so a saved URL cannot be repointed at an internal service before the next send.
- Escaped the controller-supplied gateway name before interpolating it into the dashboard (XSS).
- Raised `aiohttp` (`>=3.10.11`, CVE-2024-52304) and `python-multipart` (`>=0.0.18`, CVE-2024-53981) floors.

### CI / Build
- Added a **Tests** workflow that runs the pytest suite on every pull request and on pushes to `main`.
- **Decoupled `:latest` from `main`.** A push to `main` now publishes a moving `:edge` image (a staging channel); `:latest` and the semver tags move only when a `vX.Y.Z` tag is pushed, so releasing is a deliberate step rather than a side effect of merging.

### Documentation
- `docs/house-arrest-design.md` records the design and every measured API behaviour, including corrections to earlier wrong assumptions so they are not rediscovered.
- CLAUDE.md gains the UniFi API quirks found while building this.

## [1.12.0] - 2026-09-16

### Fixed
- **A fresh `pip install -r requirements.txt` produced a broken app.** `fastapi>=0.115.6` caps starlette below the `starlette>=0.47.2` on the next line, so pip resolved to a much newer fastapi and pulled starlette 1.x — which removed the `TemplateResponse(name, context)` signature and returned 500 on every template route, the main dashboard included. All 9 call sites now use the request-first signature, which works on starlette 0.29+ and on 1.x, so no upper bound is needed. Verified by installing from `requirements.txt` into a clean environment and loading every template route on both starlette 1.6.0 and 0.41.3.

### Documentation
- CLAUDE.md gains a note that `requirements.txt` previously produced a broken app on a fresh install.

## [1.11.2] - 2026-03-18

### Fixed
- **Network Pulse chart panel resizing** - Chart cards now resize responsively on narrow viewports. Added `min-width: 0` on `.chart-card` and `overflow: hidden` on `.chart-container` to fix the CSS Grid min-width:auto gotcha that prevented canvas-based charts from shrinking. (#96)

### Changed
- **Documentation updated for UniFi OS requirement** - Removed all references to legacy standalone controllers from README and INSTALLATION.md. Added clear "UniFi OS required" callout, removed port 8443 examples, lifted Python 3.13 restriction, reordered auth options to lead with API key. (#97)

---

## [1.11.1] - 2026-03-10

### Fixed
- **Threat Watch geo/category data from v2 API** - `source.region` mapped to country code (was looking for nonexistent `source.country`), `ips.category_name` mapped to category (was using `ips.ips_category` which only exists in `policies[]`). (#79)

### Changed
- **Document cloud access limitation** - Controller URL must be a local IP/hostname; `unifi.ui.com` cloud access is not supported (README.md and INSTALLATION.md).

### Removed
- **Dead v2 parser** - Removed unreachable `_parse_v2_traffic_flow()` from Threat Watch scheduler — v2 events are pre-normalized to legacy format by `_normalize_v2_event()` before reaching the scheduler.

### Dependencies
- docker/metadata-action v5 → v6 (#93)
- docker/build-push-action v6 → v7 (#94)

---

## [1.11.0] - 2026-03-10

### Changed
- **Drop legacy standalone controller support** - Removed aiounifi dependency entirely. All API calls now use direct aiohttp requests to UniFi OS endpoints. **Users on standalone/self-hosted controllers (the Java-based controller software) should stay on v1.10.3.** (#92)
- **Remove Python 3.13 version block** - The aiounifi constraint was the only reason for the block; Python 3.13+ is now supported.
- **Simplify UniFi client** - Removed all `if self.is_unifi_os:` URL conditionals and legacy `else` branches from `shared/unifi_client.py`.
- **Update Dependabot config** - Removed aiounifi ignore rules and Python version pinning.

---

## [1.10.3] - 2026-03-06

### Fixed
- **UAP-AC-LR model mapping** - `U7LR` model code was incorrectly mapped to "U7 LR" (a WiFi 7 product); corrected to "UAP AC LR". Added `G7LR` → "U7 LR" for the actual WiFi 7 U7 Long-Range AP. (#89)

### Added
- **AP model codes in debug info** - `/api/debug-info` now includes AP names, raw model codes, and display names; shown in Debug Info modal and Report Issue template for faster diagnosis.

---

## [1.10.2] - 2026-03-06

### Improved
- **Threat Watch test-fetch diagnostics** - Test both v2 payload formats independently, capture rejection body, total flow count, sample flow keys, and nested structure for faster remote debugging. (#85)

### Added
- **Gateway firmware in debug info** - `get_gateway_info()`, `/api/debug-info` endpoint, Debug Info modal, and Report Issue template now include gateway firmware version.

---

## [1.10.1] - 2026-03-01

### Added
- **Docker Swarm secrets support** - `_FILE` env var suffix reads secret values from files (e.g., `ENCRYPTION_KEY_FILE=/run/secrets/key`) for orchestrators that mount secrets as files. Supported for `ENCRYPTION_KEY`, `AUTH_USERNAME`, `AUTH_PASSWORD_HASH`, `DATABASE_URL`, `UNIFI_PASSWORD`, `UNIFI_API_KEY`. `_FILE` takes precedence if both forms are set. (#86)

### Fixed
- **Express in AP mode missing from Network Pulse** - `get_ap_details()` now includes `device_mode_override=mesh` check matching `get_access_points()` and `get_system_info()`. (#90)

### Changed
- **Remove UI Product Selector card** - Service shut down; info cards moved to dedicated full-width `.info-row` for balanced 3+2 layout.

### Dependencies
- actions/stale v9 → v10 (#88)

---

## [1.10.0] - 2026-02-25

### Added
- **Multi-WAN support in Network Pulse** - Per-WAN IP (click-to-reveal), throughput tabs, latency, and uptime for dual/multi-WAN setups. WAN tab selector in Current Throughput section (hidden for single-WAN). Extra WAN entries in WAN Status card and Network Health panel. (#83)

### Fixed
- **Threat Watch external links not opening** - `@click.prevent` modifier was unconditionally blocking navigation on AbuseIPDB, VirusTotal, and Shodan links. (#79)

---

## [1.9.21] - 2026-02-23

### Fixed
- **UniFi Express in AP-only mode not detected as AP** - Express reports `type: "udm"` with `device_mode_override: "mesh"` when in AP mode. Now correctly skipped as gateway candidate and counted as AP in device counts and `get_access_points()`. (#71)

### Dependencies
- greenlet dependency update (#68)

---

## [1.9.20] - 2026-02-23

### Added
- **Threat Watch time range filter** - 24h / 7d (default) / 30d dropdown in filter bar, scopes both events table and stat cards. Added `time_range` query param to `/api/events` and `/api/events/stats` endpoints. (#75)
- **Auto-purge old threat events** - Events older than 30 days are automatically purged hourly via scheduler to keep DB size in check.

### Fixed
- **Threat Watch webhook delivery** - Scheduler was calling WiFi Stalker's `deliver_webhook` instead of `deliver_threat_webhook`, causing `custom_message` kwarg error on real alerts while test webhooks worked fine. (#77)

---

## [1.9.19] - 2026-02-22

### Improved
- **Form input accessibility** - Removed placeholder text from form inputs for accessibility — users with cognitive disabilities may confuse placeholders with filled-in fields. Replaced with visible `<small>` hint text below inputs with `aria-describedby` for screen readers. (#73)

### Added
- **Update available notification** - Dashboard header badge shows when a new version is available. New `/api/update-check` endpoint fetches latest GitHub release, compares against running version, caches for 1 hour. Badge links to GitHub release page; silently hidden if GitHub is unreachable. (#74)

### Fixed
- **Network Pulse theme default** - Was defaulting to dark mode instead of matching dashboard's light default.

---

## [1.9.18] - 2026-02-22

### Fixed
- **Threat Watch getting 0 IPS events** - Use correct v2 traffic-flows payload format with server-side `policy_type: ["INTRUSION_PREVENTION"]` filtering instead of paginating all flows and filtering client-side. Pass scheduler timestamps through to v2 API (previously hardcoded to `timeRange: "24h"`). Added backward-compatible fallback for older firmware via `_v2_uses_new_payload` flag. (#63)
- **WiFi Stalker table overflow** - Long hostnames no longer push delete button off-screen. (#72)

### Added
- **`payload_format` diagnostic field** - Debug endpoint now reports which v2 payload format is in use.
- **`curl` dependency check** - `upgrade.sh` preflight now verifies `curl` is available. (#70)

---

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
