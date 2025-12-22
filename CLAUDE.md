# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**UI Toolkit** (v1.7.0) is a comprehensive monorepo containing multiple tools for UniFi network management and monitoring. Each tool operates independently but shares common infrastructure for UniFi API access, database management, configuration, and authentication.

**Current Tools:**
- **Wi-Fi Stalker v0.10.0** - Track specific client devices, monitor roaming, block/unblock devices, and maintain connection history with webhook alerts
- **Threat Watch v0.3.0** - Monitor IDS/IPS events, view blocked threats, analyze attack patterns, and receive webhook alerts (with automatic detection of gateway IDS/IPS capability)
- **Network Pulse v0.3.0** - Real-time network monitoring dashboard with Chart.js visualizations (clients by band, clients by SSID, top bandwidth), clickable AP cards with detail pages, hide/show wired toggle on charts, and WebSocket-powered live updates

**External Tools (linked from dashboard):**
- **UI Product Selector** - External site at uiproductselector.com for UniFi product recommendations

## Deployment Modes

The application supports two deployment modes:

### Local Mode (default)
- No authentication required
- Access via `http://localhost:8000`
- Suitable for trusted LAN environments
- Set `DEPLOYMENT_TYPE=local` in `.env`

### Production Mode
- Session-based authentication with bcrypt password hashing
- HTTPS via Caddy with automatic Let's Encrypt certificates
- Rate limiting (5 failed login attempts = 5 minute lockout)
- Access via `https://your-domain.com`
- Set `DEPLOYMENT_TYPE=production` in `.env`

## Setup Wizard

The project includes an interactive setup wizard (`setup.sh`) that:
- Generates the encryption key automatically
- Prompts for deployment type (local/production)
- For production: collects domain, username, and password
- Validates password policy (12+ chars, uppercase, lowercase, numbers)
- Creates the `.env` file with all required settings

Run with: `./setup.sh`

## Upgrade Script

The project includes an upgrade script (`upgrade.sh`) for easy updates:
- Detects deployment mode (local/production) from `.env`
- Stops running containers
- Pulls latest code from git
- Rebuilds Docker image (with `--no-cache`)
- Runs database migrations with smart error handling:
  - Normal migrations: runs `alembic upgrade head`
  - Tables already exist: automatically stamps database to current version
- Restarts containers and verifies health

Run with: `./upgrade.sh`

This script eliminates the common "table already exists" migration errors that occur when upgrading from older versions.

## Authentication System

Located in `app/routers/auth.py`:

- **Session-based**: Uses secure cookies with 7-day expiration
- **Rate limiting**: 5 failed attempts triggers 5-minute lockout per IP
- **Middleware**: `AuthMiddleware` protects all routes in production mode
- **Login page**: Branded login at `/login` with dark mode support
- **Logout**: `/logout` clears session and redirects to login

The auth system is transparent in local mode (no login required).

## Dashboard

The main dashboard (`/`) provides:
- **System Status Widget**: Shows gateway info, connected clients, network health
- **Tool Cards**: Links to Wi-Fi Stalker, Threat Watch, and external tools
- **Settings Cog** (⚙️): Opens UniFi configuration modal (always accessible in header)

### Centralized UniFi Configuration

UniFi controller configuration is managed centrally from the dashboard (not in individual tools):
- Located in `app/routers/config.py`
- Accessible via settings cog (⚙️) in dashboard header
- **Endpoints**:
  - `POST /api/config/unifi` - Save configuration
  - `GET /api/config/unifi` - Get current configuration
  - `POST /api/config/unifi/test` - Test credentials before saving
  - `GET /api/config/unifi/test` - Test saved configuration
- **Test-before-save**: Configuration is only saved after successful connection test
- Supports both legacy (username/password) and UniFi OS (API key) authentication

Individual tools (Wi-Fi Stalker, Threat Watch) only have webhook configuration - they use the shared UniFi config from the dashboard.

## Legal Disclaimer

The footer of both the main dashboard and Wi-Fi Stalker includes a disclaimer:
> "This project is not affiliated with, endorsed by, or sponsored by Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc."

This must remain in all public-facing pages.

## Branding

The application uses **Crosstalk Solutions** branding:
- **Logo**: `/app/static/images/2022-Crosstalk-Solutions-Logo.png`
- **Icon**: `/app/static/images/2022-Crosstalk-Solutions-Icon.png`
- **Favicon**: `/app/static/images/favicon16x16.jpg`
- **Brand Colors**:
  - Blue (primary): `#2B3990`
  - Orange (accent): `#F15A29`
  - Grey (secondary): `#939598`

## Dark Mode

The application supports dark/light mode toggle:
- Toggle button in dashboard header (upper right)
- Theme preference stored in `localStorage` with key `unifi-toolkit-theme`
- CSS uses `:root[data-theme="dark"]` selector for dark mode variables
- Theme persists across page navigation and sub-applications
- Dashboard, Wi-Fi Stalker, and Threat Watch CSS files all have matching theme variable definitions

## Architecture

### Monorepo Structure

```
unifi-toolkit/
├── app/                    # Main unified application
│   ├── main.py            # FastAPI app entry point, mounts all tools
│   ├── routers/           # Main app routers
│   │   ├── auth.py        # Authentication (login, logout, middleware)
│   │   └── config.py      # UniFi configuration (centralized)
│   ├── static/            # Main dashboard static files
│   │   ├── css/           # Dashboard styles (includes dark mode)
│   │   └── images/        # Branding assets (logo, favicon)
│   └── templates/         # Main dashboard templates
│       ├── dashboard.html # Main dashboard (includes UniFi config modal)
│       └── login.html     # Login page (production mode)
├── shared/                # Shared infrastructure (all tools use this)
│   ├── config.py          # Pydantic settings (loads from .env)
│   ├── crypto.py          # Fernet encryption for credentials
│   ├── database.py        # SQLAlchemy async database management
│   ├── unifi_client.py    # UniFi API wrapper (supports legacy + UniFi OS)
│   ├── websocket_manager.py  # WebSocket real-time updates
│   ├── webhooks.py        # Webhook delivery (Slack, Discord, n8n)
│   └── models/            # Shared SQLAlchemy models
│       ├── base.py        # Declarative base for all models
│       └── unifi_config.py  # UniFi controller config (shared)
├── tools/                 # Individual tools (each is a FastAPI sub-app)
│   ├── wifi_stalker/
│   │   ├── __init__.py    # Tool metadata (__version__)
│   │   ├── main.py        # FastAPI app factory (create_app())
│   │   ├── database.py    # Tool-specific models (stalker_* tables)
│   │   ├── models.py      # Pydantic request/response models
│   │   ├── scheduler.py   # APScheduler background tasks
│   │   ├── routers/       # API endpoints
│   │   ├── static/        # Tool static files
│   │   └── templates/     # Tool templates
│   └── threat_watch/
│       ├── __init__.py    # Tool metadata (__version__)
│       ├── main.py        # FastAPI app factory (create_app())
│       ├── database.py    # Tool-specific models (threats_* tables)
│       ├── models.py      # Pydantic request/response models
│       ├── scheduler.py   # APScheduler background tasks
│       ├── routers/       # API endpoints (events, config, webhooks)
│       ├── static/        # Tool static files
│       └── templates/     # Tool templates
├── alembic/               # Database migrations
│   ├── env.py            # Migration environment
│   └── versions/         # Migration scripts
├── docs/                  # Documentation
│   ├── INSTALLATION.md   # Complete installation guide
│   └── QUICKSTART.md     # Quick start reference
├── data/                  # Runtime data (database, logs)
├── setup.sh               # Interactive setup wizard
├── reset_password.sh      # Password reset utility
├── run.py                 # Application entry point
├── requirements.txt       # Python dependencies
├── .env.example           # Configuration template
├── Caddyfile              # Caddy reverse proxy config (production)
└── docker-compose.yml     # Docker deployment
```

### Key Design Principles

1. **Shared Infrastructure**: All tools use common UniFi client, database, encryption
2. **Table Prefixes**: Each tool prefixes its tables (`stalker_`, `threats_`, etc.)
3. **Independent Apps**: Each tool is a FastAPI sub-application mounted to a prefix
4. **Single Database**: All tools share one SQLite database
5. **Unified Configuration**: Single `.env` file for all settings

## Running the Application

### Development Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Generate encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Create .env file
cp .env.example .env
# Edit .env and add ENCRYPTION_KEY (required)

# Run application
python run.py
```

### URLs

- **Main Dashboard**: http://localhost:8000
- **Wi-Fi Stalker**: http://localhost:8000/stalker/
- **Threat Watch**: http://localhost:8000/threats/
- **Health Check**: http://localhost:8000/health
- **API Docs**: http://localhost:8000/docs (auto-generated by FastAPI)

### Docker Deployment

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f

# Stop
docker compose down
```

## Python Version Constraint

**CRITICAL**: This project requires **Python 3.9-3.12** only.

It does **NOT** support Python 3.13+ due to the `aiounifi==85` dependency.

## Shared Infrastructure Details

### Configuration (shared/config.py)

Uses Pydantic Settings to load from `.env`:

```python
class ToolkitSettings(BaseSettings):
    encryption_key: str  # Required for credential encryption
    database_url: str = "sqlite+aiosqlite:///./data/unifi_toolkit.db"
    log_level: str = "INFO"

    # UniFi Controller (optional, can configure via UI)
    unifi_controller_url: Optional[str] = None
    unifi_username: Optional[str] = None
    unifi_password: Optional[str] = None
    unifi_api_key: Optional[str] = None
    unifi_site_id: str = "default"
    unifi_verify_ssl: bool = False

    # Wi-Fi Stalker settings
    stalker_refresh_interval: int = 60  # Seconds
```

### Database (shared/database.py)

- **Engine**: SQLAlchemy async with aiosqlite
- **Pattern**: Singleton `Database` class via `get_database()`
- **Initialization**: Auto-creates tables on startup
- **Tables**: Defined in shared/models/ and tools/*/database.py

### UniFi Client (shared/unifi_client.py)

Supports **two authentication methods** with **automatic detection**:

1. **UniFi OS (UCG, UDM, Cloud Key with UniFi OS)**: username/password or API key
2. **Legacy Controllers (self-hosted)**: username + password (uses aiounifi.Controller)

**Auto-detection**: When using username/password, the client automatically tries UniFi OS authentication first (`/api/auth/login`). If that returns 404, it falls back to legacy controller authentication. API keys always use UniFi OS mode.

Note: Cloud Key Gen2+ now runs UniFi OS on recent firmware, so it uses UniFi OS authentication (not legacy).

Key methods:
- `connect()` - Authenticate and connect
- `get_clients()` - Get all active clients
- `get_ap_name_by_mac()` - Resolve AP MAC to friendly name
- `get_gateway_info()` - Get gateway details including IDS/IPS capability
- `get_ips_settings()` - Get IDS/IPS configuration (mode, enabled status, DNS filtering)
- `has_gateway()` - Check if site has a gateway device
- `disconnect()` - Close connection

### Gateway and IDS/IPS Detection

The UniFi client includes detection for gateway devices and their IDS/IPS capability:

- **Supported device types**: `ugw` (USG), `udm` (Dream Machine), `uxg` (UXG series), `ux` (UniFi Express)
- **IDS/IPS capable models**: UDM, UDM Pro, UDM SE, UDR, UCG, UCG Max, UXG Pro, UXG Lite, USG series
- **Non-IDS/IPS gateways**: UniFi Express (UX) - detected as a gateway but IDS/IPS features are not available

The `get_gateway_info()` method returns:
```python
{
    "has_gateway": True,
    "gateway_model": "UX",
    "gateway_name": "UniFi Express",
    "supports_ids_ips": False
}
```

The `get_ips_settings()` method queries `/rest/setting` for IPS configuration (UniFi OS only):
```python
{
    "ips_mode": "ips",        # "disabled", "ids", "ips", or "ipsInline"
    "ips_enabled": True,      # Convenience boolean
    "honeypot_enabled": False,
    "dns_filtering": "none",
    "suppression_enabled": True
}
```

**IPS Mode values:**
- `disabled` - IDS/IPS is off
- `ids` - Intrusion Detection only (alerts but doesn't block)
- `ips` - Intrusion Prevention (blocks threats)
- `ipsInline` - Inline IPS mode (more aggressive blocking)

Threat Watch uses this to show appropriate messaging when a gateway exists but doesn't support IDS/IPS, or when IDS/IPS is disabled.

### Caching (shared/cache.py)

Simple in-memory cache to prevent race conditions when multiple components need gateway/IPS info:

```python
from shared import cache

# Get/set gateway info (30-second TTL)
cached = cache.get_gateway_info()
cache.set_gateway_info({"has_gateway": True, ...})

# Get/set IPS settings
ips = cache.get_ips_settings()
cache.set_ips_settings({"ips_mode": "ips", ...})

# Invalidate cache
cache.invalidate("gateway_info")
cache.invalidate_all()
```

**Why caching matters:** Cloud Key devices can struggle with multiple concurrent API connections. The dashboard's `system-status` endpoint populates the cache, and `gateway-check` reads from it. This prevents race conditions where Threat Watch availability checks would fail intermittently.

### Encryption (shared/crypto.py)

Uses Fernet symmetric encryption:
- `encrypt_password()` / `decrypt_password()`
- `encrypt_api_key()` / `decrypt_api_key()`

**Critical**: The `ENCRYPTION_KEY` must remain the same once set, or encrypted data cannot be decrypted.

## Wi-Fi Stalker Tool Deep Dive

### Core Concept

Track **user-specified devices** by MAC address (not all network clients). Monitor:
- Online/offline status
- Which AP they're connected to (roaming detection)
- Connection history with timestamps and durations

### Background Refresh Logic (scheduler.py)

The `refresh_tracked_devices()` function is the heart of device tracking:

1. Get all tracked devices from database (`stalker_tracked_devices`)
2. Connect to UniFi controller
3. Get all active clients from UniFi API
4. For each tracked device:
   - Search for MAC in active clients
   - If found (online):
     - Update `last_seen`
     - Check if `ap_mac` changed (roaming)
     - If roamed: close old history entry, create new one
     - Set `is_connected = True`
   - If not found (offline):
     - Close any open history entries
     - Set `is_connected = False`
5. Commit all changes to database
6. Broadcast updates via WebSocket

Runs every `STALKER_REFRESH_INTERVAL` seconds (default: 60).

### Database Tables

**stalker_tracked_devices:**
- User-added devices to track
- Current connection state (`is_connected`, `current_ap_mac`, `current_ap_name`)
- Updated every refresh cycle

**stalker_connection_history:**
- Log of roaming events
- Each entry = one connection to one AP
- `connected_at` when device connects/roams to AP
- `disconnected_at` when device roams away or goes offline
- `duration_seconds` calculated when entry closes

**stalker_webhook_config:**
- Webhook configurations for events (connected, disconnected, roamed, blocked, unblocked)
- Supports Slack, Discord, n8n/generic

### Webhook Events

Wi-Fi Stalker sends webhooks for the following events:
- **connected** - Device came online (includes offline duration)
- **disconnected** - Device went offline
- **roamed** - Device moved to a different AP or switch port
- **blocked** - Device was blocked from the network
- **unblocked** - Device was unblocked

**Webhook Payload Fields:**
- Device name and MAC address
- Access point name (for connected/roamed events)
- Signal strength in dBm (for wireless devices)
- **Offline duration** (connected events only) - Shows how long the device was offline before reconnecting (e.g., "1h 21m"). Shows "n/a" if device has no prior connection history.

**n8n/Generic Webhook Format:**
```json
{
  "event_type": "connected",
  "device": {"name": "Device Name", "mac_address": "aa:bb:cc:dd:ee:ff"},
  "access_point": "Living Room AP",
  "signal_strength": -45,
  "offline_duration_seconds": 4860,
  "offline_duration_formatted": "1h 21m",
  "timestamp": "2025-01-15T10:30:00Z",
  "source": "unifi-toolkit"
}
```

### API Endpoints

All mounted under `/stalker/api/`:

- **Devices**: GET/POST/DELETE `/api/devices`
- **Device Details**: GET `/api/devices/{id}/details`
- **History**: GET `/api/devices/{id}/history`
- **Webhooks**: GET/POST/PUT/DELETE `/api/webhooks`

Note: UniFi configuration is centralized at the dashboard level (`/api/config/unifi`), not in individual tools.

See routers/*.py for full endpoint definitions.

### Frontend (Alpine.js)

- **Template**: `tools/wifi_stalker/templates/index.html`
- **JavaScript**: `tools/wifi_stalker/static/js/app.js`
- **Styles**: `tools/wifi_stalker/static/css/styles.css`

Uses Alpine.js for reactivity. WebSocket connection for real-time updates.

### Navigation

- Each sub-tool has a "Back to Dashboard" link in its header
- The main dashboard at `/` shows all available tools as cards
- Theme preference (dark/light) persists across navigation via localStorage

## Threat Watch Tool Deep Dive

### Core Concept

Monitor IDS/IPS events from UniFi gateways that support threat detection. Features:
- Real-time event feed with severity indicators
- Top attackers analysis
- Category breakdown (malware, exploits, scans, etc.)
- Blocked vs detected event filtering
- Webhook alerts for new threats

### Prerequisites

Threat Watch requires:
1. **UniFi OS gateway** - UDM, UCG, UXG, or USG series (not UniFi Express)
2. **IDS/IPS enabled** - Must be turned on in UniFi Network settings
3. **UniFi OS authentication** - Legacy controllers don't expose IDS/IPS API endpoints

### Gateway Detection Flow

On dashboard load:
1. `loadSystemStatus()` fetches `/api/system-status` which calls `get_gateway_info()` and `get_ips_settings()`
2. Results are cached in `shared/cache.py` (30-second TTL)
3. `checkGatewayAvailability()` waits for `systemStatusLoaded` event, then fetches `/api/config/gateway-check`
4. Gateway check reads from cache to determine Threat Watch availability
5. Dashboard shows appropriate status: available, disabled (with "check again" link), or unavailable

### Database Tables

**threats_events:**
- IDS/IPS events fetched from UniFi
- Includes timestamp, severity, category, source/destination IPs
- `is_blocked` indicates if threat was blocked (IPS) or just detected (IDS)

**threats_webhook_config:**
- Webhook configurations for threat alerts
- Supports Slack, Discord, n8n/generic

### API Endpoints

All mounted under `/threats/api/`:

- **Events**: GET `/api/events` - List IDS/IPS events with filtering
- **Stats**: GET `/api/stats` - Event counts by severity/category
- **Top Attackers**: GET `/api/top-attackers` - Most frequent source IPs
- **Webhooks**: GET/POST/PUT/DELETE `/api/webhooks`
- **Refresh**: POST `/api/refresh` - Manually trigger event fetch

### Frontend

- **Template**: `tools/threat_watch/templates/index.html`
- **Styles**: `tools/threat_watch/static/css/styles.css`

Uses vanilla JavaScript with fetch API. Severity cards use colored backgrounds (high=red, medium=yellow, low=blue) with white text for contrast.

### IDS Mode Badge

The UI shows the current IDS/IPS mode in the header:
- 🛡️ **IDS Mode** - Detection only, threats are logged but not blocked
- 🛡️ **IPS Mode** - Prevention mode, threats are actively blocked

### Dark Mode

Threat Watch supports dark/light mode toggle. Key CSS considerations:
- Severity cards maintain colored backgrounds in both modes
- IPS status badge uses `.ips-status-badge` class with dark mode variant
- Event table alternates row colors appropriately

## Network Pulse Tool Deep Dive

### Core Concept

Real-time network monitoring dashboard with visualizations. Features:
- Gateway status (model, version, uptime, WAN status)
- Device counts (total clients, wired, wireless, APs, switches)
- Current bandwidth throughput (TX/RX)
- Chart.js visualizations for client distribution
- Clickable AP cards with detailed client views

### Dashboard Charts

Three Chart.js visualizations on the main dashboard:
- **Clients by Band** - Doughnut chart showing 2.4 GHz (orange), 5 GHz (blue), 6 GHz (purple), Wired (green)
- **Clients by SSID** - Doughnut chart with dynamic colors for each network
- **Top Bandwidth** - Horizontal bar chart showing top 5 clients by total bytes

Both the Clients by Band and Clients by SSID charts have a "(hide Wired)" toggle link that filters out wired clients from the visualization. The toggle state persists in localStorage (`unifi-toolkit-hide-band-wired`, `unifi-toolkit-hide-ssid-wired`).

Charts update in real-time via WebSocket when the scheduler refreshes data (every 60 seconds).

### AP Detail Pages

The Access Points section header includes "(Click for detail)" hint. Clicking any AP card navigates to `/pulse/ap/{ap_mac}` with:
- AP info header (name, model, online/offline status)
- Stats grid (connected clients, uptime, channels, satisfaction, TX/RX)
- Band distribution chart for clients on that specific AP
- Full client table with columns: Name, IP, SSID, Band, Signal (dBm), Bandwidth

### Key Files

- **`tools/network_pulse/scheduler.py`** - Background refresh every 60s, aggregates chart data
- **`tools/network_pulse/models.py`** - Pydantic models including `ChartData`, `TopClient` with radio/ap_mac
- **`tools/network_pulse/routers/stats.py`** - API endpoints including `/api/stats/ap/{ap_mac}`
- **`tools/network_pulse/static/js/app.js`** - Alpine.js dashboard with chart management
- **`tools/network_pulse/static/js/ap_detail.js`** - AP detail page component

### Radio Band Mapping

UniFi API radio codes are mapped to friendly names:
- `ng`, `2g`, `b`, `g` → "2.4 GHz"
- `na`, `5g`, `a`, `ac`, `ax` → "5 GHz"
- `6e`, `6g` → "6 GHz"
- Wired clients have `radio = None`

### API Endpoints

All mounted under `/pulse/api/`:
- **Stats**: GET `/api/stats` - Full dashboard data including chart_data
- **Status**: GET `/api/status` - Scheduler status and errors
- **AP Detail**: GET `/api/stats/ap/{ap_mac}` - Single AP info with filtered clients

### Caching

All clients are cached in memory (`all_clients` list in `DashboardData`) for fast AP detail page loads without additional UniFi API calls.

## Database Migrations (Alembic)

### Creating Migrations

```bash
# Auto-generate migration after model changes
alembic revision --autogenerate -m "Description of changes"

# Review generated migration in alembic/versions/
# Edit if necessary

# Apply migration
alembic upgrade head
```

### Important Notes

- **Import all models** in `alembic/env.py` so Alembic can detect them
- **SQLite limitations**: Use `render_as_batch=True` for ALTER TABLE operations
- **Review auto-generated migrations** before running (Alembic isn't perfect)

## Adding a New Tool

To add a new tool to the toolkit:

1. **Create tool directory**: `tools/new_tool/`
2. **Create app factory**: `tools/new_tool/main.py` with `create_app()` function
3. **Define models**: `tools/new_tool/database.py` (use `newtool_` prefix)
4. **Create routers**: `tools/new_tool/routers/*.py`
5. **Mount in main app**: Edit `app/main.py`:
   ```python
   from tools.new_tool.main import create_app as create_newtool_app

   newtool_app = create_newtool_app()
   app.mount("/newtool", newtool_app)
   ```
6. **Import models in Alembic**: Edit `alembic/env.py`
7. **Create migration**: `alembic revision --autogenerate -m "Add new_tool tables"`
8. **Update dashboard**: Edit `app/templates/dashboard.html` to add tool card

## Common Development Tasks

### Testing UniFi Connection

```bash
# Via API (with app running)
curl http://localhost:8000/api/config/unifi/test
```

### Viewing Logs

```bash
# Set LOG_LEVEL=DEBUG in .env for detailed logs
# Restart app to see scheduler activity
```

### Database Inspection

```bash
# Open database
sqlite3 ./data/unifi_toolkit.db

# List tables
.tables

# View tracked devices
SELECT * FROM stalker_tracked_devices;

# View history
SELECT * FROM stalker_connection_history ORDER BY connected_at DESC LIMIT 10;

# Exit
.quit
```

### Manual Refresh Trigger

The scheduler runs automatically, but to test immediately, restart the app (refresh runs on startup).

## Key Behaviors

1. **Refresh interval**: Default 60 seconds, configurable via `STALKER_REFRESH_INTERVAL`
2. **MAC normalization**: User can enter with any separator, normalized to lowercase with colons
3. **History entry lifecycle**:
   - Created: When device first connects OR roams to new AP
   - Open: `disconnected_at = NULL` while on that AP
   - Closed: When device roams away or goes offline
4. **AP name resolution**: Gets friendly name from controller, falls back to model or MAC

## Important Dependencies

- `fastapi` - Web framework
- `uvicorn[standard]` - ASGI server
- `aiounifi==85` - UniFi API client (**version locked for Python <3.13**)
- `sqlalchemy` - ORM
- `aiosqlite` - Async SQLite driver
- `apscheduler` - Background task scheduler
- `cryptography` - Fernet encryption
- `pydantic-settings` - Environment variable management
- `alembic` - Database migrations
- `python-dotenv` - .env file loading

## Security Notes

- Encryption key must be kept secure (in `.env`, not committed)
- `.env` is gitignored by default
- Database contains encrypted credentials
- Authentication available in production mode (session-based with bcrypt)
- Local mode has no authentication (designed for trusted LAN environments)
- SSL verification can be disabled for self-signed UniFi certificates

## Troubleshooting Common Issues

**"No UniFi configuration found"**:
- Configure via web UI OR set variables in `.env`
- Ensure `ENCRYPTION_KEY` is set

**"Failed to connect to UniFi controller"**:
- Set `UNIFI_VERIFY_SSL=false` for self-signed certs
- Verify controller URL is accessible
- Test credentials in UniFi dashboard first
- For UniFi OS (UDM, UCG, Cloud Key with recent firmware): use `https://IP` without port
- For legacy self-hosted controllers: use `https://IP:8443`
- Controller type is auto-detected; check DEBUG logs to see which auth method was attempted

**Device not showing as online**:
- Wait 60 seconds for next refresh
- Check MAC address is correct
- Verify device is actually connected (check UniFi dashboard)
- Enable DEBUG logging to see active clients list

**Python version errors**:
- Must use Python 3.9-3.12 (not 3.13+)
- Run `python --version` to check

**SQLite errors after git pull** (e.g., "no such column", connection test works but save fails):
- This happens when new code expects columns/tables that don't exist yet
- Docker fix: `docker compose exec unifi-toolkit alembic upgrade head && docker compose restart`
- Python fix: `source venv/bin/activate && alembic upgrade head`
- Always run migrations after pulling new code

## File Naming Conventions

- **Database models**: Use `stalker_` prefix for Wi-Fi Stalker tables
- **API routes**: Group by resource (devices, config, webhooks)
- **Templates**: Use tool-specific templates directory
- **Static files**: Organize by type (css/, js/)

## Testing Strategy

- **Manual testing**: Use web UI and API docs (http://localhost:8000/docs)
- **Database verification**: Check tables after operations
- **UniFi integration**: Test with real controller
- **Docker testing**: Ensure Docker deployment works

## Future Enhancements

### Planned Features
- **Multi-site support** - Ability to monitor and switch between multiple UniFi sites
- **Rotating ad banners** - Fetch banner ads from a central JSON source for dynamic updates without app changes

### Architecture Notes
As new tools are added:
- They will mount at their own prefix (`/ids`, `/recommender`, etc.)
- They will share the same UniFi configuration
- They will use their own table prefixes
- They will integrate into the main dashboard

The toolkit is designed to scale horizontally with minimal coupling between tools.
