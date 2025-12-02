# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**UI Toolkit** (v1.4.0) is a comprehensive monorepo containing multiple tools for UniFi network management and monitoring. Each tool operates independently but shares common infrastructure for UniFi API access, database management, configuration, and authentication.

**Current Tools:**
- **Wi-Fi Stalker v0.7.0** - Track specific client devices, monitor roaming, and maintain connection history
- **Threat Watch v0.1.0** - Monitor IDS/IPS events, view blocked threats, analyze attack patterns, and receive webhook alerts

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
│   ├── QUICKSTART.md     # Quick start reference
│   └── MIGRATION.md      # Migration from standalone wifi-stalker
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

Supports **two authentication methods**:

1. **Legacy Controllers**: username + password (uses aiounifi.Controller)
2. **UniFi OS (UCG, UDM, etc.)**: API key (direct HTTP calls)

Auto-detects which method based on presence of `api_key`.

Key methods:
- `connect()` - Authenticate and connect
- `get_clients()` - Get all active clients
- `get_ap_name_by_mac()` - Resolve AP MAC to friendly name
- `disconnect()` - Close connection

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
- Webhook configurations for events (connected, disconnected, roamed)
- Supports Slack, Discord, n8n/generic

### API Endpoints

All mounted under `/stalker/api/`:

- **Devices**: GET/POST/DELETE `/api/devices`
- **Device Details**: GET `/api/devices/{id}/details`
- **History**: GET `/api/devices/{id}/history`
- **UniFi Config**: GET/POST `/api/config/unifi`
- **Webhooks**: GET/POST/PUT/DELETE `/api/webhooks`

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
curl http://localhost:8000/stalker/api/config/unifi/test
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
- No user authentication (designed as single-user local app)
- SSL verification can be disabled for self-signed UniFi certificates

## Troubleshooting Common Issues

**"No UniFi configuration found"**:
- Configure via web UI OR set variables in `.env`
- Ensure `ENCRYPTION_KEY` is set

**"Failed to connect to UniFi controller"**:
- Set `UNIFI_VERIFY_SSL=false` for self-signed certs
- Verify controller URL is accessible
- Test credentials in UniFi dashboard first
- Check if using UniFi OS (need API key, not just password)

**Device not showing as online**:
- Wait 60 seconds for next refresh
- Check MAC address is correct
- Verify device is actually connected (check UniFi dashboard)
- Enable DEBUG logging to see active clients list

**Python version errors**:
- Must use Python 3.9-3.12 (not 3.13+)
- Run `python --version` to check

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

As new tools are added:
- They will mount at their own prefix (`/ids`, `/recommender`, etc.)
- They will share the same UniFi configuration
- They will use their own table prefixes
- They will integrate into the main dashboard

The toolkit is designed to scale horizontally with minimal coupling between tools.
