# UI Toolkit

A comprehensive suite of tools for UniFi network management and monitoring.

> **Note:** This project is not affiliated with, endorsed by, or sponsored by Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc.

<img width="1094" height="748" alt="image" src="https://github.com/user-attachments/assets/a167fc5c-9db5-48f2-8b43-0dfdab3b08a8" />

## Features

### Dashboard
Real-time system status including:
- **Gateway Info** - Model, firmware, uptime
- **Resource Usage** - CPU and RAM utilization
- **Network Health** - WAN, LAN, WLAN, VPN status with diagnostic reasons
- **Connected Clients** - Wired and wireless counts
- **WAN Status** - IP, ISP, latency, uptime (supports 3+ WANs dynamically)
- **Debug Info** - One-click copy of system info for issue reporting

### Wi-Fi Stalker
Track specific client devices through your UniFi infrastructure.
- Device tracking by MAC address (wireless and wired)
- Roaming detection between access points
- Connection history with timestamps and CSV export
- Signal strength, radio band (2.4/5/6 GHz), and SSID tracking
- Device analytics: dwell time, favorite AP, presence pattern heatmap
- Block/unblock devices directly from the UI
- Webhook alerts (Slack, Discord, n8n) for connect, disconnect, roam, block, and unblock events

<img width="1355" height="702" alt="image" src="https://github.com/user-attachments/assets/383d3c84-1b24-480a-bbaf-e72c47953b85" />

### Threat Watch
Monitor IDS/IPS security events from your UniFi gateway.
- Real-time event monitoring (requires UniFi OS)
- Threat categorization and analysis
- Top attackers and targets
- Ignore rules: filter noise by IP address and severity level
- Sortable event columns and advanced filtering
- Webhook alerts (Slack, Discord, n8n)

<img width="1359" height="468" alt="image" src="https://github.com/user-attachments/assets/7bfec7f7-bdf6-4ae2-af0e-143dcd982d4a" />

### House Arrest
Lock a device or a whole network down using UniFi's zone-based firewall — reversible in one click, and honest about exactly what is and is not being blocked.
- **Networks** - Editable audit matrix of your VLANs: firewall zone, network isolation, internet access, mDNS, and DHCP DNS at a glance, with per-SSID Wi-Fi client isolation
- **DNS Lockdown** - Force chosen networks onto approved DNS resolvers and block everything else answering DNS (optionally DNS-over-TLS too)
- **Devices** - Per-device lockdown presets by MAC: Full lockdown, Internet only, or LAN only, with multi-device selection
- **Blocked traffic view** - See what each lockdown actually stopped, attributed to its own rules by ID
- Every change is previewed before applying, every rule carries a marker so release can only ever delete its own rules, and a lockdown that stops enforcing (MAC changed, rule disabled in UniFi) is flagged instead of shown green
- **Requires the zone-based firewall** (UniFi Network 9.0+ on a UniFi OS console)

See [docs/HOUSE-ARREST.md](docs/HOUSE-ARREST.md) for the full guide, including measured limitations.

### Network Pulse
Real-time network monitoring dashboard.
- Gateway status (model, firmware, uptime, WAN)
- Device counts (total clients, wired, wireless, APs, switches)
- Chart.js visualizations (clients by band, clients by SSID, top bandwidth)
- Clickable AP cards with detailed client views
- WebSocket-powered live updates

<img width="1895" height="957" alt="image" src="https://github.com/user-attachments/assets/ca6f0df5-8657-4c2a-ad16-8807aa21bcac" />

---

## Quick Start

### Requirements
- **Docker** (recommended) or Python 3.9+
- **Ubuntu 22.04/24.04** (or other Linux)
- **UniFi OS** controller (UDM, UCG, Cloud Key Gen2+) — standalone/self-hosted controllers are not supported as of v1.11.0

### Local Deployment (LAN Only)

No authentication, access via `http://localhost:8000`

**Prerequisites:** Install Docker first - see [docs/INSTALLATION.md](docs/INSTALLATION.md#option-a-docker-installation-recommended)

```bash
# Clone and setup
git clone https://github.com/Crosstalk-Solutions/unifi-toolkit.git
cd unifi-toolkit
./setup.sh  # Select 1 for Local

# Start
docker compose up -d
```

Access at **http://localhost:8000**

### Production Deployment (Internet-Facing)

Authentication enabled, HTTPS with Let's Encrypt via Caddy

**Prerequisites:** Install Docker first - see [docs/INSTALLATION.md](docs/INSTALLATION.md#option-a-docker-installation-recommended)

```bash
# Clone and setup
git clone https://github.com/Crosstalk-Solutions/unifi-toolkit.git
cd unifi-toolkit
./setup.sh  # Select 2 for Production
# Enter: domain name, admin username, password

# Open firewall ports
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp

# Start with HTTPS
docker compose --profile production up -d
```

Access at **https://your-domain.com**

---

## Documentation

| Guide | Description |
|-------|-------------|
| [INSTALLATION.md](docs/INSTALLATION.md) | Complete installation guide with troubleshooting |
| [SYNOLOGY.md](docs/SYNOLOGY.md) | Synology NAS Container Manager setup |
| [QNAP Guide](https://github.com/Crosstalk-Solutions/unifi-toolkit/issues/29) | QNAP Container Station setup (community) |
| [Unraid Guide](docs/UNRAID.md) | Unraid Community apps Setup |
| [QUICKSTART.md](docs/QUICKSTART.md) | 5-minute quick start reference |
| [HOUSE-ARREST.md](docs/HOUSE-ARREST.md) | House Arrest guide: lockdowns, DNS control, and measured limitations |

---

## Common Commands

| Action | Command |
|--------|---------|
| Start (local) | `docker compose up -d` |
| Start (production) | `docker compose --profile production up -d` |
| Stop | `docker compose down` |
| View logs | `docker compose logs -f` |
| Restart | `docker compose restart` |
| Reset password | `./reset_password.sh` |
| Update | `./upgrade.sh` |

Images are published to both GHCR (`ghcr.io/crosstalk-solutions/unifi-toolkit`) and Docker Hub (`crosstalksolutions/unifi-toolkit`) — they are identical. `:latest` is the release channel and only moves on tagged releases; `:edge` is the beta/staging channel, rebuilt on every merge. See [Running the beta channel](docs/INSTALLATION.md#running-the-beta-edge-channel).

---

## Configuration

### Setup Wizard (Recommended)

Run the interactive setup wizard:

```bash
./setup.sh
```

The wizard will:
- Generate encryption key
- Configure deployment mode (local/production)
- Set up authentication (production only)
- Create your `.env` file

### Manual Configuration

Copy and edit the example configuration:

```bash
cp .env.example .env
```

#### Required Settings

| Variable | Description |
|----------|-------------|
| `ENCRYPTION_KEY` | Encrypts stored credentials (auto-generated by setup wizard) |

#### Deployment Settings (Production Only)

| Variable | Description |
|----------|-------------|
| `DEPLOYMENT_TYPE` | `local` or `production` |
| `DOMAIN` | Your domain name (e.g., `toolkit.example.com`) |
| `AUTH_USERNAME` | Admin username |
| `AUTH_PASSWORD_HASH` | Bcrypt password hash (generated by setup wizard) |

#### UniFi Controller Settings

UniFi controller credentials are configured **through the web UI** after first
launch (the gear icon on the dashboard) — they are stored encrypted in the
database, not read from environment variables.

| Setting (web UI) | Description |
|----------|-------------|
| Controller URL | Local controller IP/hostname (e.g., `https://192.168.1.1`) |
| API key | Recommended — generate in UniFi OS Settings → Admins |
| Username / password | Fallback if not using an API key |
| Site ID | Site ID from URL, not friendly name (default: `default`). For multi-site, use ID from `/manage/site/{id}/...` |
| Verify SSL | Off by default (self-signed controller certificates) |

> **Note:** Use your controller's local IP address (e.g., `https://192.168.1.1`). Cloud access via `unifi.ui.com` is not supported.

#### Other Settings

| Variable | Description |
|----------|-------------|
| `STALKER_REFRESH_INTERVAL` | Device refresh interval in seconds (default: `60`) |
| `ALLOWED_HOSTS` | Extra hostnames allowed to reach the toolkit (comma separated). The toolkit rejects requests whose Host header is not an IP, `localhost`, a `.local`-style name, or your `DOMAIN` — this protects against DNS-rebinding. If you access it through a Tailscale name or reverse-proxy alias, add that name here. |

Every secret-carrying variable also accepts a `_FILE` variant (e.g. `ENCRYPTION_KEY_FILE=/run/secrets/key`) for Docker Swarm / Kubernetes secrets mounted as files.

---

## Security

### Authentication

- **Local mode**: No authentication (trusted LAN only)
- **Production mode**: Session-based authentication with bcrypt password hashing
- **Rate limiting**: 5 failed login attempts = 5 minute lockout

### HTTPS

Production deployments use Caddy for automatic HTTPS:
- Let's Encrypt certificates (auto-renewed)
- HTTP to HTTPS redirect
- Security headers (HSTS, X-Frame-Options, etc.)

### Multi-Site Networking

When managing multiple UniFi sites, always use site-to-site VPN:

```
✅ RECOMMENDED: VPN Connection
┌──────────────────┐         ┌──────────────────┐
│  UI Toolkit      │◄──VPN──►│  Remote UniFi    │
│  Server          │         │  Controller      │
└──────────────────┘         └──────────────────┘

❌ AVOID: Direct Internet Exposure
Never expose UniFi controllers via port forwarding
```

**VPN Options:** UniFi Site-to-Site, WireGuard, Tailscale, IPSec

---

## Troubleshooting

### Can't connect to UniFi controller
- **UniFi OS required** — standalone/self-hosted controllers are not supported (v1.11.0+). If you're running the Java-based controller software, v1.10.3 is the last compatible version.
- **Stable (GA) firmware only** — Early Access firmware changes APIs without notice and is not supported. If a tool suddenly gets errors or empty data, check your firmware channel first (your firmware version is in Debug Info).
- Set `UNIFI_VERIFY_SSL=false` for self-signed certificates
- API key auth is recommended — generate in UniFi OS Settings → Admins
- Verify network connectivity to controller

### Device not showing as online
- Wait 60 seconds for the next refresh cycle
- Verify MAC address format is correct
- Confirm device is connected in UniFi dashboard

### Let's Encrypt certificate fails
- Verify DNS A record points to your server
- Ensure ports 80 and 443 are open
- Check Caddy logs: `docker compose logs caddy`

### Rate limited on login
- Wait 5 minutes for lockout to expire
- Use `./reset_password.sh` if you forgot your password

### Requests rejected when using a hostname
- The toolkit only answers requests addressed to an IP, `localhost`, a `.local`-style name, or your configured `DOMAIN` (anti-DNS-rebinding protection). Add other names — a Tailscale MagicDNS name, a reverse-proxy alias — to `ALLOWED_HOSTS` in `.env`.

### Docker issues
- Verify `.env` exists and contains `ENCRYPTION_KEY`
- Check logs: `docker compose logs -f`
- Pull latest image: `docker compose pull && docker compose up -d`

---

## Running with Python (Alternative to Docker)

```bash
# Clone repository
git clone https://github.com/Crosstalk-Solutions/unifi-toolkit.git
cd unifi-toolkit

# Create virtual environment (Python 3.9+)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run setup wizard
./setup.sh

# Start application
python run.py
```

---

## Project Structure

```
unifi-toolkit/
├── app/                    # Main application
│   ├── main.py            # FastAPI entry point
│   ├── routers/           # API routes (auth, config)
│   ├── static/            # CSS, images
│   └── templates/         # HTML templates
├── tools/                 # Individual tools
│   ├── wifi_stalker/      # Wi-Fi Stalker tool
│   ├── threat_watch/      # Threat Watch tool
│   ├── network_pulse/     # Network Pulse tool
│   └── house_arrest/      # House Arrest tool
├── shared/                # Shared infrastructure
│   ├── config.py          # Settings management
│   ├── database.py        # SQLAlchemy setup
│   ├── unifi_client.py    # UniFi API wrapper
│   └── crypto.py          # Credential encryption
├── docs/                  # Documentation
├── data/                  # Database (created at runtime)
├── setup.sh               # Setup wizard
├── upgrade.sh             # Upgrade script
├── reset_password.sh      # Password reset utility
├── Caddyfile              # Reverse proxy config
├── docker-compose.yml     # Docker configuration
└── requirements.txt       # Python dependencies
```

---

## Development

### Running Tests

The project includes a comprehensive test suite covering authentication, caching, configuration, and encryption.

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_auth.py -v

# Run with coverage
pytest tests/ --cov=shared --cov=app -v
```

**Test modules:**
- `tests/test_auth.py` - Authentication, session management, rate limiting (23 tests)
- `tests/test_cache.py` - In-memory caching with TTL expiration (19 tests)
- `tests/test_config.py` - Pydantic settings and environment variables (13 tests)
- `tests/test_crypto.py` - Fernet encryption for credentials (14 tests)
- `tests/test_house_arrest_policies.py` - House Arrest policy builders, zone resolution, safety checks (199 tests)

---

## Support

- **Community**: [#unifi-toolkit on Discord](https://discord.com/invite/crosstalksolutions)
- **Issues**: [GitHub Issues](https://github.com/Crosstalk-Solutions/unifi-toolkit/issues)
- **Documentation**: [docs/](docs/)

### Buy Me a Coffee

If you find UI Toolkit useful, consider supporting development:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/crosstalk)

---

## Credits

Developed by [Crosstalk Solutions](https://www.crosstalksolutions.com/)

- YouTube: [@CrosstalkSolutions](https://www.youtube.com/@CrosstalkSolutions)

---

## License

MIT License
