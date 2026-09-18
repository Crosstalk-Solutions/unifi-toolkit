# UI Toolkit Quick Start Guide

Get up and running in 5 minutes.

---

## Ubuntu Server (Docker)

**Prerequisites:** Install Docker first - see [Docker Installation in INSTALLATION.md](INSTALLATION.md#option-a-docker-installation-recommended) for complete steps.

### Local Deployment (LAN Only)

```bash
# Clone and setup
git clone https://github.com/Crosstalk-Solutions/unifi-toolkit.git
cd unifi-toolkit
./setup.sh  # Select 1 for Local

# Start
docker compose up -d

# Access at http://localhost:8000
```

### Production Deployment (Internet-Facing)

```bash
# Clone and setup
git clone https://github.com/Crosstalk-Solutions/unifi-toolkit.git
cd unifi-toolkit
./setup.sh  # Select 2 for Production
# Enter: domain, username, password

# Open firewall
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp

# Start with Caddy (HTTPS)
docker compose --profile production up -d

# Access at https://your-domain.com
```

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

---

## First-Time Setup

1. Open UI Toolkit in browser
2. Click the **Settings cog (⚙️)** in the dashboard header
3. Enter UniFi controller details
4. Click **Test Connection**
5. Save configuration
6. Start using tools (Wi-Fi Stalker, Threat Watch, Network Pulse, House Arrest)

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Can't start | Run `./setup.sh` to create `.env` |
| Can't connect to UniFi | Check URL, credentials, set `UNIFI_VERIFY_SSL=false` |
| Certificate error | Wait 2 minutes, check DNS, ensure port 80 is open |
| Forgot password | Run `./reset_password.sh` then restart |
| Rate limited | Wait 5 minutes |

---

For detailed instructions, see [INSTALLATION.md](INSTALLATION.md).
