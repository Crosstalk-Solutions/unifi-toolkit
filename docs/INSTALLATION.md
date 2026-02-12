# UI Toolkit Installation Guide

Complete installation instructions for Ubuntu Server (22.04 LTS or 24.04 LTS).

> **Synology NAS users:** See [SYNOLOGY.md](SYNOLOGY.md) for Container Manager instructions.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Local Deployment](#local-deployment-lan-only)
- [Production Deployment](#production-deployment-internet-facing)
- [Post-Installation](#post-installation)
- [Updating](#updating)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **OS**: Ubuntu 22.04 LTS or 24.04 LTS (other Debian-based distros should work)
- **RAM**: 1 GB minimum, 2 GB recommended
- **Disk**: 1 GB free space
- **Network**: Access to your UniFi controller(s)

### Required Software

UI Toolkit can run either with Docker (recommended) or directly with Python.

#### Option A: Docker Installation (Recommended)

Install Docker from the official Docker repository:

```bash
# Install prerequisites
sudo apt update
sudo apt install -y ca-certificates curl

# Create keyrings directory
sudo install -m 0755 -d /etc/apt/keyrings

# Download Docker's GPG key
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add Docker repository
cat << 'EOF' | sudo tee /etc/apt/sources.list.d/docker.sources
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

# Note: For Ubuntu 22.04, change "noble" to "jammy" in the file above

# Install Docker and Docker Compose
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to the docker group (avoids needing sudo)
sudo usermod -aG docker $USER

# Apply group changes (or log out and back in)
newgrp docker

# Verify Docker is working
docker --version
docker compose version
docker run hello-world
```

#### Option B: Python Installation (Alternative)

```bash
# Update package list
sudo apt update

# Install Python and required packages
# Ubuntu 24.04: install Python 3.14 (preferred)
sudo apt install -y python3.14 python3.14-venv git

# Ubuntu 22.04: Python 3.10 is the default, install 3.14 via deadsnakes
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.14 python3.14-venv git

# Verify Python version (must be 3.13-3.14)
python3.14 --version
```

> **Note for Ubuntu 24.04 users:** The system Python is "externally managed" (PEP 668), which prevents system-wide pip installs. This is expected - you **must** use a virtual environment (venv) as shown in the installation steps below. The venv approach works around this protection.

---

## Installation

### Step 1: Clone the Repository

```bash
# Create the installation directory and set ownership
sudo mkdir -p /opt/unifi-toolkit
sudo chown $USER:$USER /opt/unifi-toolkit

# Clone the repository
git clone https://github.com/Crosstalk-Solutions/unifi-toolkit.git /opt/unifi-toolkit

# Navigate into the directory
cd /opt/unifi-toolkit
```

### Step 2: Run the Setup Wizard

The setup wizard will guide you through configuration:

```bash
./setup.sh
```

You'll be prompted to choose between:

1. **Local** - For LAN-only access (no authentication, no HTTPS)
2. **Production** - For internet-facing access (authentication + HTTPS)

---

## Local Deployment (LAN Only)

Use this option if UI Toolkit will only be accessed from your local network.

### Setup Wizard Prompts

```
Select deployment type [1-2]: 1

✓ Selected: local deployment
✓ Encryption key generated
✓ Configuration saved to .env
```

### Start with Docker (Recommended)

```bash
# Pull and start the container
docker compose up -d

# View logs (optional)
docker compose logs -f

# Stop viewing logs with Ctrl+C
```

The pre-built image is pulled automatically from GitHub Container Registry.

### Start with Python (Alternative)

```bash
# Create virtual environment (python3.14 preferred)
python3.14 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies (this works inside the venv, even on Ubuntu 24.04)
pip install -r requirements.txt

# Start the application
python run.py
```

### Access the Application

Open your browser and navigate to:

```
http://localhost:8000
```

Or from another device on your network:

```
http://<server-ip>:8000
```

### Changing the Default Port

By default, UI Toolkit runs on port 8000. To use a different port, add `APP_PORT` to your `.env` file:

```bash
# Edit your .env file
nano .env

# Add this line (example: port 8001)
APP_PORT=8001
```

Then restart the application:

```bash
docker compose restart
# or for Python: Ctrl+C and re-run python run.py
```

---

## Production Deployment (Internet-Facing)

Use this option if UI Toolkit will be accessible from the internet.

### Prerequisites for Production

1. **Domain name** pointing to your server's public IP
2. **Ports 80 and 443** open in your firewall
3. **DNS A record** configured for your domain

### Setup Wizard Prompts

```
Select deployment type [1-2]: 2

╔═══════════════════════════════════════════════════════════════╗
║  IMPORTANT: Network Security                                  ║
╠═══════════════════════════════════════════════════════════════╣
║  When managing multiple UniFi sites, always use site-to-site  ║
║  VPN connections. Never expose UniFi controllers directly to  ║
║  the internet via port forwarding.                            ║
╚═══════════════════════════════════════════════════════════════╝

Domain name: toolkit.yourdomain.com
Admin username [admin]: admin
Admin password (min 12 characters): ************
Confirm password: ************

✓ Encryption key generated
✓ Password configured
✓ Configuration saved to .env
```

### Configure Firewall

```bash
# Allow HTTP (for Let's Encrypt verification)
sudo ufw allow 80/tcp

# Allow HTTPS
sudo ufw allow 443/tcp

# Enable firewall if not already enabled
sudo ufw enable

# Check status
sudo ufw status
```

### Verify DNS

Before starting, verify your domain points to your server:

```bash
# Replace with your domain
nslookup toolkit.yourdomain.com

# Should return your server's public IP
```

### Start with Docker

```bash
# Start with production profile (includes Caddy)
docker compose --profile production up -d

# View logs to monitor certificate acquisition
docker compose logs -f caddy

# Stop viewing logs with Ctrl+C
```

### First Startup

On first startup, Caddy will automatically:
1. Obtain a Let's Encrypt SSL certificate
2. Configure HTTPS
3. Redirect HTTP to HTTPS

This may take 1-2 minutes. You can monitor progress:

```bash
docker compose logs -f caddy
```

Look for: `certificate obtained successfully`

### Access the Application

Open your browser and navigate to:

```
https://toolkit.yourdomain.com
```

Login with the credentials you configured during setup.

---

## Post-Installation

### Configure UniFi Controller

1. Open UI Toolkit in your browser
2. Click the **Settings cog (⚙️)** in the dashboard header
3. Enter your UniFi controller details:

**Controller URL:**
   - **UniFi OS devices** (UDM, UCG, Cloud Key with recent firmware): `https://192.168.1.1` (no port)
   - **Self-hosted controllers**: `https://192.168.1.1:8443` (include port 8443)

**Authentication (auto-detected):**
   - **API Key (recommended for UniFi OS)**: Generate in UniFi OS Settings → Integrations → API Keys
   - **Username/Password**: Works for all controller types - UI Toolkit auto-detects UniFi OS vs legacy

**Other Settings:**
   - **Site ID**: Usually `default`. For multi-site, use the alphanumeric code from the URL (e.g., `7jnove4a` from `/network/7jnove4a/...`)
   - **Verify SSL**: Disable for self-signed certificates (most UniFi deployments)

**Note**: Cloud Key Gen2+ now runs UniFi OS on recent firmware. Use the UniFi OS URL format (no port) for these devices.

### Test Connection

After configuring, click **Test Connection** to verify connectivity.

### Start Using Tools

- **Wi-Fi Stalker**: Track specific devices by MAC address
- **Threat Watch**: Monitor IDS/IPS security events
- **Network Pulse**: Real-time network monitoring dashboard

---

## Managing the Application

### Docker Commands

```bash
# Start the application
docker compose up -d                          # Local mode
docker compose --profile production up -d     # Production mode

# Stop the application
docker compose down

# View logs
docker compose logs -f

# Restart the application
docker compose restart

# Pull latest image
docker compose pull
docker compose up -d
```

### Python Commands

```bash
# Activate virtual environment
source venv/bin/activate

# Start the application
python run.py

# Stop with Ctrl+C
```

### Reset Admin Password

If you forget your password:

```bash
cd /opt/unifi-toolkit
./reset_password.sh

# Restart to apply changes
docker compose --profile production restart
```

---

## Updating

### Upgrade Script (Recommended)

The easiest way to update is using the upgrade script, which handles everything automatically:

```bash
cd /opt/unifi-toolkit
./upgrade.sh
```

The upgrade script will:
1. Detect your deployment mode (local or production)
2. Stop the running containers
3. Pull the latest code from git
4. Pull the latest Docker image from GitHub Container Registry
5. Run database migrations (with smart error handling)
6. Restart the application

### Manual Update (Docker)

If you prefer to update manually:

```bash
cd /opt/unifi-toolkit

# Pull latest image from GitHub Container Registry
docker compose pull

# Start with updated image
docker compose up -d                          # Local mode
# OR
docker compose --profile production up -d     # Production mode

# Apply any database migrations (run this after every update)
docker compose exec unifi-toolkit alembic upgrade head

# Restart to ensure changes take effect
docker compose restart
```

### Manual Update (Python/non-Docker)

```bash
cd /opt/unifi-toolkit
source venv/bin/activate

# Pull latest changes
git pull origin main

# Update Python dependencies (important for security patches)
pip install -r requirements.txt --upgrade

# Apply any database migrations
alembic upgrade head

# Restart the application
python run.py
```

> **Note**: Unlike Docker deployments where dependencies are updated automatically during image rebuild, Python/venv installations require manually running `pip install -r requirements.txt --upgrade` to receive security patches and dependency updates.

**Note:** Always run migrations after pulling updates. Skipping this step can cause SQLite errors if the update includes database schema changes. See [Database Errors After Git Pull](#database-errors-after-git-pull) for troubleshooting.

---

## Troubleshooting

### Application Won't Start

**Check logs:**
```bash
docker compose logs unifi-toolkit
```

**Common issues:**
- Missing `.env` file: Run `./setup.sh`
- Missing `ENCRYPTION_KEY`: Regenerate with setup wizard
- Port 8000 in use: Change `APP_PORT` in `.env`

### "externally-managed-environment" Error (Ubuntu 24.04)

**Symptom:** When running `pip install`, you get:
```
error: externally-managed-environment
```

**Cause:** Ubuntu 24.04 (and other recent distros) mark the system Python as "externally managed" per PEP 668 to prevent breaking system packages.

**Fix:** Use a virtual environment (venv):
```bash
# Install Python 3.14 venv support
sudo apt install python3.14 python3.14-venv

# Create and activate virtual environment
python3.14 -m venv venv
source venv/bin/activate

# Now pip install works
pip install -r requirements.txt
```

**Important:** You must activate the venv (`source venv/bin/activate`) every time you open a new terminal before running the app.

### Can't Connect to UniFi Controller

**Verify network access:**
```bash
# Test connectivity to controller
curl -k https://192.168.1.1:8443/status
```

**Common issues:**
- Wrong controller URL
- Firewall blocking access
- Invalid credentials
- Self-signed cert: Set `UNIFI_VERIFY_SSL=false`

### Let's Encrypt Certificate Fails

**Check Caddy logs:**
```bash
docker compose logs caddy
```

**Common issues:**
- DNS not propagated yet (wait 5-10 minutes)
- Port 80 blocked (required for verification)
- Domain doesn't point to server
- Rate limited (too many attempts)

### Rate Limited on Login

If you see "Too many login attempts":
- Wait 5 minutes for the lockout to expire
- The countdown timer shows remaining time

### Database Errors After Git Pull

**Symptom:** SQLite errors like "no such column", "database schema mismatch", or the connection test works but saving fails.

**Cause:** New code often includes database schema changes (new columns/tables). If you don't run migrations after pulling, the code expects columns that don't exist in your database.

**Fix - Apply migrations (Docker):**
```bash
cd /opt/unifi-toolkit
docker compose exec unifi-toolkit alembic upgrade head
docker compose restart
```

**Fix - Apply migrations (Python/non-Docker):**
```bash
cd /opt/unifi-toolkit
source venv/bin/activate
alembic upgrade head
python run.py
```

**Quick reference for Docker updates:**
```bash
cd /opt/unifi-toolkit
git pull                                              # Pull latest code
docker compose exec unifi-toolkit alembic upgrade head  # Apply migrations
docker compose restart                                # Restart app
```

### Reset Database (Last Resort)

**Warning:** This loses all tracked devices, history, and configuration.

```bash
# Stop application
docker compose down

# Remove database
rm -f data/unifi_toolkit.db

# Restart (creates fresh database)
docker compose up -d
```

### Docker Permission Denied

**"permission denied" when running `docker compose`:**

This means your user isn't in the `docker` group. You have two options:

**Option 1 - Add user to docker group (recommended):**
```bash
sudo usermod -aG docker $USER

# Log out and back in, or run:
newgrp docker

# Verify it works
docker ps
```

**Option 2 - Use sudo (less ideal):**
```bash
sudo docker compose up -d
```

Using `sudo` can cause file permission issues since containers create files as root. If you must use `sudo`, you may need to fix permissions later:
```bash
sudo chown -R $USER:$USER data/
```

### Permission Errors

**"unable to open database file" in Docker:**

This happens when the Docker container can't write to the data directory. Fix it by setting proper permissions:

```bash
# Create data directory with write permissions for Docker
mkdir -p data
chmod 777 data

# Restart the container
docker compose down
docker compose up -d
```

**General permission errors:**

```bash
# Fix ownership
sudo chown -R $USER:$USER /opt/unifi-toolkit

# Fix data directory permissions
chmod 755 /opt/unifi-toolkit/data
```

---

## Security Best Practices

### For Production Deployments

1. **Use strong passwords**: 12+ characters, mixed case, numbers
2. **Keep software updated**: Regularly pull updates from git
3. **Use VPN for multi-site**: Never expose UniFi controllers to the internet
4. **Monitor logs**: Check for suspicious login attempts
5. **Backup regularly**: Export your database periodically

### Network Security

When managing multiple UniFi sites:

```
✅ RECOMMENDED: Site-to-Site VPN
┌─────────────────────┐         ┌─────────────────────┐
│  UI Toolkit Server  │◄──VPN──►│  Remote UniFi Site  │
│  192.168.1.0/24     │         │  10.20.30.0/24      │
└─────────────────────┘         └─────────────────────┘

❌ NOT RECOMMENDED: Port Forwarding
┌─────────────────────┐         ┌─────────────────────┐
│  UI Toolkit Server  │◄─INTERNET─►│  Exposed Controller │
│                     │  (DANGER)  │  (SECURITY RISK)    │
└─────────────────────┘         └─────────────────────┘
```

**VPN Options:**
- UniFi Site-to-Site VPN (built into UDM/UCG)
- WireGuard
- Tailscale / ZeroTier
- IPSec / OpenVPN

---

## File Locations

| File/Directory | Purpose |
|----------------|---------|
| `/opt/unifi-toolkit/.env` | Configuration file |
| `/opt/unifi-toolkit/data/` | Database and persistent data |
| `/opt/unifi-toolkit/setup.sh` | Setup wizard |
| `/opt/unifi-toolkit/upgrade.sh` | Upgrade script (handles git pull, rebuild, migrations) |
| `/opt/unifi-toolkit/reset_password.sh` | Password reset utility |
| `/opt/unifi-toolkit/Caddyfile` | Reverse proxy configuration |
| `/opt/unifi-toolkit/docker-compose.yml` | Docker configuration |

---

## Getting Help

- **Community**: [#unifi-toolkit on Discord](https://discord.com/invite/crosstalksolutions)
- **GitHub Issues**: [Report a bug or request a feature](https://github.com/Crosstalk-Solutions/unifi-toolkit/issues)
- **Documentation**: Check the `docs/` directory for additional guides

---

## Quick Reference

### Local Deployment
```bash
sudo mkdir -p /opt/unifi-toolkit && sudo chown $USER:$USER /opt/unifi-toolkit
git clone https://github.com/Crosstalk-Solutions/unifi-toolkit.git /opt/unifi-toolkit
cd /opt/unifi-toolkit
./setup.sh  # Select 1 for Local
docker compose up -d
# Access: http://localhost:8000
```

### Production Deployment
```bash
sudo mkdir -p /opt/unifi-toolkit && sudo chown $USER:$USER /opt/unifi-toolkit
git clone https://github.com/Crosstalk-Solutions/unifi-toolkit.git /opt/unifi-toolkit
cd /opt/unifi-toolkit
./setup.sh  # Select 2 for Production
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
docker compose --profile production up -d
# Access: https://your-domain.com
```

### Updating (Docker)
```bash
cd /opt/unifi-toolkit
./upgrade.sh
```
