# UI Toolkit Installation Guide

Complete installation instructions for Ubuntu Server (22.04 LTS or 24.04 LTS).

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

# Install Python 3.11 and required packages
sudo apt install -y python3.11 python3.11-venv python3-pip git

# Verify Python version (must be 3.9-3.12, NOT 3.13+)
python3.11 --version
```

---

## Installation

### Step 1: Clone the Repository

**Note:** This is a private repository. You need GitHub access and SSH keys configured.

```bash
# Navigate to where you want to install
cd /opt

# Clone the repository (requires SSH key access)
sudo git clone git@github.com:Crosstalk-Solutions/unifi-toolkit.git

# Change ownership to your user (replace 'yourusername' with your actual username)
sudo chown -R $USER:$USER /opt/unifi-toolkit

# Navigate into the directory
cd /opt/unifi-toolkit
```

If you haven't set up SSH keys for GitHub, see: https://docs.github.com/en/authentication/connecting-to-github-with-ssh

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
# Build and start the container
docker compose up -d

# View logs (optional)
docker compose logs -f

# Stop viewing logs with Ctrl+C
```

### Start with Python (Alternative)

```bash
# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
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
# Build and start with production profile (includes Caddy)
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
2. Click on **Wi-Fi Stalker** or **Threat Watch**
3. Click **Settings** (gear icon)
4. Enter your UniFi controller details:
   - **Controller URL**: `https://192.168.1.1` (your controller IP)
   - **Authentication**: Username/password OR API key
   - **Site ID**: Usually `default`
   - **Verify SSL**: Disable for self-signed certificates

### Test Connection

After configuring, click **Test Connection** to verify connectivity.

### Start Using Tools

- **Wi-Fi Stalker**: Track specific devices by MAC address
- **Threat Watch**: Monitor IDS/IPS security events

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

# Rebuild after updates
docker compose build
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

### Update from Git

```bash
cd /opt/unifi-toolkit

# Stop the application
docker compose down

# Pull latest changes
git pull origin main

# Rebuild and start
docker compose build
docker compose up -d                          # Local mode
# OR
docker compose --profile production up -d     # Production mode
```

### Database Migrations

If the update includes database changes:

```bash
# With Docker
docker compose exec unifi-toolkit alembic upgrade head

# With Python
source venv/bin/activate
alembic upgrade head
```

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

### Database Errors

**Reset database (loses all data):**
```bash
# Stop application
docker compose down

# Remove database
rm -f data/unifi_toolkit.db

# Restart
docker compose up -d
```

### Permission Errors

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
| `/opt/unifi-toolkit/reset_password.sh` | Password reset utility |
| `/opt/unifi-toolkit/Caddyfile` | Reverse proxy configuration |
| `/opt/unifi-toolkit/docker-compose.yml` | Docker configuration |

---

## Getting Help

- **GitHub Issues**: [Report a bug or request a feature](https://github.com/CrosstalkSolutions/unifi-toolkit/issues)
- **Documentation**: Check the `docs/` directory for additional guides

---

## Quick Reference

### Local Deployment
```bash
git clone git@github.com:Crosstalk-Solutions/unifi-toolkit.git
cd unifi-toolkit
./setup.sh  # Select 1 for Local
docker compose up -d
# Access: http://localhost:8000
```

### Production Deployment
```bash
git clone git@github.com:Crosstalk-Solutions/unifi-toolkit.git
cd unifi-toolkit
./setup.sh  # Select 2 for Production
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
docker compose --profile production up -d
# Access: https://your-domain.com
```
