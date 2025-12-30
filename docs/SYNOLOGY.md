# UI Toolkit on Synology NAS

Step-by-step instructions for running UI Toolkit on Synology NAS using Container Manager.

> **Important:** Synology Container Manager's GUI cannot browse or download images from GitHub Container Registry (ghcr.io) due to API limitations. This guide provides two working methods: SSH commands or Container Manager Projects.

---

## Prerequisites

- **Synology NAS** with Container Manager installed (DSM 7.2+)
- **SSH access** enabled (see below)
- **Supported architectures**: Intel (x86_64) or ARM64-based Synology models

### Enable SSH on Synology

SSH is disabled by default. To enable it:

1. Open **Control Panel**
2. Go to **Terminal & SNMP**
3. Check **Enable SSH service**
4. (Optional) Change the port from 22 if desired
5. Click **Apply**

You can then connect with: `ssh your-admin-user@your-synology-ip`

---

## Step 1: Create Folder Structure

> **Note:** This guide uses `/volume1/` in examples. Your Synology may use `/volume2/` or another path depending on your storage configuration. Substitute your actual volume path in all commands.

1. Open **File Station**
2. Navigate to the `docker` shared folder (create it if it doesn't exist)
3. Create a new folder called `unifi-toolkit`
4. Inside `unifi-toolkit`, create a subfolder called `data`

Your structure should look like:
```
/volume1/docker/unifi-toolkit/   (or /volume2/, etc.)
└── data/
```

### Set Permissions

The container runs as user ID 1000. Set ownership so it can write to the data directory:

```bash
sudo chown -R 1000:1000 /volume1/docker/unifi-toolkit/data
sudo chmod 755 /volume1/docker/unifi-toolkit/data
```

---

## Step 2: Create Configuration File

You need to create a `.env` file with your settings.

### Option A: Using File Station

1. On your computer, create a text file called `env.txt` with this content:

```
ENCRYPTION_KEY=paste-your-key-here
DEPLOYMENT_TYPE=local
LOG_LEVEL=INFO
```

2. Generate an encryption key using one of these methods:

   **Mac/Linux (no dependencies)**
   ```bash
   openssl rand -base64 32
   ```

   **Windows PowerShell (no dependencies)**
   ```powershell
   [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }) -as [byte[]])
   ```

   **Any system with Python**
   ```bash
   python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
   ```

3. Paste the generated key into your `env.txt` file, replacing `paste-your-key-here`

4. Upload `env.txt` to `/volume1/docker/unifi-toolkit/`

5. Rename the file from `env.txt` to `.env`:
   - In File Station, right-click the file → **Rename** → change to `.env`

### Option B: Using SSH

```bash
ssh your-admin-user@your-synology-ip
cd /volume1/docker/unifi-toolkit

# Generate key and create .env file
cat > .env << EOF
ENCRYPTION_KEY=$(openssl rand -base64 32)
DEPLOYMENT_TYPE=local
LOG_LEVEL=INFO
EOF
```

---

## Step 3: Choose Your Installation Method

Synology Container Manager cannot browse ghcr.io directly. Choose one of these methods:

| Method | Best For | Difficulty |
|--------|----------|------------|
| [Method A: SSH Commands](#method-a-ssh-commands-recommended) | Quick setup, familiar with terminal | Easy |
| [Method B: Container Manager Project](#method-b-container-manager-project) | Prefer GUI management | Moderate |

---

## Method A: SSH Commands (Recommended)

This method pulls the image via SSH and then lets you manage it in Container Manager.

### Step A1: SSH into your Synology

```bash
ssh your-admin-user@your-synology-ip
```

### Step A2: Pull the image

```bash
sudo docker pull ghcr.io/crosstalk-solutions/unifi-toolkit:latest
```

### Step A3: Create and start the container

```bash
sudo docker run -d \
  --name unifi-toolkit \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /volume1/docker/unifi-toolkit/data:/app/data \
  -v /volume1/docker/unifi-toolkit/.env:/app/.env:ro \
  ghcr.io/crosstalk-solutions/unifi-toolkit:latest
```

### Step A4: Verify it's running

```bash
sudo docker ps | grep unifi-toolkit
```

You should see the container running. It will also appear in Container Manager's GUI.

### Updating (Method A)

```bash
ssh your-admin-user@your-synology-ip
sudo docker pull ghcr.io/crosstalk-solutions/unifi-toolkit:latest
sudo docker stop unifi-toolkit
sudo docker rm unifi-toolkit
sudo docker run -d \
  --name unifi-toolkit \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /volume1/docker/unifi-toolkit/data:/app/data \
  -v /volume1/docker/unifi-toolkit/.env:/app/.env:ro \
  ghcr.io/crosstalk-solutions/unifi-toolkit:latest
```

---

## Method B: Container Manager Project

This method uses docker-compose via Container Manager's "Project" feature.

### Step B1: Create docker-compose.yml

Create a file called `docker-compose.yml` in `/volume1/docker/unifi-toolkit/` with this content:

```yaml
services:
  unifi-toolkit:
    image: ghcr.io/crosstalk-solutions/unifi-toolkit:latest
    container_name: unifi-toolkit
    restart: unless-stopped
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./.env:/app/.env:ro
```

You can create this file:
- **Via File Station**: Create on your computer, upload to the folder
- **Via SSH**:
  ```bash
  cat > /volume1/docker/unifi-toolkit/docker-compose.yml << 'EOF'
  services:
    unifi-toolkit:
      image: ghcr.io/crosstalk-solutions/unifi-toolkit:latest
      container_name: unifi-toolkit
      restart: unless-stopped
      ports:
        - "8000:8000"
      volumes:
        - ./data:/app/data
        - ./.env:/app/.env:ro
  EOF
  ```

### Step B2: Pull the image first (required)

Container Manager Projects cannot pull from ghcr.io directly. You must pull the image via SSH first:

```bash
ssh your-admin-user@your-synology-ip
sudo docker pull ghcr.io/crosstalk-solutions/unifi-toolkit:latest
```

### Step B3: Create the Project in Container Manager

1. Open **Container Manager**
2. Go to **Project** in the left sidebar
3. Click **Create**
4. Configure:
   - **Project name**: `unifi-toolkit`
   - **Path**: Click **Set path** and select `/docker/unifi-toolkit`
   - **Source**: Select "Use existing docker-compose.yml"
5. Click **Next**, review the settings
6. Click **Done** to create and start the project

### Updating (Method B)

1. SSH into your Synology and pull the new image:
   ```bash
   sudo docker pull ghcr.io/crosstalk-solutions/unifi-toolkit:latest
   ```
2. In Container Manager → Project → select `unifi-toolkit`
3. Click **Action** → **Stop**
4. Click **Action** → **Build** (rebuilds with new image)
5. Click **Action** → **Start**

---

## Step 4: Access UI Toolkit

1. Open your browser
2. Go to: `http://your-synology-ip:8000`
3. You should see the UI Toolkit dashboard
4. Click the **Settings cog** (⚙️) to configure your UniFi controller

---

## Troubleshooting

### Container won't start

**Check the logs via SSH:**
```bash
sudo docker logs unifi-toolkit
```

**Common issues:**
- Missing `.env` file: Make sure it exists at `/volume1/docker/unifi-toolkit/.env`
- Missing `ENCRYPTION_KEY`: Verify your `.env` file has a valid key
- Port conflict: Try a different port (change `8000:8000` to `8080:8000`)

### Can't access web interface

- Verify the container is running: `sudo docker ps | grep unifi-toolkit`
- Check you're using the correct port
- Check Synology firewall settings (Control Panel → Security → Firewall)

### "Permission denied" errors

Fix folder permissions:
```bash
sudo chown -R 1000:1000 /volume1/docker/unifi-toolkit/data
sudo chmod 755 /volume1/docker/unifi-toolkit/data
```

### Database errors after update

Run migrations manually:
```bash
sudo docker exec unifi-toolkit alembic upgrade head
sudo docker restart unifi-toolkit
```

### Why can't I use the Container Manager GUI to download the image?

Synology Container Manager only works with registries that fully implement the Docker Registry HTTP API v2. GitHub Container Registry (ghcr.io) has a non-standard implementation that Synology's GUI cannot handle. This is a known limitation affecting all ghcr.io images on Synology.

**References:**
- [Synology Community: Docker & Github Container Repository](https://community.synology.com/enu/forum/1/post/159445)
- [GitHub Container Registry, Proxy and Synology](https://williamdurand.fr/2023/03/18/github-container-registry-proxy-and-synology/)

---

## Configuration Reference

### Required .env Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `ENCRYPTION_KEY` | Key for encrypting credentials | (generated 44-char string) |
| `DEPLOYMENT_TYPE` | Must be `local` for Synology | `local` |

### Optional .env Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging verbosity | `INFO` |
| `STALKER_REFRESH_INTERVAL` | Device check interval (seconds) | `60` |
| `UNIFI_VERIFY_SSL` | Verify controller SSL cert | `false` |

### Complete .env Example

```
ENCRYPTION_KEY=your-44-character-key-here
DEPLOYMENT_TYPE=local
LOG_LEVEL=INFO
STALKER_REFRESH_INTERVAL=60
UNIFI_VERIFY_SSL=false
```

---

## Architecture Support

UI Toolkit publishes multi-architecture images:
- **amd64** (Intel/AMD Synology: DS920+, DS1621+, RS1221+, etc.)
- **arm64** (ARM Synology: DS223, DS220j, DS124, etc.)

The correct architecture is selected automatically when pulling.

---

## Getting Help

- **GitHub Issues**: [Report a bug or request a feature](https://github.com/Crosstalk-Solutions/unifi-toolkit/issues)
- **Discord**: [Crosstalk Solutions Discord](https://discord.com/invite/crosstalksolutions)
