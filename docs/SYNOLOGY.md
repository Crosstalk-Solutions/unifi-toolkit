# UI Toolkit on Synology NAS

Step-by-step instructions for running UI Toolkit on Synology NAS using Container Manager.

## Quick Start (Recommended)

The easiest way to install UI Toolkit on Synology:

1. Create folders: `docker/unifi-toolkit/data/` and a `.env` file (see [Step 1](#step-1-create-folder-structure) and [Step 2](#step-2-create-configuration-file))
2. Set permissions: `sudo chown -R 1000:1000 /volume1/docker/unifi-toolkit/data`
3. In Container Manager → **Registry** → search `crosstalksolutions/unifi-toolkit` → **Download**
4. In **Image** → select the image → **Run** → configure ports and volumes → **Done**

Full details in [Method A: Container Manager GUI](#method-a-container-manager-gui-recommended) below.

---

## Prerequisites

- **Synology NAS** with Container Manager installed (DSM 7.2+)
- **SSH access** (only required for Methods B & C, not for Method A)
- **Supported architectures**: Intel (x86_64) or ARM64-based Synology models

### Enable SSH on Synology (Methods B & C only)

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

| Method | Best For | Difficulty |
|--------|----------|------------|
| [Method A: Container Manager GUI](#method-a-container-manager-gui-recommended) | Easiest, full GUI support, update notifications | Easiest |
| [Method B: SSH Commands](#method-b-ssh-commands) | Quick setup, familiar with terminal | Easy |
| [Method C: Container Manager Project](#method-c-container-manager-project) | Docker-compose management | Moderate |

---

## Method A: Container Manager GUI (Recommended)

The easiest method - no SSH required for installation, and you get update notifications.

### Step A1: Download the Image

1. Open **Container Manager**
2. Go to **Registry** in the left sidebar
3. Search for: `crosstalksolutions/unifi-toolkit`
4. Select the image and click **Download**
5. Choose tag: `latest`
6. Wait for download to complete (check **Image** section)

### Step A2: Create the Container

1. Go to **Image** in Container Manager
2. Select `crosstalksolutions/unifi-toolkit`
3. Click **Run**

**General Settings:**
| Setting | Value |
|---------|-------|
| Container Name | `unifi-toolkit` |
| Enable auto-restart | Yes |

Click **Next**

**Port Settings:**
| Local Port | Container Port | Protocol |
|------------|----------------|----------|
| 8000 | 8000 | TCP |

**Volume Settings** - Add these two mappings:
| Folder/File | Mount Path | Mode |
|-------------|------------|------|
| `docker/unifi-toolkit/data` | `/app/data` | Read/Write |
| `docker/unifi-toolkit/.env` | `/app/.env` | Read-only |

Click **Next**, review settings, click **Done**.

### Updating (Method A)

Container Manager will show "Update available" when a new version is released:

1. Go to **Image** in Container Manager
2. You'll see an update indicator on `crosstalksolutions/unifi-toolkit`
3. Click the image, click **Update**
4. Go to **Container**, select `unifi-toolkit`
5. Click **Action** → **Stop**
6. Click **Action** → **Reset** (this recreates with new image)
7. Click **Action** → **Start**

---

## Method B: SSH Commands

This method pulls the image via SSH and then lets you manage it in Container Manager.

### Step B1: SSH into your Synology

```bash
ssh your-admin-user@your-synology-ip
```

### Step B2: Pull the image

```bash
sudo docker pull crosstalksolutions/unifi-toolkit:latest
```

### Step B3: Create and start the container

```bash
sudo docker run -d \
  --name unifi-toolkit \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /volume1/docker/unifi-toolkit/data:/app/data \
  -v /volume1/docker/unifi-toolkit/.env:/app/.env:ro \
  crosstalksolutions/unifi-toolkit:latest
```

### Step B4: Verify it's running

```bash
sudo docker ps | grep unifi-toolkit
```

You should see the container running. It will also appear in Container Manager's GUI.

### Updating (Method B)

```bash
ssh your-admin-user@your-synology-ip
sudo docker pull crosstalksolutions/unifi-toolkit:latest
sudo docker stop unifi-toolkit && sudo docker rm unifi-toolkit
sudo docker run -d \
  --name unifi-toolkit \
  --restart unless-stopped \
  -p 8000:8000 \
  -v /volume1/docker/unifi-toolkit/data:/app/data \
  -v /volume1/docker/unifi-toolkit/.env:/app/.env:ro \
  crosstalksolutions/unifi-toolkit:latest
```

---

## Method C: Container Manager Project

This method uses docker-compose via Container Manager's "Project" feature.

### Step C1: Create docker-compose.yml

Create a file called `docker-compose.yml` in `/volume1/docker/unifi-toolkit/` with this content:

```yaml
services:
  unifi-toolkit:
    image: crosstalksolutions/unifi-toolkit:latest
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
      image: crosstalksolutions/unifi-toolkit:latest
      container_name: unifi-toolkit
      restart: unless-stopped
      ports:
        - "8000:8000"
      volumes:
        - ./data:/app/data
        - ./.env:/app/.env:ro
  EOF
  ```

### Step C2: Create the Project in Container Manager

1. Open **Container Manager**
2. Go to **Project** in the left sidebar
3. Click **Create**
4. Configure:
   - **Project name**: `unifi-toolkit`
   - **Path**: Click **Set path** and select `/docker/unifi-toolkit`
   - **Source**: Select "Use existing docker-compose.yml"
5. Click **Next**, review the settings
6. Click **Done** to create and start the project

### Updating (Method C)

1. In Container Manager → Project → select `unifi-toolkit`
2. Click **Action** → **Stop**
3. Click **Action** → **Pull** (downloads latest image)
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

### Why are there multiple installation methods?

UI Toolkit is published to both Docker Hub and GitHub Container Registry:

- **Docker Hub** (`crosstalksolutions/unifi-toolkit`) - Full Synology GUI support
- **ghcr.io** (`ghcr.io/crosstalk-solutions/unifi-toolkit`) - Alternative registry

We recommend Docker Hub (Method A) for Synology users because it provides the best GUI experience with update notifications.

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

### Complete .env Example

```
ENCRYPTION_KEY=your-44-character-key-here
DEPLOYMENT_TYPE=local
LOG_LEVEL=INFO
STALKER_REFRESH_INTERVAL=60
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
