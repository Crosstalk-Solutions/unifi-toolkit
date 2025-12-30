# UI Toolkit on Synology NAS

Step-by-step instructions for running UI Toolkit on Synology NAS using Container Manager.

---

## Prerequisites

- **Synology NAS** with Container Manager installed (DSM 7.2+)
  - Container Manager is the new name for Docker on Synology
  - Install from Package Center if not already installed
- **Supported architectures**: Intel (x86_64) or ARM64-based Synology models

---

## Step 1: Create Folder Structure

1. Open **File Station**
2. Navigate to the `docker` shared folder (create it if it doesn't exist)
3. Create a new folder called `unifi-toolkit`
4. Inside `unifi-toolkit`, create a subfolder called `data`

Your structure should look like:
```
/volume1/docker/unifi-toolkit/
└── data/
```

---

## Step 2: Create Configuration File

You need to create a `.env` file with your settings.

### Option A: Using File Station (easier)

1. On your computer, create a text file called `env.txt` with this content:

```
ENCRYPTION_KEY=paste-your-key-here
DEPLOYMENT_TYPE=local
LOG_LEVEL=INFO
```

2. Generate an encryption key using one of these methods:

   **On a Mac/Linux computer:**
   ```bash
   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   **On Windows (PowerShell):**
   ```powershell
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

   **No Python? Use this online generator:**
   - Go to https://fernetkeygen.com/
   - Copy the generated key

3. Paste the generated key into your `env.txt` file, replacing `paste-your-key-here`

4. Upload `env.txt` to `/volume1/docker/unifi-toolkit/`

5. Rename the file from `env.txt` to `.env`:
   - In File Station, right-click the file
   - Select **Rename**
   - Change to `.env`
   - If File Station warns about hidden files, click OK

### Option B: Using SSH

1. SSH into your Synology:
   ```bash
   ssh admin@your-synology-ip
   ```

2. Create the .env file:
   ```bash
   cd /volume1/docker/unifi-toolkit

   # Generate encryption key and create .env
   cat > .env << 'EOF'
   ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
   DEPLOYMENT_TYPE=local
   LOG_LEVEL=INFO
   EOF
   ```

   Or if Python isn't available, manually create the file with a pre-generated key.

---

## Step 3: Download the Image

1. Open **Container Manager**
2. Go to **Registry** in the left sidebar
3. In the search box at the top, search for: `ghcr.io/crosstalk-solutions/unifi-toolkit`
4. If the search doesn't find it, click **Add** → **Add From URL**
5. Enter the image URL:
   ```
   ghcr.io/crosstalk-solutions/unifi-toolkit:latest
   ```
6. Click **Add** or **Download**
7. When prompted for a tag, select `latest`
8. Wait for the download to complete (shows in the **Image** section)

---

## Step 4: Create the Container

1. Go to **Image** in Container Manager
2. Select `ghcr.io/crosstalk-solutions/unifi-toolkit`
3. Click **Run**
4. Configure the container:

### General Settings
| Setting | Value |
|---------|-------|
| Container Name | `unifi-toolkit` |
| Enable auto-restart | Yes (recommended) |

Click **Next**

### Port Settings
| Local Port | Container Port | Protocol |
|------------|----------------|----------|
| 8000 | 8000 | TCP |

> **Note:** If port 8000 is already in use, choose a different local port (e.g., 8080)

### Volume Settings

Click **Add Folder** twice to create these mappings:

| Folder/File | Mount Path | Mode |
|-------------|------------|------|
| `docker/unifi-toolkit/data` | `/app/data` | Read/Write |
| `docker/unifi-toolkit/.env` | `/app/.env` | Read-only |

> **Important:** For the `.env` file, you're mapping a *file*, not a folder. In the folder browser, navigate into `unifi-toolkit` and select the `.env` file directly.

### Environment (optional)

You can leave this empty since settings come from the `.env` file.

### Review and Run

1. Review your settings
2. Click **Done** or **Apply**
3. The container will start automatically

---

## Step 5: Access UI Toolkit

1. Open your browser
2. Go to: `http://your-synology-ip:8000`
3. You should see the UI Toolkit dashboard
4. Click the **Settings cog** (⚙️) to configure your UniFi controller

---

## Updating UI Toolkit

When a new version is released:

1. Open **Container Manager**
2. Go to **Container**
3. Select `unifi-toolkit` and click **Stop**
4. Go to **Image**
5. Select `ghcr.io/crosstalk-solutions/unifi-toolkit`
6. Click **Pull** or delete and re-download with `latest` tag
7. Go back to **Container**
8. Select `unifi-toolkit` and click **Start**

Your data and settings are preserved because they're stored in the mapped volumes.

---

## Troubleshooting

### Container won't start

**Check the logs:**
1. Go to Container Manager → Container
2. Click on `unifi-toolkit`
3. Click **Log** tab
4. Look for error messages

**Common issues:**
- Missing `.env` file: Make sure it exists and is mapped correctly
- Missing `ENCRYPTION_KEY`: Verify your `.env` file has a valid key
- Port conflict: Try a different local port

### Can't access web interface

- Verify the container is running (green status)
- Check you're using the correct port
- Try accessing from the Synology itself: `http://localhost:8000`
- Check Synology firewall settings

### "Permission denied" errors

Fix folder permissions:
1. SSH into your Synology
2. Run:
   ```bash
   sudo chown -R 1000:1000 /volume1/docker/unifi-toolkit/data
   sudo chmod 755 /volume1/docker/unifi-toolkit/data
   ```

### Database errors after update

If you see database errors after updating to a new version:

1. Stop the container
2. SSH into your Synology
3. Run the migration manually:
   ```bash
   docker exec unifi-toolkit alembic upgrade head
   ```
4. Start the container

---

## Configuration Reference

### Required .env Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `ENCRYPTION_KEY` | Fernet key for encrypting credentials | (generated 44-char string) |
| `DEPLOYMENT_TYPE` | Must be `local` for Synology | `local` |

### Optional .env Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging verbosity | `INFO` |
| `STALKER_REFRESH_INTERVAL` | Device check interval (seconds) | `60` |
| `UNIFI_VERIFY_SSL` | Verify controller SSL cert | `false` |

### Complete .env Example

```
ENCRYPTION_KEY=your-44-character-fernet-key-here
DEPLOYMENT_TYPE=local
LOG_LEVEL=INFO
STALKER_REFRESH_INTERVAL=60
UNIFI_VERIFY_SSL=false
```

---

## Architecture Notes

UI Toolkit publishes multi-architecture images that support:
- **amd64** (Intel/AMD Synology: DS920+, DS1621+, etc.)
- **arm64** (ARM Synology: DS223, DS220j, etc.)

The correct architecture is selected automatically when you download the image.

---

## Getting Help

- **GitHub Issues**: [Report a bug or request a feature](https://github.com/Crosstalk-Solutions/unifi-toolkit/issues)
- **Discord**: [Crosstalk Solutions Discord](https://discord.com/invite/crosstalksolutions)
