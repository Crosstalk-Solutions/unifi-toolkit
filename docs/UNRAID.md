# UI Toolkit on Unraid

Step-by-step instructions for running UI Toolkit on Unraid using Community Apps Manager.

---

## Quick Start (Recommended)

The easiest way to install UI Toolkit on Unraid:

1. **Search & Install**: Go to Community Apps Manager, search for `unifi-toolkit`, and click **Install**.
2. **Set Encryption Key**: You can generate a secure key by running this command in the Unraid terminal:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
3. **Apply**: Paste the key into the template and click **Apply**.
4. **Permissions**: If you receive a permission error, set permissions and restart the app:
   `chmod -R 777 /mnt/user/appdata/unifi-toolkit`
5. **Access the Application**: Open your browser to `http://<UNRAID-IP>:8000`
6. **Configure UniFi API Access**: Follow the setup wizard to link your controller.

---

## First-Time Setup

1. Open UI Toolkit in browser
2. Click the **Settings cog (⚙️)** in the dashboard header
3. Enter UniFi controller details
4. Click **Test Connection**
5. Save configuration
6. Start using tools (Wi-Fi Stalker, Threat Watch, Network Pulse)

---

### Custom Port
If port `8000` is already in use on your Unraid server, change the **Host Port** in the Docker settings to an available port (e.g., `8085`).

---

## 🛠 Troubleshooting

* **Logs**: If the app doesn't load, check the container logs in the Docker tab for specific error messages.
* **Database Fix**: If the database is locked or inaccessible, ensure the path `/mnt/user/appdata/unifi-toolkit` has the correct permissions (see step 4 above).

---
*Created for the Unraid Community - UI Toolkit Integration*