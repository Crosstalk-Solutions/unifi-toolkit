"""
UniFi API client — supports UniFi OS controllers (Dream Machine, Cloud Key, etc.)
"""
from typing import Optional, Dict, List
import aiohttp
import asyncio
import json
import logging

logger = logging.getLogger(__name__)

# Gateway models that support IDS/IPS
# UniFi Express (UX, UXBSDM) does NOT support IDS/IPS — but Express 7 (UX7) DOES
IDS_IPS_SUPPORTED_MODELS = {
    # Dream Machine series
    "UDM",          # UDM (base)
    "UDMPRO",       # UDM Pro
    "UDMPROMAX",    # UDM Pro Max
    "UDMPROSE",     # UDM SE (alternate code)
    "UDMSE",        # UDM SE
    "UDR",          # UDR (Dream Router)
    "UDR7",         # UDR7 (Dream Router 7)
    "UDMA67A",      # UDR7 (Dream Router 7 - actual API model code)
    "UDW",          # UDW (Dream Wall)
    # UXG series (Next-Gen Gateway)
    "UXG",          # UXG Lite (model code is just "UXG" not "UXGLITE")
    "UXGPRO",       # UXG Pro
    "UXGB",         # Gateway Max
    "UXGA6AA",      # UXG Fiber
    # UCG series (Cloud Gateway)
    "UCG",          # UCG
    "UCGMAX",       # UCG Max
    "UDMA6A8",      # UCG Fiber
    "UDRULT",       # UCG Ultra
    # UniFi Express 7 (supports IDS/IPS unlike original Express)
    "UX7",          # UniFi Express 7
    "UDMA69B",      # UniFi Express 7 (actual API model code)
    # USG series (Security Gateway - legacy)
    "USG",          # USG (base)
    "USG3P",        # USG 3P
    "UGW3",         # USG 3P (alternate code)
    "USG4P",        # USG Pro 4
    "UGW4",         # USG Pro 4 (alternate code)
    "USGP4",        # USG Pro 4 (another alternate)
    "UGWHD4",       # USG HD
    "UGWXG",        # USG XG 8
}

# UniFi Express model codes — used to detect Express devices which can be
# either a standalone gateway OR just a mesh AP. Express sometimes reports
# type 'udm' instead of 'ux', so we detect by model code too.
EXPRESS_MODEL_CODES = {'UX', 'UXBSDM', 'UX7', 'UDMA69B'}

# UniFi device model code to friendly name mapping
UNIFI_MODEL_NAMES = {
    # Gateways / Dream Machines
    "UDM": "UDM",
    "UDMPRO": "UDM Pro",
    "UDMPROMAX": "UDM Pro Max",
    "UDMPROSE": "UDM SE",
    "UDMSE": "UDM SE",
    "UDR": "UDR",
    "UDR7": "Dream Router 7",
    "UDMA67A": "Dream Router 7",
    "UDW": "UDW",
    # UXG series - Note: "UXG" is the model code for UXG Lite
    "UXG": "UXG Lite",
    "UXGPRO": "UXG Pro",
    "UXGB": "Gateway Max",
    "UXGA6AA": "UXG Fiber",
    # UCG series
    "UCG": "UCG",
    "UCGMAX": "UCG Max",
    "UDMA6A8": "UCG Fiber",
    "UDRULT": "UCG Ultra",
    # USG series (legacy)
    "USG": "USG",
    "USG3P": "USG 3P",
    "UGW3": "USG 3P",
    "USG4P": "USG Pro 4",
    "UGW4": "USG Pro 4",
    "USGP4": "USG Pro 4",
    "UGWHD4": "USG HD",
    "UGWXG": "USG XG 8",
    # UniFi Express
    "UX": "UniFi Express",
    "UXBSDM": "UniFi Express",
    "UX7": "UniFi Express 7",
    "UDMA69B": "UniFi Express 7",
    # Access Points
    "U7PROMAX": "U7 Pro Max",
    "UAPA6A4": "U7 Pro XGS",
    "U7PRO": "U7 Pro",
    "U7PIW": "U7 Pro Wall",
    "G7LR": "U7 LR",
    "U7LR": "UAP AC LR",
    "U7UKU": "UK Ultra",
    "U6PRO": "U6 Pro",
    "U6LR": "U6 LR",
    "U6LITE": "U6 Lite",
    "U6PLUS": "U6+",
    "UAPL6": "U6+",
    "U6MESH": "U6 Mesh",
    "U6ENT": "U6 Enterprise",
    "U6ENTIWP": "U6 Enterprise In-Wall",
    "UAP6MP": "U6 Mesh Pro",
    "UAPAC": "UAP AC",
    "UAPACLITE": "UAP AC Lite",
    "UAPACLR": "UAP AC LR",
    "UAPACPRO": "UAP AC Pro",
    "UAPACHD": "UAP AC HD",
    "UAPACSHD": "UAP AC SHD",
    "UAPIW": "UAP In-Wall",
    "UAPIWPRO": "UAP In-Wall Pro",
    "UAPNANOHD": "UAP nanoHD",
    "UAPFLEXHD": "UAP FlexHD",
    "UAPBEACONHD": "UAP BeaconHD",
    # Switches
    "USPM16P": "USW Pro Max 16 PoE",
    "USPM24P": "USW Pro Max 24 PoE",
    "USPM48P": "USW Pro Max 48 PoE",
    "USPPRO24": "USW Pro 24",
    "USPPRO24P": "USW Pro 24 PoE",
    "USPPRO48": "USW Pro 48",
    "USPPRO48P": "USW Pro 48 PoE",
    "USW24P250": "USW 24 PoE 250W",
    "USW24P450": "USW 24 PoE 450W",
    "USW48P750": "USW 48 PoE 750W",
    "USW48": "USW 48",
    "USW24": "USW 24",
    "USW16P150": "USW 16 PoE 150W",
    "USW8P150": "USW 8 PoE 150W",
    "USW8P60": "USW 8 PoE 60W",
    "USL8LP": "USW Lite 8 PoE",
    "USL16LP": "USW Lite 16 PoE",
    "USWED35": "USW Flex 2.5G 5",
    "USWED37": "USW Flex 2.5G 8 PoE",
    "USWED76": "USW Pro XG 8 PoE",
    "USM8P": "USW Ultra",
    "USM8P210": "USW Ultra 210W",
    "USC8P450": "USW Industrial",
    "USF5P": "USW Flex",
    "USMINI": "USW Flex Mini",
    "USPRPS": "USP RPS",
    # Building Bridge
    "UBB": "UBB",
    # Cloud Keys
    "UCK": "Cloud Key",
    "UCKG2": "Cloud Key Gen2",
    "UCKP": "Cloud Key Gen2 Plus",
}


def get_friendly_model_name(model_code: str) -> str:
    """
    Convert a UniFi model code to a friendly name

    Args:
        model_code: The internal model code (e.g., "UDMA6A8")

    Returns:
        Friendly name if known, otherwise the original code
    """
    if not model_code:
        return "Unknown"
    return UNIFI_MODEL_NAMES.get(model_code.upper(), model_code)


class UniFiClient:
    """
    Client for interacting with UniFi OS controllers.
    Supports API key or username/password authentication.
    """

    def __init__(
        self,
        host: str,
        username: str = None,
        password: str = None,
        api_key: str = None,
        site: str = "default",
        verify_ssl: bool = False,
        is_unifi_os: bool = None
    ):
        """
        Initialize UniFi client

        Args:
            host: UniFi controller URL (e.g., https://192.168.1.1)
            username: UniFi username
            password: UniFi password
            api_key: UniFi API key (preferred auth method)
            site: UniFi site ID (default: "default")
            verify_ssl: Whether to verify SSL certificates
            is_unifi_os: Deprecated — always True. Kept for backward compatibility.
        """
        self.host = host.rstrip('/')  # Remove trailing slash if present
        self.username = username
        self.password = password
        self.api_key = api_key
        self.site = site
        self.verify_ssl = verify_ssl
        self._session: Optional[aiohttp.ClientSession] = None
        self.is_unifi_os = True  # Only UniFi OS is supported
        self._v2_uses_new_payload: Optional[bool] = None  # None=unknown, True/False=cached

    async def connect(self) -> bool:
        """
        Connect to the UniFi OS controller.

        Uses API key auth if provided, otherwise username/password.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            logger.debug(f"Attempting to connect to UniFi controller at {self.host}")
            logger.debug(f"Authentication method: {'API Key' if self.api_key else 'Username/Password'}")
            logger.debug(f"Site: {self.site}, Verify SSL: {self.verify_ssl}")

            # Create aiohttp session
            # ssl=False disables all SSL verification (for self-signed certs)
            ssl_param = False if not self.verify_ssl else None
            if not self.verify_ssl:
                logger.debug("SSL verification disabled")
            connector = aiohttp.TCPConnector(ssl=ssl_param)

            # Add API key header if using UniFi OS with API key
            headers = {}
            if self.api_key:
                headers['X-API-KEY'] = self.api_key

            # Use cookie_jar to persist session cookies for UniFi OS login
            self._session = aiohttp.ClientSession(
                connector=connector,
                headers=headers,
                cookie_jar=aiohttp.CookieJar(unsafe=True)
            )

            # API key auth
            if self.api_key:
                return await self._connect_unifi_os_api_key()

            # Username/password auth
            logger.debug("Trying UniFi OS authentication...")
            unifi_os_result = await self._try_unifi_os_login()

            if unifi_os_result == "success":
                logger.info(f"Successfully connected to UniFi OS at {self.host}")
                return True
            elif unifi_os_result == "auth_failed":
                logger.error("UniFi OS authentication failed - invalid credentials")
                await self.disconnect()
                return False

            # UniFi OS endpoint not found (404)
            logger.error("Failed to connect - this does not appear to be a UniFi OS controller")
            await self.disconnect()
            return False

        except Exception as e:
            logger.error(f"Failed to connect to UniFi controller: {e}")
            logger.debug(f"Connection error details - Type: {type(e).__name__}, Args: {e.args}")
            await self.disconnect()
            return False

    async def _connect_unifi_os_api_key(self) -> bool:
        """Connect to UniFi OS using API key authentication."""
        test_url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
        try:
            async with self._session.get(test_url) as resp:
                if resp.status != 200:
                    logger.error(f"UniFi OS API key connection failed: {resp.status}")
                    await self.disconnect()
                    return False
            logger.info(f"Successfully connected to UniFi OS (API key) at {self.host}")
            return True
        except Exception as e:
            logger.error(f"UniFi OS API key connection error: {e}")
            await self.disconnect()
            return False

    async def _try_unifi_os_login(self) -> str:
        """
        Try to login via UniFi OS endpoint.

        Returns:
            "success" - Login successful
            "auth_failed" - Endpoint exists but credentials wrong
            "not_found" - Endpoint doesn't exist (not UniFi OS)
        """
        login_url = f"{self.host}/api/auth/login"
        login_payload = {
            "username": self.username,
            "password": self.password,
            "remember": True
        }

        try:
            async with self._session.post(login_url, json=login_payload) as resp:
                if resp.status == 404:
                    logger.debug("UniFi OS login endpoint not found (404)")
                    return "not_found"

                if resp.status != 200:
                    # Try to get error message
                    try:
                        error_data = await resp.json()
                        error_msg = error_data.get('errors', [error_data.get('message', 'Unknown error')])
                        logger.debug(f"UniFi OS login failed: {resp.status} - {error_msg}")
                    except:
                        logger.debug(f"UniFi OS login failed: {resp.status}")

                    # Some legacy controllers return 401 on /api/auth/login instead of 404.
                    # Verify this is actually UniFi OS by checking a UniFi OS-only endpoint.
                    if resp.status == 401:
                        is_real_unifi_os = await self._verify_unifi_os()
                        if not is_real_unifi_os:
                            logger.debug("401 from /api/auth/login but not UniFi OS — falling back to legacy")
                            return "not_found"

                    return "auth_failed"

                # Get CSRF token from response headers for future requests
                csrf_token = resp.headers.get('X-CSRF-Token')
                if csrf_token:
                    self._session.headers.update({'X-CSRF-Token': csrf_token})

            # Test the connection by getting devices
            test_url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
            async with self._session.get(test_url) as resp:
                if resp.status != 200:
                    logger.debug(f"UniFi OS API test failed after login: {resp.status}")
                    return "auth_failed"

            return "success"

        except aiohttp.ClientError as e:
            logger.debug(f"UniFi OS connection error: {e}")
            return "not_found"

    async def _verify_unifi_os(self) -> bool:
        """Check if this is actually UniFi OS by probing a UniFi OS-only endpoint."""
        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
            async with self._session.get(url) as resp:
                # UniFi OS returns 401 (needs auth) or 200; legacy returns 404
                is_unifi_os = resp.status != 404
                logger.debug(f"UniFi OS verification: /proxy/network/ returned {resp.status} → {'UniFi OS' if is_unifi_os else 'legacy'}")
                return is_unifi_os
        except aiohttp.ClientError as e:
            logger.debug(f"UniFi OS verification failed: {e}")
            return False

    async def disconnect(self):
        """
        Disconnect from the UniFi controller
        """
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def get_clients(self) -> Dict:
        """
        Get all active clients from the UniFi controller

        Returns:
            Dictionary of clients indexed by MAC address
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/sta"
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get clients: {resp.status}")
                    raise RuntimeError(f"API request failed: {resp.status}")

                data = await resp.json()
                clients_list = data.get('data', [])

                # Convert to dictionary indexed by MAC
                clients_dict = {}
                for client in clients_list:
                    mac = client.get('mac', '').lower()
                    if mac:
                        # Convert tx/rx rates from Kbps to Mbps
                        tx_rate = client.get('tx_rate')
                        rx_rate = client.get('rx_rate')
                        tx_rate_mbps = round(tx_rate / 1000, 1) if tx_rate else None
                        rx_rate_mbps = round(rx_rate / 1000, 1) if rx_rate else None

                        # Detect if wired device
                        is_wired = client.get('is_wired', False)

                        # Convert to simple dict with needed fields
                        clients_dict[mac] = {
                            'mac': mac,
                            'ap_mac': client.get('ap_mac'),
                            'ip': client.get('ip'),
                            'last_seen': client.get('last_seen'),
                            'rssi': client.get('rssi'),
                            'signal': client.get('signal'),
                            'hostname': client.get('hostname'),
                            'name': client.get('name'),
                            'oui': client.get('oui'),  # Manufacturer from UniFi
                            'tx_rate': tx_rate_mbps,
                            'rx_rate': rx_rate_mbps,
                            'channel': client.get('channel'),
                            'radio': client.get('radio'),
                            'uptime': client.get('uptime'),
                            'tx_bytes': client.get('tx_bytes'),
                            'rx_bytes': client.get('rx_bytes'),
                            'blocked': client.get('blocked', False),
                            # Wired device fields
                            'is_wired': is_wired,
                            'sw_mac': client.get('sw_mac'),
                            'sw_port': client.get('sw_port'),
                            # Network/SSID for wireless
                            'essid': client.get('essid'),
                            'network': client.get('network'),
                            'network_id': client.get('network_id')
                        }

                return clients_dict

        except Exception as e:
            logger.error(f"Failed to get clients from UniFi controller: {e}")
            raise

    async def get_client_by_mac(self, mac_address: str):
        """
        Get a specific client by MAC address

        Args:
            mac_address: MAC address to search for (normalized format)

        Returns:
            Client object/dict if found, None otherwise
        """
        clients = await self.get_clients()
        # Normalize MAC address for lookup (lowercase, colon-separated)
        normalized_mac = mac_address.lower().replace("-", ":").replace(".", ":")
        return clients.get(normalized_mac)

    async def get_access_points(self) -> Dict:
        """
        Get all access points from the UniFi controller

        Returns:
            Dictionary of access points indexed by MAC address
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get devices: {resp.status}")
                    raise RuntimeError(f"API request failed: {resp.status}")

                data = await resp.json()
                devices_list = data.get('data', [])

                # Convert to dictionary indexed by MAC, filter for APs
                aps_dict = {}
                for device in devices_list:
                    device_type = device.get('type', '')
                    model_code = device.get('model', '').upper()
                    # Include regular APs and Express devices in AP-only mode
                    is_express_ap = (
                        (device_type == 'ux' or model_code in EXPRESS_MODEL_CODES)
                        and device.get('device_mode_override') == 'mesh'
                    )
                    if device_type == 'uap' or is_express_ap:
                        mac = device.get('mac', '').lower()
                        if mac:
                            aps_dict[mac] = {
                                'mac': mac,
                                'name': device.get('name'),
                                'model': device.get('model'),
                                'type': 'uap' if is_express_ap else device_type
                            }

                return aps_dict

        except Exception as e:
            logger.error(f"Failed to get access points from UniFi controller: {e}")
            raise

    async def get_ap_name_by_mac(self, ap_mac: str) -> Optional[str]:
        """
        Get the friendly name of an access point by its MAC address.
        Also checks gateway devices with built-in radios (UDM, UDR, UDM SE).

        For devices with built-in Wi-Fi (like UDR), the ap_mac reported for
        connected clients is often a radio BSSID, not the device's primary MAC.
        This method checks both the device MAC and the vap_table BSSIDs.

        Args:
            ap_mac: AP MAC address (could be device MAC or radio BSSID)

        Returns:
            AP name if found, MAC address as fallback
        """
        try:
            normalized_mac = ap_mac.lower().replace("-", ":").replace(".", ":")

            # First check standalone APs by their device MAC
            aps = await self.get_access_points()
            ap = aps.get(normalized_mac)
            if ap:
                return ap.get('name') or get_friendly_model_name(ap.get('model', '')) or normalized_mac

            # Not found by device MAC - check all devices including their radio BSSIDs
            # This handles gateways with built-in radios (UDR, UDM, UDM SE) where
            # clients report the radio BSSID, not the device MAC
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    devices = data.get('data', [])

                    for device in devices:
                        device_mac = device.get('mac', '').lower()
                        name = device.get('name')
                        model = device.get('model', '')
                        friendly_name = name or get_friendly_model_name(model) or device_mac

                        # Check if the device MAC matches
                        if device_mac == normalized_mac:
                            return friendly_name

                        # Check vap_table for radio BSSIDs (Virtual Access Points)
                        # This is where built-in Wi-Fi radios report their BSSIDs
                        vap_table = device.get('vap_table', [])
                        for vap in vap_table:
                            # Check both 'bssid' and 'ap_mac' fields
                            vap_bssid = vap.get('bssid', '').lower()
                            vap_ap_mac = vap.get('ap_mac', '').lower()
                            if vap_bssid == normalized_mac or vap_ap_mac == normalized_mac:
                                logger.debug(
                                    f"Found BSSID {normalized_mac} on device {friendly_name} "
                                    f"(radio: {vap.get('radio', 'unknown')})"
                                )
                                return friendly_name

            return normalized_mac
        except Exception as e:
            logger.error(f"Failed to get AP name for {ap_mac}: {e}")
            return ap_mac

    async def get_switch_name_by_mac(self, sw_mac: str) -> Optional[str]:
        """
        Get the friendly name of a switch by its MAC address.

        Args:
            sw_mac: Switch MAC address

        Returns:
            Switch name if found, MAC address as fallback
        """
        try:
            normalized_mac = sw_mac.lower().replace("-", ":").replace(".", ":")

            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    devices = data.get('data', [])

                    for device in devices:
                        device_mac = device.get('mac', '').lower()
                        if device_mac == normalized_mac:
                            name = device.get('name')
                            model = device.get('model', '')
                            return name or get_friendly_model_name(model) or normalized_mac

            return normalized_mac
        except Exception as e:
            logger.error(f"Failed to get switch name for {sw_mac}: {e}")
            return sw_mac

    async def block_client(self, mac_address: str) -> bool:
        """
        Block a client device

        Args:
            mac_address: MAC address of client to block

        Returns:
            True if successful, False otherwise
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/cmd/stamgr"

            payload = {
                "cmd": "block-sta",
                "mac": mac_address.lower()
            }

            async with self._session.post(url, json=payload) as resp:
                if resp.status == 200:
                    logger.info(f"Successfully blocked client {mac_address}")
                    return True
                else:
                    logger.error(f"Failed to block client {mac_address}: {resp.status}")
                    return False

        except Exception as e:
            logger.error(f"Error blocking client {mac_address}: {e}")
            return False

    async def unblock_client(self, mac_address: str) -> bool:
        """
        Unblock a client device

        Args:
            mac_address: MAC address of client to unblock

        Returns:
            True if successful, False otherwise
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/cmd/stamgr"

            payload = {
                "cmd": "unblock-sta",
                "mac": mac_address.lower()
            }

            async with self._session.post(url, json=payload) as resp:
                if resp.status == 200:
                    logger.info(f"Successfully unblocked client {mac_address}")
                    return True
                else:
                    logger.error(f"Failed to unblock client {mac_address}: {resp.status}")
                    return False

        except Exception as e:
            logger.error(f"Error unblocking client {mac_address}: {e}")
            return False

    async def is_client_blocked(self, mac_address: str) -> bool:
        """
        Check if a client is blocked in UniFi

        Args:
            mac_address: MAC address of client to check

        Returns:
            True if blocked, False otherwise
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/rest/user"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    users = data.get('data', [])
                    user = next((u for u in users if u.get('mac', '').lower() == mac_address.lower()), None)

                    if user:
                        return user.get('blocked', False)

            return False

        except Exception as e:
            logger.error(f"Error checking blocked status for {mac_address}: {e}")
            return False

    async def set_client_name(self, mac_address: str, name: str) -> bool:
        """
        Set friendly name for a client in UniFi

        Args:
            mac_address: MAC address of client
            name: Friendly name to set

        Returns:
            True if successful, False otherwise
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/rest/user"

            # First, find the user ID for this MAC
            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    users = data.get('data', [])
                    user = next((u for u in users if u.get('mac', '').lower() == mac_address.lower()), None)

                    if user:
                        user_id = user.get('_id')
                        # Update the user's name
                        update_url = f"{url}/{user_id}"
                        payload = {"name": name}

                        async with self._session.put(update_url, json=payload) as update_resp:
                            if update_resp.status == 200:
                                logger.info(f"Successfully set name for {mac_address} to '{name}'")
                                return True
                    else:
                        # User doesn't exist yet, create it
                        payload = {
                            "mac": mac_address.lower(),
                            "name": name
                        }
                        async with self._session.post(url, json=payload) as create_resp:
                            if create_resp.status == 200:
                                logger.info(f"Successfully created user and set name for {mac_address} to '{name}'")
                                return True

            logger.error(f"Failed to set name for {mac_address}")
            return False

        except Exception as e:
            logger.error(f"Error setting name for {mac_address}: {e}")
            return False

    def _normalize_v2_event(self, event: Dict) -> Dict:
        """
        Normalize a v2 traffic-flows event to the legacy format expected by the parser.

        The v2 API (Network 10.x) returns events with nested objects (source, destination, ips)
        while the legacy API returns flat events. This normalizes v2 to look like legacy.

        Args:
            event: Raw event from v2 traffic-flows API

        Returns:
            Event dictionary in legacy format
        """
        source = event.get('source', {})
        destination = event.get('destination', {})
        ips_data = event.get('ips', {})

        # Extract IPS alert information
        signature = ips_data.get('advanced_information', '')

        # Map risk levels to severity (v2 uses "high", "medium", "low" strings)
        risk = event.get('risk', '').lower() if event.get('risk') else ''
        severity_map = {'high': 1, 'medium': 2, 'low': 3}
        severity = severity_map.get(risk, 3)

        # Determine action from the event
        action = event.get('action', 'alert')
        if action == 'allowed':
            action = 'alert'  # Detection only
        elif action in ('blocked', 'dropped', 'rejected'):
            action = 'block'

        # Build normalized event
        normalized = {
            # Use flow ID or generate unique ID from timestamp
            '_id': event.get('id') or str(event.get('time', '')),
            'flow_id': event.get('id'),
            'timestamp': event.get('time'),  # Already in milliseconds

            # Alert info from IPS data
            'inner_alert_signature': signature,
            'inner_alert_signature_id': ips_data.get('signature_id'),
            'inner_alert_severity': severity,
            'inner_alert_category': ips_data.get('category_name') or ips_data.get('ips_category') or event.get('service', ''),
            'inner_alert_action': action,
            'msg': signature,
            'catname': ips_data.get('category_name') or ips_data.get('ips_category'),

            # Network - Source
            'src_ip': source.get('ip'),
            'src_port': source.get('port'),
            'src_mac': source.get('mac'),

            # Network - Destination
            'dest_ip': destination.get('ip'),
            'dest_port': destination.get('port'),
            'dst_mac': destination.get('mac'),

            # Protocol info
            'proto': event.get('protocol'),
            'app_proto': event.get('service'),
            # v2 API returns 'in' as an object with network_id/network_name
            'in_iface': event.get('in', {}).get('network_name') if isinstance(event.get('in'), dict) else event.get('in'),

            # Geo info (v2 uses 'region' for country code, e.g. "NL")
            'src_ip_country': source.get('region') or source.get('country'),
            'dest_ip_country': destination.get('region') or destination.get('country'),

            # Site info
            'site_id': self.site,

            # Mark as v2 format for debugging/logging
            '_api_version': 'v2'
        }

        return normalized

    async def get_traffic_flows(
        self,
        timestamp_from: int = None,
        timestamp_to: int = None,
        page_size: int = 100,
        policy_types: List[str] = None,
        max_events: int = 1000
    ) -> List[Dict]:
        """
        Get traffic flows from UniFi Network 10.x v2 API.

        This is the new endpoint that replaces stat/ips/event in Network 10.x.
        Uses server-side policy_type filtering to request only IPS events.

        Args:
            timestamp_from: Start time in milliseconds (default: 24 hours ago)
            timestamp_to: End time in milliseconds (default: now)
            page_size: Events per page (default: 100)
            policy_types: Filter by policy types (default: ["INTRUSION_PREVENTION"])
            max_events: Maximum total events to return (default: 1000)

        Returns:
            List of traffic flow dictionaries normalized to legacy field names
            (e.g., src_ip_country, inner_alert_category) via _normalize_v2_event().
            The Threat Watch scheduler depends on this normalization.
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        # Default time range: last 24 hours
        import time as time_module
        now_ms = int(time_module.time() * 1000)
        if timestamp_to is None:
            timestamp_to = now_ms
        if timestamp_from is None:
            timestamp_from = now_ms - (24 * 60 * 60 * 1000)

        # Try new filtered payload first, fall back to legacy pagination
        if self._v2_uses_new_payload is not False:
            result = await self._fetch_traffic_flows_v2_filtered(
                timestamp_from, timestamp_to, page_size, policy_types, max_events
            )
            if result is not None:
                self._v2_uses_new_payload = True
                return result
            # New format rejected — cache and fall back
            self._v2_uses_new_payload = False
            logger.info("v2 filtered payload not supported, falling back to legacy pagination")

        return await self._fetch_traffic_flows_v2_legacy(
            timestamp_from, timestamp_to, page_size, max_events
        )

    async def _fetch_traffic_flows_v2_filtered(
        self,
        timestamp_from: int,
        timestamp_to: int,
        page_size: int,
        policy_types: List[str] = None,
        max_events: int = 1000
    ) -> Optional[List[Dict]]:
        """
        Fetch traffic flows using the filtered payload format (Network 10.x+).

        Server-side filtering via policy_type eliminates the need to paginate
        through all traffic flows to find IPS events.

        Returns None if the server rejects this payload format (triggers fallback).
        Returns [] if format works but no events found.

        Available filter arrays (currently only policy_type is used):
            risk, action, direction, protocol, policy, policy_type, service,
            source_host, source_mac, source_ip, source_port, source_network_id,
            source_domain, source_zone_id, source_region,
            destination_host, destination_mac, destination_ip, destination_port,
            destination_network_id, destination_domain, destination_zone_id,
            destination_region, in_network_id, out_network_id
        """
        url = f"{self.host}/proxy/network/v2/api/site/{self.site}/traffic-flows"

        try:
            all_events = []
            page_number = 0
            max_iterations = 50

            while len(all_events) < max_events and max_iterations > 0:
                max_iterations -= 1

                payload = {
                    "timestampFrom": timestamp_from,
                    "timestampTo": timestamp_to,
                    "pageNumber": page_number,
                    "pageSize": min(page_size, 100),
                    "skip_count": False,
                    "policy_type": policy_types or ["INTRUSION_PREVENTION"],
                    "risk": [],
                    "action": [],
                    "direction": [],
                    "protocol": [],
                    "policy": [],
                    "service": [],
                    "source_host": [],
                    "source_mac": [],
                    "source_ip": [],
                    "source_port": [],
                    "source_network_id": [],
                    "source_domain": [],
                    "source_zone_id": [],
                    "source_region": [],
                    "destination_host": [],
                    "destination_mac": [],
                    "destination_ip": [],
                    "destination_port": [],
                    "destination_network_id": [],
                    "destination_domain": [],
                    "destination_zone_id": [],
                    "destination_region": [],
                    "in_network_id": [],
                    "out_network_id": [],
                    "next_ai_query": [],
                    "except_for": [],
                    "search_text": ""
                }

                logger.debug(f"Fetching traffic flows (filtered) page {page_number} from: {url}")

                async with self._session.post(url, json=payload) as resp:
                    if resp.status in (400, 405, 422):
                        logger.debug(f"v2 filtered payload rejected: HTTP {resp.status}")
                        return None  # Triggers fallback
                    if resp.status != 200:
                        resp_text = await resp.text()
                        logger.error(f"Failed to get traffic flows: HTTP {resp.status}")
                        logger.debug(f"Traffic flows error response: {resp_text[:500] if resp_text else 'empty'}")
                        return []

                    data = await resp.json()
                    flows = data.get('data', [])
                    all_events.extend(flows)

                    logger.debug(f"Page {page_number}: {len(flows)} IPS events")

                    if not flows or len(flows) < payload["pageSize"]:
                        break

                    page_number += 1

            logger.info(f"Retrieved {len(all_events)} IPS events from traffic flows v2 API (filtered)")

            # Normalize v2 events to legacy format for parser compatibility
            normalized_events = [self._normalize_v2_event(e) for e in all_events]
            return normalized_events

        except Exception as e:
            logger.error(f"Failed to get traffic flows (filtered): {e}")
            return []

    async def _fetch_traffic_flows_v2_legacy(
        self,
        timestamp_from: int,
        timestamp_to: int,
        page_size: int,
        max_events: int = 1000
    ) -> List[Dict]:
        """
        Fetch traffic flows using the legacy limit/offset payload format.

        Fallback for older firmware that doesn't support the filtered format.
        Requires client-side filtering for IPS events.
        """
        url = f"{self.host}/proxy/network/v2/api/site/{self.site}/traffic-flows"

        try:
            all_events = []
            offset = 0
            max_iterations = 50

            while len(all_events) < max_events and max_iterations > 0:
                max_iterations -= 1
                batch_limit = min(100, max_events - len(all_events))

                payload = {
                    "limit": batch_limit,
                    "offset": offset,
                    "timeRange": "24h"
                }

                logger.debug(f"Fetching traffic flows (legacy) from: {url}")

                async with self._session.post(url, json=payload) as resp:
                    if resp.status == 405:
                        logger.debug("Traffic flows v2 endpoint returned 405 - not available")
                        return []
                    if resp.status != 200:
                        resp_text = await resp.text()
                        logger.error(f"Failed to get traffic flows: HTTP {resp.status}")
                        logger.debug(f"Traffic flows error response: {resp_text[:500] if resp_text else 'empty'}")
                        return []

                    data = await resp.json()
                    flows = data.get('data', [])
                    has_next = data.get('has_next', False)

                    # Client-side filter for flows with IPS data
                    ips_flows = [f for f in flows if f.get('ips')]
                    all_events.extend(ips_flows)

                    logger.debug(f"Batch: {len(flows)} flows, {len(ips_flows)} with IPS data")

                    if not has_next or not flows:
                        break

                    offset += len(flows)

            logger.info(f"Retrieved {len(all_events)} IPS events from traffic flows v2 API (legacy)")

            # Normalize v2 events to legacy format for parser compatibility
            normalized_events = [self._normalize_v2_event(e) for e in all_events]
            return normalized_events

        except Exception as e:
            logger.error(f"Failed to get traffic flows (legacy): {e}")
            return []

    async def get_ips_events(
        self,
        start: int = None,
        end: int = None,
        limit: int = 10000
    ) -> List[Dict]:
        """
        Get IDS/IPS threat events from the UniFi controller.

        For Network 10.x (UniFi OS), tries the new v2 traffic-flows API first,
        then falls back to the legacy stat/ips/event endpoint.

        Args:
            start: Start timestamp in milliseconds (default: 24 hours ago)
            end: End timestamp in milliseconds (default: now)
            limit: Maximum number of events to return (default: 10000)

        Returns:
            List of IDS/IPS event dictionaries
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        # Try the v2 traffic-flows API first (Network 10.x)
        v2_events = await self.get_traffic_flows(
            timestamp_from=start,
            timestamp_to=end,
            max_events=min(limit, 1000)
        )
        if v2_events:
            logger.info(f"Using v2 traffic-flows API - got {len(v2_events)} IPS events")
            return v2_events
        logger.debug("v2 traffic-flows returned no events, trying legacy endpoint")

        # Fall back to legacy stat/ips/event endpoint
        try:
            import time
            now_ms = int(time.time() * 1000)
            day_ago_ms = now_ms - (24 * 60 * 60 * 1000)

            payload = {
                "start": start or day_ago_ms,
                "end": end or now_ms,
                "_limit": limit
            }

            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/ips/event"

            logger.debug(f"Fetching IPS events from legacy endpoint: {url}")
            logger.debug(f"IPS events payload: {payload}")

            async with self._session.post(url, json=payload) as resp:
                if resp.status != 200:
                    resp_text = await resp.text()
                    logger.error(f"Failed to get IPS events: HTTP {resp.status}")
                    logger.debug(f"IPS events error response: {resp_text[:500] if resp_text else 'empty'}")
                    return []

                data = await resp.json()
                events = data.get('data', [])

                # Log response metadata for debugging
                meta = data.get('meta', {})
                if meta:
                    logger.debug(f"IPS events response meta: {meta}")

                logger.info(f"Retrieved {len(events)} IPS events from legacy API")

                # Log sample event structure if DEBUG and events exist
                if events and logger.isEnabledFor(logging.DEBUG):
                    sample_keys = list(events[0].keys()) if events else []
                    logger.debug(f"IPS event sample keys: {sample_keys[:15]}...")

                return events

        except Exception as e:
            logger.error(f"Failed to get IPS events from UniFi controller: {e}")
            return []

    async def get_system_info(self) -> Dict:
        """
        Get system information including gateway model, health, and stats

        Returns:
            Dictionary with system info including:
            - gateway_model: Gateway device model
            - gateway_name: Gateway friendly name
            - gateway_version: Firmware version
            - uptime: Gateway uptime in seconds
            - cpu_utilization: CPU usage percentage
            - mem_utilization: Memory usage percentage
            - wan_status: WAN connection status
            - wan_ip: WAN IP address
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            result = {
                "gateway_model": None,
                "gateway_name": None,
                "gateway_version": None,
                "uptime": None,
                "cpu_utilization": None,
                "mem_utilization": None,
                "wan_status": None,
                "wan_ip": None,
                "download_speed": None,
                "upload_speed": None,
                "latency": None,
                "is_hosted": False,
                "devices": [],
                "client_count": 0,
                "ap_count": 0,
                "switch_count": 0,
            }

            # Get all devices
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    devices = data.get('data', [])

                    # First pass: find the correct gateway device
                    # Prioritize dedicated gateways over Express (which may be in AP mode)
                    # Express in AP-only mode reports type "udm" with device_mode_override "mesh"
                    gateway_device = None
                    express_device = None
                    for device in devices:
                        device_type = device.get('type', '')
                        if device_type in ('ugw', 'udm', 'uxg', 'ux'):
                            model_code = device.get('model', '').upper()
                            is_express = device_type == 'ux' or model_code in EXPRESS_MODEL_CODES
                            if is_express:
                                # Skip Express in AP-only mode — not a gateway
                                if device.get('device_mode_override') == 'mesh':
                                    continue
                                if express_device is None:
                                    express_device = device
                            elif gateway_device is None:
                                gateway_device = device

                    # Fall back to Express if no dedicated gateway
                    if gateway_device is None:
                        gateway_device = express_device

                    for device in devices:
                        device_type = device.get('type', '')
                        model_code = device.get('model', '').upper()

                        # Express in AP-only mode reports type "udm" — count as AP
                        is_express_ap = (
                            (device_type == 'ux' or model_code in EXPRESS_MODEL_CODES)
                            and device.get('device_mode_override') == 'mesh'
                        )

                        # Count device types
                        if device_type == 'uap' or is_express_ap:
                            result['ap_count'] += 1
                        elif device_type == 'usw':
                            result['switch_count'] += 1

                        # Extract info from the selected gateway device
                        if device is gateway_device:
                            model_code = device.get('model', 'Unknown')
                            result['gateway_model'] = get_friendly_model_name(model_code)
                            result['gateway_name'] = device.get('name', result['gateway_model'])
                            result['gateway_version'] = device.get('version', 'Unknown')
                            result['uptime'] = device.get('uptime')

                            # System stats
                            system_stats = device.get('system-stats', {})
                            if system_stats:
                                cpu = system_stats.get('cpu')
                                mem = system_stats.get('mem')
                                result['cpu_utilization'] = float(cpu) if cpu else None
                                result['mem_utilization'] = float(mem) if mem else None

                            # WAN info from uplink
                            uplink = device.get('uplink', {})
                            if uplink:
                                result['wan_ip'] = uplink.get('ip')
                                result['wan_status'] = 'connected' if uplink.get('up') else 'disconnected'

                            # Speedtest results
                            speedtest = device.get('speedtest-status', {})
                            if speedtest:
                                result['download_speed'] = speedtest.get('xput_download')
                                result['upload_speed'] = speedtest.get('xput_upload')
                                result['latency'] = speedtest.get('latency')

                        # Store device summary
                        result['devices'].append({
                            'name': device.get('name', device.get('model', 'Unknown')),
                            'model': device.get('model'),
                            'type': device_type,
                            'mac': device.get('mac'),
                            'state': device.get('state', 0),
                            'uptime': device.get('uptime'),
                            'device_mode_override': device.get('device_mode_override')
                        })

            # If no gateway found, might be hosted/cloud controller
            if not result['gateway_model']:
                result['is_hosted'] = True
                result['gateway_model'] = 'Cloud Hosted'

            # Get client count
            clients = await self.get_clients()
            result['client_count'] = len(clients)

            return result

        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            raise

    async def get_health(self) -> Dict:
        """
        Get site health information

        Returns:
            Dictionary with health subsystems (wan, www, lan, wlan, vpn)
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/health"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    health_list = data.get('data', [])

                    # Convert list to dict keyed by subsystem
                    health = {}
                    for item in health_list:
                        subsystem = item.get('subsystem')
                        if subsystem:
                            health[subsystem] = {
                                'status': item.get('status', 'unknown'),
                                'num_user': item.get('num_user', 0),
                                'num_guest': item.get('num_guest', 0),
                                'num_adopted': item.get('num_adopted', 0),
                                'num_disconnected': item.get('num_disconnected', 0),
                                'num_pending': item.get('num_pending', 0),
                                'tx_bytes': item.get('tx_bytes-r', 0),
                                'rx_bytes': item.get('rx_bytes-r', 0),
                                'latency': item.get('latency') if subsystem == 'www' else None,
                            }

                            # WAN-specific fields (wan, wan2, wan3, etc.)
                            if subsystem.startswith('wan'):
                                health[subsystem]['wan_ip'] = item.get('wan_ip')
                                health[subsystem]['isp_name'] = item.get('isp_name')
                                health[subsystem]['gw_name'] = item.get('gw_name')

                                # Extract uptime stats (availability, latency)
                                uptime_stats = item.get('uptime_stats', {})
                                wan_key = subsystem.upper()
                                wan_stats = uptime_stats.get(wan_key, {})
                                health[subsystem]['availability'] = wan_stats.get('availability')
                                health[subsystem]['latency_avg'] = wan_stats.get('latency_average')

                                # Gateway system stats
                                gw_stats = item.get('gw_system-stats', {})
                                if gw_stats:
                                    health[subsystem]['uptime'] = gw_stats.get('uptime')

                            # Build a reason string for non-ok status
                            if item.get('status') != 'ok':
                                reasons = []
                                num_disconnected = item.get('num_disconnected', 0)
                                num_pending = item.get('num_pending', 0)
                                num_disabled = item.get('num_disabled', 0)

                                if num_disconnected > 0:
                                    device_type = 'APs' if subsystem == 'wlan' else 'switches' if subsystem == 'lan' else 'devices'
                                    reasons.append(f"{num_disconnected} {device_type} offline")
                                if num_pending > 0:
                                    reasons.append(f"{num_pending} pending adoption")
                                if num_disabled > 0:
                                    reasons.append(f"{num_disabled} disabled")

                                # VPN-specific: no VPN configured often shows as error
                                if subsystem == 'vpn' and not reasons:
                                    reasons.append("not configured")

                                # WAN-specific issues
                                if subsystem.startswith('wan'):
                                    if not item.get('wan_ip'):
                                        reasons.append("no IP assigned")
                                    # Check for high latency or low availability
                                    uptime_stats = item.get('uptime_stats', {})
                                    wan_key = subsystem.upper()
                                    wan_stats = uptime_stats.get(wan_key, {})
                                    availability = wan_stats.get('availability', 100)
                                    if availability < 99:
                                        reasons.append(f"{availability:.1f}% uptime")

                                health[subsystem]['status_reason'] = ', '.join(reasons) if reasons else None

                    return health
                else:
                    logger.error(f"Failed to get health: {resp.status}")
                    return {}

        except Exception as e:
            logger.error(f"Failed to get health info: {e}")
            return {}

    async def get_wan_stats(self) -> Dict:
        """
        Get WAN statistics including uptime and throughput

        Returns:
            Dictionary with WAN stats for each WAN interface
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            # Get health for basic WAN info
            health = await self.get_health()
            wan_health = health.get('wan', {})

            result = {
                'status': wan_health.get('status', 'unknown'),
                'wan_ip': wan_health.get('wan_ip'),
                'isp_name': wan_health.get('isp_name'),
                'tx_bytes_rate': wan_health.get('tx_bytes', 0),
                'rx_bytes_rate': wan_health.get('rx_bytes', 0),
            }

            return result

        except Exception as e:
            logger.error(f"Failed to get WAN stats: {e}")
            return {}

    async def has_gateway(self) -> bool:
        """
        Check if the site has a UniFi Gateway device.
        IDS/IPS features require a gateway (UDM, USG, UCG, UXG).

        Returns:
            True if a gateway device is present, False otherwise
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    devices = data.get('data', [])

                    # Check for gateway device types
                    # ux = UniFi Express, ugw = USG, udm = Dream Machine, uxg = UXG series
                    for device in devices:
                        device_type = device.get('type', '')
                        if device_type in ('ugw', 'udm', 'uxg', 'ux'):
                            # Skip Express in AP-only mode — not a gateway
                            model_code = device.get('model', '').upper()
                            is_express = device_type == 'ux' or model_code in EXPRESS_MODEL_CODES
                            if is_express and device.get('device_mode_override') == 'mesh':
                                continue
                            logger.info(f"Found gateway: {device.get('model', 'Unknown')} (type: {device_type})")
                            return True

                    logger.info("No gateway device found in devices list")
                    return False
                else:
                    logger.error(f"Failed to get devices: {resp.status}")
                    return False

        except Exception as e:
            logger.error(f"Failed to check for gateway: {e}")
            return False

    async def get_gateway_info(self) -> Dict:
        """
        Get detailed gateway information including IDS/IPS capability.

        Returns:
            Dictionary with:
            - has_gateway: True if any gateway device is present
            - gateway_model: Model code of the gateway (if present)
            - gateway_name: Friendly name of the gateway
            - supports_ids_ips: True if the gateway supports IDS/IPS
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        result = {
            "has_gateway": False,
            "gateway_model": None,
            "gateway_name": None,
            "supports_ids_ips": False
        }

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    devices = data.get('data', [])

                    # Look for gateway device types
                    # Prioritize dedicated gateways (ugw, udm, uxg) over UniFi Express (ux)
                    # because Express can be either a standalone gateway OR just a mesh AP.
                    # Note: UniFi Express sometimes reports type 'udm' instead of 'ux',
                    # so we also detect Express by model code.
                    express_device = None
                    for device in devices:
                        device_type = device.get('type', '')
                        model_code = device.get('model', '').upper()
                        is_express = device_type == 'ux' or model_code in EXPRESS_MODEL_CODES
                        if device_type in ('ugw', 'udm', 'uxg') and not is_express:
                            # Dedicated gateway — always use this
                            result["has_gateway"] = True
                            result["gateway_model"] = model_code
                            result["gateway_name"] = device.get('name') or get_friendly_model_name(model_code)
                            result["gateway_firmware"] = device.get('version')
                            result["supports_ids_ips"] = model_code in IDS_IPS_SUPPORTED_MODELS

                            logger.info(
                                f"Found gateway: {result['gateway_name']} ({model_code}, type: {device_type}), "
                                f"IDS/IPS: {result['supports_ids_ips']}"
                            )
                            return result
                        elif is_express and express_device is None:
                            # Skip Express in AP-only mode — not a gateway
                            if device.get('device_mode_override') == 'mesh':
                                continue
                            # UniFi Express — save as fallback in case no dedicated gateway exists
                            express_device = device

                    # No dedicated gateway found; use Express if present (standalone mode)
                    if express_device:
                        model_code = express_device.get('model', '').upper()
                        result["has_gateway"] = True
                        result["gateway_model"] = model_code
                        result["gateway_name"] = express_device.get('name') or get_friendly_model_name(model_code)
                        result["gateway_firmware"] = express_device.get('version')
                        result["supports_ids_ips"] = model_code in IDS_IPS_SUPPORTED_MODELS

                        logger.info(
                            f"Found Express as gateway: {result['gateway_name']} ({model_code}), "
                            f"IDS/IPS: {result['supports_ids_ips']}"
                        )
                        return result

                    logger.info("No gateway device found in devices list")
                else:
                    logger.error(f"Failed to get devices: {resp.status}")

        except Exception as e:
            logger.error(f"Failed to get gateway info: {e}")

        return result

    async def get_ips_settings(self) -> Dict:
        """
        Get IDS/IPS settings from the site configuration.

        Returns:
            Dictionary with:
            - ips_mode: Current mode ("disabled", "ids", "ips", "ipsInline")
            - ips_enabled: True if IDS or IPS is enabled
            - honeypot_enabled: True if honeypot is enabled
            - dns_filtering: True if DNS filtering is enabled
            - ad_blocking_enabled: True if ad blocking is enabled
            - error: Error message if failed to retrieve settings
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        result = {
            "ips_mode": "unknown",
            "ips_enabled": False,
            "honeypot_enabled": False,
            "dns_filtering": False,
            "ad_blocking_enabled": False,
            "error": None
        }

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/rest/setting"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    settings_list = data.get('data', [])

                    # Find the IPS settings object (key = "ips")
                    for setting in settings_list:
                        if setting.get('key') == 'ips':
                            ips_mode = setting.get('ips_mode', 'disabled')
                            result["ips_mode"] = ips_mode
                            result["ips_enabled"] = ips_mode in ('ids', 'ips', 'ipsInline')
                            result["honeypot_enabled"] = setting.get('honeypot_enabled', False)
                            result["dns_filtering"] = setting.get('dns_filtering', False)
                            result["ad_blocking_enabled"] = setting.get('ad_blocking_enabled', False)

                            logger.debug(f"IPS settings: mode={ips_mode}, enabled={result['ips_enabled']}")
                            return result

                    # No IPS settings found - might be disabled or not available
                    logger.debug("No IPS settings found in site configuration")
                    result["ips_mode"] = "disabled"
                else:
                    logger.warning(f"Failed to get site settings: {resp.status}")
                    result["error"] = f"Failed to retrieve settings (HTTP {resp.status})"

        except Exception as e:
            logger.error(f"Failed to get IPS settings: {e}")
            result["error"] = str(e)

        return result

    async def test_connection(self) -> Dict:
        """
        Test the connection to the UniFi controller

        Returns:
            Dictionary with connection status and controller info
        """
        try:
            connected = await self.connect()
            if not connected:
                return {
                    "connected": False,
                    "error": "Failed to connect to UniFi controller"
                }

            # Get controller info
            clients = await self.get_clients()
            aps = await self.get_access_points()

            return {
                "connected": True,
                "client_count": len(clients),
                "ap_count": len(aps),
                "site": self.site
            }

        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return {
                "connected": False,
                "error": str(e)
            }
        finally:
            await self.disconnect()

    async def get_site_stats(self, interval: str = "hourly", hours: int = 24) -> List[Dict]:
        """
        Get historical site bandwidth stats.

        Args:
            interval: "5minutes", "hourly", or "daily"
            hours: How many hours of data to fetch (for 5minutes/hourly) or days (for daily)

        Returns:
            List of dicts with: time, wan_tx_bytes, wan_rx_bytes, num_sta
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            import time

            # Calculate time range
            now_ms = int(time.time() * 1000)
            if interval == "daily":
                # For daily, treat hours as days
                start_ms = now_ms - (hours * 24 * 60 * 60 * 1000)
            else:
                start_ms = now_ms - (hours * 60 * 60 * 1000)

            # Build request payload with attributes that might work on different controllers
            payload = {
                "attrs": ["bytes", "wan-tx_bytes", "wan-rx_bytes", "wlan_bytes", "time", "num_sta"],
                "start": start_ms,
                "end": now_ms
            }

            # Map interval to endpoint name
            interval_map = {
                "5minutes": "5minutes",
                "hourly": "hourly",
                "daily": "daily"
            }
            endpoint_interval = interval_map.get(interval, "hourly")

            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/report/{endpoint_interval}.site"

            logger.debug(f"Requesting site stats from: {url}")
            logger.debug(f"Payload: {payload}")

            async with self._session.post(url, json=payload) as resp:
                if resp.status != 200:
                    resp_text = await resp.text()
                    logger.error(f"Failed to get site stats: {resp.status} - {resp_text}")
                    return []

                data = await resp.json()
                stats_list = data.get('data', [])
                logger.debug(f"Site stats response keys: {data.keys() if isinstance(data, dict) else 'not a dict'}")

                if stats_list:
                    logger.debug(f"First stat entry keys: {stats_list[0].keys() if stats_list else 'empty'}")
                    logger.debug(f"First stat entry: {stats_list[0] if stats_list else 'empty'}")

                # Normalize field names - handle both hyphen and underscore variants
                result = []
                for stat in stats_list:
                    result.append({
                        'time': stat.get('time'),
                        'wan_tx_bytes': stat.get('wan-tx_bytes', stat.get('wan_tx_bytes', 0)),
                        'wan_rx_bytes': stat.get('wan-rx_bytes', stat.get('wan_rx_bytes', 0)),
                        'num_sta': stat.get('num_sta', 0)
                    })

                # Filter out entries without valid time
                result = [r for r in result if r.get('time') is not None]
                logger.debug(f"Retrieved {len(result)} {interval} site stats")
                return result

        except Exception as e:
            logger.error(f"Failed to get site stats: {e}")
            return []

    async def get_hourly_bandwidth(self, hours: int = 24) -> List[Dict]:
        """
        Get WAN bandwidth for the last N hours.
        Tries 5-minute intervals first (more commonly available), falls back to hourly.

        Args:
            hours: Number of hours of data to fetch (default: 24)

        Returns:
            List of dicts with: time, wan_tx_bytes, wan_rx_bytes, num_sta
        """
        # Try 5-minute interval first (limited to 12 hours typically)
        result = await self.get_site_stats(interval="5minutes", hours=min(hours, 12))
        if result:
            return result

        # Fall back to hourly
        return await self.get_site_stats(interval="hourly", hours=hours)

    async def get_ap_details(self) -> List[Dict]:
        """
        Get detailed AP statistics including client counts.

        Returns:
            List of dicts with: mac, name, model, num_sta, channel, tx_bytes, rx_bytes, state
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get AP details: {resp.status}")
                    return []

                data = await resp.json()
                devices = data.get('data', [])

                # Filter for APs and extract relevant stats
                aps = []
                for device in devices:
                    device_type = device.get('type', '')
                    model_code = device.get('model', '')
                    # Include regular APs and Express devices in AP-only mode
                    is_express_ap = (
                        (device_type == 'ux' or model_code.upper() in EXPRESS_MODEL_CODES)
                        and device.get('device_mode_override') == 'mesh'
                    )
                    if device_type == 'uap' or is_express_ap:

                        # Get radio info for channel
                        radio_table = device.get('radio_table', [])
                        channels = []
                        for radio in radio_table:
                            channel = radio.get('channel')
                            if channel:
                                channels.append(str(channel))

                        # Get stats
                        stat = device.get('stat', {})

                        aps.append({
                            'mac': device.get('mac', '').lower(),
                            'name': device.get('name') or get_friendly_model_name(model_code),
                            'model': get_friendly_model_name(model_code),
                            'model_code': model_code,
                            'num_sta': device.get('num_sta', 0),
                            'user_num_sta': device.get('user-num_sta', 0),
                            'guest_num_sta': device.get('guest-num_sta', 0),
                            'channels': ', '.join(channels) if channels else None,
                            'tx_bytes': stat.get('tx_bytes', 0) if stat else 0,
                            'rx_bytes': stat.get('rx_bytes', 0) if stat else 0,
                            'state': device.get('state', 0),  # 1 = online, 0 = offline
                            'uptime': device.get('uptime', 0),
                            'satisfaction': device.get('satisfaction', None)
                        })

                logger.debug(f"Retrieved details for {len(aps)} APs")
                return aps

        except Exception as e:
            logger.error(f"Failed to get AP details: {e}")
            return []

    async def get_top_clients(self, limit: int = 10) -> List[Dict]:
        """
        Get top N clients by bandwidth usage.

        Args:
            limit: Maximum number of clients to return (default: 10)

        Returns:
            List of dicts sorted by total bytes (tx + rx) descending
        """
        try:
            clients = await self.get_clients()

            # Calculate total bytes and prepare list
            clients_with_totals = []
            for mac, client in clients.items():
                tx_bytes = client.get('tx_bytes', 0) or 0
                rx_bytes = client.get('rx_bytes', 0) or 0
                total_bytes = tx_bytes + rx_bytes

                # Get display name (prefer name, then hostname, then MAC)
                display_name = client.get('name') or client.get('hostname') or mac

                clients_with_totals.append({
                    'mac': mac,
                    'name': display_name,
                    'hostname': client.get('hostname'),
                    'ip': client.get('ip'),
                    'tx_bytes': tx_bytes,
                    'rx_bytes': rx_bytes,
                    'total_bytes': total_bytes,
                    'rssi': client.get('rssi'),
                    'signal': client.get('signal') or client.get('rssi'),
                    'is_wired': client.get('is_wired', False),
                    'ap_mac': client.get('ap_mac'),
                    'uptime': client.get('uptime'),
                    # Network info
                    'essid': client.get('essid'),
                    'network': client.get('network') or client.get('essid')  # Use network name or SSID
                })

            # Sort by total bytes descending and limit
            sorted_clients = sorted(
                clients_with_totals,
                key=lambda x: x['total_bytes'],
                reverse=True
            )[:limit]

            logger.debug(f"Returning top {len(sorted_clients)} clients by bandwidth")
            return sorted_clients

        except Exception as e:
            logger.error(f"Failed to get top clients: {e}")
            return []

    # ------------------------------------------------------------------
    # Zone-based firewall (House Arrest)
    #
    # These live on the v2 API. See docs/house-arrest-design.md for the
    # confirmed payload shapes and why destination matching is IP-only.
    # ------------------------------------------------------------------

    async def get_firewall_zones(self) -> List[Dict]:
        """
        Get zone-based firewall zones.

        Zone IDs are per-console — always look them up, never hardcode.

        Returns:
            List of zone dicts, or [] on failure
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        url = f"{self.host}/proxy/network/v2/api/site/{self.site}/firewall/zone"

        try:
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get firewall zones: {resp.status}")
                    return []
                data = await resp.json()
                # v2 returns a bare list, not the v1 {"data": [...]} envelope
                zones = data if isinstance(data, list) else data.get('data', [])
                logger.debug(f"Retrieved {len(zones)} firewall zones")
                return zones

        except Exception as e:
            logger.error(f"Error getting firewall zones: {e}")
            return []

    async def get_firewall_policies(self, custom_only: bool = False) -> List[Dict]:
        """
        Get zone-based firewall policies.

        Args:
            custom_only: If True, return only user-created policies
                         (predefined is False). The predefined allow-all at
                         index 2147483647 is never a policy we may touch.

        Returns:
            List of policy dicts, or [] on failure
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        url = f"{self.host}/proxy/network/v2/api/site/{self.site}/firewall-policies"

        try:
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get firewall policies: {resp.status}")
                    return []
                data = await resp.json()
                policies = data if isinstance(data, list) else data.get('data', [])
                if custom_only:
                    policies = [p for p in policies if not p.get('predefined')]
                logger.debug(f"Retrieved {len(policies)} firewall policies")
                return policies

        except Exception as e:
            logger.error(f"Error getting firewall policies: {e}")
            return []

    async def create_firewall_policy(self, policy: Dict) -> Optional[Dict]:
        """
        Create a zone-based firewall policy.

        Args:
            policy: Full policy payload (see tools/house_arrest/policies.py)

        Returns:
            The created policy dict (including its _id), or None on failure
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        url = f"{self.host}/proxy/network/v2/api/site/{self.site}/firewall-policies"

        try:
            async with self._session.post(url, json=policy) as resp:
                body = await resp.text()
                if resp.status not in (200, 201):
                    logger.error(
                        f"Failed to create firewall policy "
                        f"'{policy.get('name')}': {resp.status} {body[:300]}"
                    )
                    return None
                try:
                    created = json.loads(body) if body else {}
                except ValueError:
                    created = {}
                if isinstance(created, dict) and 'data' in created:
                    data = created['data']
                    created = data[0] if isinstance(data, list) and data else data
                logger.info(f"Created firewall policy '{policy.get('name')}'")
                return created

        except Exception as e:
            logger.error(f"Error creating firewall policy: {e}")
            return None

    async def delete_firewall_policy(self, policy_id: str) -> bool:
        """
        Delete a zone-based firewall policy by ID.

        Callers must confirm the policy is one we created (predefined False
        and carrying the House Arrest marker) before calling this.

        Args:
            policy_id: The policy's _id

        Returns:
            True if deleted, False otherwise
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        base = f"{self.host}/proxy/network/v2/api/site/{self.site}/firewall-policies"

        try:
            # Batch delete is what the console itself uses; the per-ID DELETE
            # is not consistently available across firmware versions.
            async with self._session.post(
                f"{base}/batch-delete", json=[policy_id]
            ) as resp:
                if resp.status in (200, 204):
                    logger.info(f"Deleted firewall policy {policy_id}")
                    return True
                body = await resp.text()
                logger.error(
                    f"Failed to delete firewall policy {policy_id}: "
                    f"{resp.status} {body[:300]}"
                )
                return False

        except Exception as e:
            logger.error(f"Error deleting firewall policy {policy_id}: {e}")
            return False

    async def get_known_clients(self) -> List[Dict]:
        """
        Get every client the controller knows about, online or not.

        This is the client *database* (`rest/user`), not the active list
        (`stat/sta`). House Arrest needs it because a policy targeting a
        device that is merely switched off is still valid — only a MAC that
        has left the known-client list means the rule has stopped matching.

        Note: `last_seen` on these records is unreliable (devices currently
        online can report values weeks old), so do not build timing logic on
        it. See docs/house-arrest-design.md, design decision 2.

        Returns:
            List of known-client dicts, or [] on failure
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        url = f"{self.host}/proxy/network/api/s/{self.site}/rest/user"

        try:
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get known clients: {resp.status}")
                    return []
                data = await resp.json()
                users = data.get('data', [])
                logger.debug(f"Retrieved {len(users)} known clients")
                return users

        except Exception as e:
            logger.error(f"Error getting known clients: {e}")
            return []

    async def get_blocked_flows(
        self,
        macs: List[str],
        hours: int = 24,
        page_size: int = 200,
    ) -> List[Dict]:
        """
        Get traffic the gateway BLOCKED from the given clients.

        This is what turns "a policy exists" into "here is the traffic it
        stopped". Measured 2026-09-15: the v2 traffic-flows endpoint records
        blocked flows even with `logging: false` on the policy, and each flow
        carries a `policies[]` array naming the exact policy that blocked it —
        so a flow can be attributed to a specific House Arrest rule rather
        than guessed at.

        The `action` filter is an enum accepting only 'allowed' or 'blocked'
        (lowercase); 'BLOCK'/'BLOCKED' are rejected with HTTP 400.

        Args:
            macs: source MACs to report on
            hours: how far back to look
            page_size: max flows to request

        Returns:
            List of raw flow dicts, newest first, or [] on failure
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")
        if not macs:
            return []

        import time as _time
        now_ms = int(_time.time() * 1000)
        payload = {
            "timestampFrom": now_ms - hours * 3600 * 1000,
            "timestampTo": now_ms,
            "pageNumber": 0,
            "pageSize": page_size,
            "source_mac": [m.lower() for m in macs],
            "action": ["blocked"],
        }
        url = f"{self.host}/proxy/network/v2/api/site/{self.site}/traffic-flows"

        try:
            async with self._session.post(url, json=payload) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error(
                        f"Failed to get blocked flows: {resp.status} {body[:300]}"
                    )
                    return []
                data = await resp.json()
                flows = data.get("data", data) if isinstance(data, dict) else data
                if not isinstance(flows, list):
                    return []
                logger.debug(f"Retrieved {len(flows)} blocked flows for {len(macs)} client(s)")
                return flows

        except Exception as e:
            logger.error(f"Error getting blocked flows: {e}")
            return []

    async def set_client_network(
        self, mac_address: str, network_id: Optional[str]
    ) -> bool:
        """
        Move a client into a different VLAN, or clear an existing override.

        Uses the per-client override fields `virtual_network_override_enabled`
        and `virtual_network_override_id`, which are confirmed present on
        client records (2026-09-15). Pass network_id=None to clear.

        The write is verified by re-reading the client afterwards: a PUT that
        returns 200 but doesn't take would otherwise let House Arrest report a
        quarantine it never performed.

        Args:
            mac_address: MAC of the client to move
            network_id: target network `_id`, or None to remove the override

        Returns:
            True only if the override reads back as requested
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        mac = mac_address.lower()
        base = f"{self.host}/proxy/network/api/s/{self.site}/rest/user"

        try:
            async with self._session.get(base) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to list clients: {resp.status}")
                    return False
                users = (await resp.json()).get('data', [])

            user = next((u for u in users if (u.get('mac') or '').lower() == mac), None)
            if not user:
                logger.error(f"Client {mac} is not a known client; cannot move it")
                return False

            payload = {
                "virtual_network_override_enabled": bool(network_id),
                "virtual_network_override_id": network_id or "",
            }

            async with self._session.put(
                f"{base}/{user.get('_id')}", json=payload
            ) as put_resp:
                if put_resp.status != 200:
                    body = await put_resp.text()
                    logger.error(
                        f"Failed to move {mac} to network {network_id}: "
                        f"{put_resp.status} {body[:300]}"
                    )
                    return False

            # Verify rather than trust the status code — but poll, don't read
            # once. Controller changes are provisioned asynchronously (DNS
            # records reportedly take ~45s to reach dnsmasq), so an immediate
            # read can return the pre-write state. A single read here would
            # report a false failure and roll back a lockdown that actually
            # succeeded, which is worse than waiting.
            deadline = 20.0
            waited = 0.0
            delay = 1.0
            enabled, current = None, None

            while waited <= deadline:
                async with self._session.get(base) as verify_resp:
                    if verify_resp.status != 200:
                        logger.error("Could not verify client network override")
                        return False
                    fresh = (await verify_resp.json()).get('data', [])

                moved = next(
                    (u for u in fresh if (u.get('mac') or '').lower() == mac), None
                )
                if moved:
                    enabled = bool(moved.get('virtual_network_override_enabled'))
                    current = moved.get('virtual_network_override_id') or None
                    ok = (enabled and current == network_id) if network_id else (not enabled)
                    if ok:
                        logger.info(
                            f"Client {mac} network override "
                            f"{'set to ' + network_id if network_id else 'cleared'}"
                            f" (confirmed after {waited:.0f}s)"
                        )
                        return True

                await asyncio.sleep(delay)
                waited += delay
                delay = min(delay * 1.6, 5.0)

            logger.error(
                f"Network override for {mac} did not take within {deadline:.0f}s: "
                f"enabled={enabled} id={current!r}"
            )
            return False

        except Exception as e:
            logger.error(f"Error setting client network for {mac_address}: {e}")
            return False

    async def set_network_flags(self, network_id: str, **flags) -> bool:
        """
        Change boolean settings on a network (isolation, internet access).

        These are the same switches the UniFi UI exposes on
        Settings -> Networks -> <network>. Setting `network_isolation_enabled`
        makes the controller generate its own predefined "Isolated Networks"
        BLOCK policies — measured on a live console, one per destination zone
        (Internal, Hotspot, DMZ), matching the network by subnet.

        Using the native flag rather than writing parallel policies means the
        UniFi UI and this tool always agree about whether a network is
        isolated.

        The whole object is read, modified and PUT back, because the endpoint
        expects a complete network document. The result is verified by
        re-reading, with a retry: provisioning is asynchronous.

        Args:
            network_id: the network `_id`
            **flags: field name -> bool, e.g. network_isolation_enabled=True

        Returns:
            True only if every flag reads back as requested
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")
        if not flags:
            return True

        base = f"{self.host}/proxy/network/api/s/{self.site}/rest/networkconf"

        try:
            async with self._session.get(f"{base}/{network_id}") as resp:
                if resp.status != 200:
                    logger.error(f"Failed to read network {network_id}: {resp.status}")
                    return False
                data = (await resp.json()).get('data', [])
            if not data:
                logger.error(f"Network {network_id} not found")
                return False

            doc = dict(data[0])
            doc.update(flags)

            async with self._session.put(f"{base}/{network_id}", json=doc) as put_resp:
                if put_resp.status != 200:
                    body = await put_resp.text()
                    logger.error(
                        f"Failed to update network {network_id}: "
                        f"{put_resp.status} {body[:300]}"
                    )
                    return False

            deadline, waited, delay = 20.0, 0.0, 1.0
            while waited <= deadline:
                async with self._session.get(f"{base}/{network_id}") as vr:
                    if vr.status != 200:
                        return False
                    fresh = (await vr.json()).get('data', [])
                if fresh and all(
                    bool(fresh[0].get(k)) == bool(v) for k, v in flags.items()
                ):
                    logger.info(
                        f"Network {network_id} updated: {flags} "
                        f"(confirmed after {waited:.0f}s)"
                    )
                    return True
                await asyncio.sleep(delay)
                waited += delay
                delay = min(delay * 1.6, 5.0)

            logger.error(f"Network {network_id} flags did not take: {flags}")
            return False

        except Exception as e:
            logger.error(f"Error updating network {network_id}: {e}")
            return False

    async def get_networks(self) -> List[Dict]:
        """
        Get configured networks (VLANs).

        Used for the Inspection report (network_isolation_enabled,
        mdns_enabled) and for the optional VLAN-move preset.

        Returns:
            List of network dicts, or [] on failure
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        url = f"{self.host}/proxy/network/api/s/{self.site}/rest/networkconf"

        try:
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get networks: {resp.status}")
                    return []
                data = await resp.json()
                networks = data.get('data', [])
                logger.debug(f"Retrieved {len(networks)} networks")
                return networks

        except Exception as e:
            logger.error(f"Error getting networks: {e}")
            return []

    def __del__(self):
        """
        Cleanup when object is destroyed
        """
        # Note: Can't use await in __del__, so we just close the session
        if self._session and not self._session.closed:
            # Schedule the close operation
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._session.close())
            except:
                pass
