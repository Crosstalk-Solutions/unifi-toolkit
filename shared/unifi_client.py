"""
UniFi API client wrapper using aiounifi
"""
from typing import Optional, Dict, List
import aiohttp
from aiounifi.controller import Controller
from aiounifi.models.configuration import Configuration
from aiounifi.interfaces.clients import ClientListRequest
from aiounifi.interfaces.devices import DeviceListRequest
import ssl
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Gateway models that support IDS/IPS
# UniFi Express (UX) does NOT support IDS/IPS
IDS_IPS_SUPPORTED_MODELS = {
    "UDMPRO", "UDMPROMAX", "UDM", "UDMSE", "UDR", "UDW",
    "UXG", "UXGPRO", "UXGLITE",
    "UCG", "UCGMAX", "UDMA6A8",  # UCG Fiber
    "USG", "USG3P", "USG4P", "USGP4",
}

# UniFi device model code to friendly name mapping
UNIFI_MODEL_NAMES = {
    # Gateways / Dream Machines
    "UDMA6A8": "UCG Fiber",
    "UDMPRO": "UDM Pro",
    "UDMPROMAX": "UDM Pro Max",
    "UDM": "UDM",
    "UDMSE": "UDM SE",
    "UDR": "UDR",
    "UDW": "UDW",
    "UXG": "UXG Pro",
    "UXGPRO": "UXG Pro",
    "UXGLITE": "UXG Lite",
    "UCG": "UCG",
    "UCGMAX": "UCG Max",
    "USG": "USG",
    "USG3P": "USG 3P",
    "USG4P": "USG Pro 4",
    "USGP4": "USG Pro 4",
    "UX": "UniFi Express",
    "UXBSDM": "UniFi Express",
    # Access Points
    "U7PROMAX": "U7 Pro Max",
    "U7PRO": "U7 Pro",
    "U7PIW": "U7 Pro Wall",
    "U7LR": "U7 LR",
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
    Wrapper around aiounifi for interacting with UniFi controller
    Supports both legacy (username/password) and UniFi OS (API key or username/password) authentication
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
            host: UniFi controller URL (e.g., https://192.168.1.1:8443)
            username: UniFi username (legacy auth or UniFi OS auth)
            password: UniFi password (legacy auth or UniFi OS auth)
            api_key: UniFi API key (UniFi OS auth)
            site: UniFi site ID (default: "default")
            verify_ssl: Whether to verify SSL certificates
            is_unifi_os: Force UniFi OS mode (True for UDM/UDR/UCG/UX devices)
                         If None, auto-detects based on API key presence
        """
        self.host = host.rstrip('/')  # Remove trailing slash if present
        self.username = username
        self.password = password
        self.api_key = api_key
        self.site = site
        self.verify_ssl = verify_ssl
        self.controller: Optional[Controller] = None
        self._session: Optional[aiohttp.ClientSession] = None
        # UniFi OS mode: explicit setting, or auto-detect if API key present
        if is_unifi_os is not None:
            self.is_unifi_os = is_unifi_os
        else:
            self.is_unifi_os = api_key is not None

    async def connect(self) -> bool:
        """
        Connect to the UniFi controller

        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Create SSL context
            ssl_context = None
            if not self.verify_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            # Create aiohttp session
            connector = aiohttp.TCPConnector(ssl=ssl_context)

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

            if self.is_unifi_os:
                if self.api_key:
                    # UniFi OS with API key - test connection
                    test_url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
                    async with self._session.get(test_url) as resp:
                        if resp.status != 200:
                            logger.error(f"UniFi OS API key connection failed: {resp.status}")
                            await self.disconnect()
                            return False
                    logger.info(f"Successfully connected to UniFi OS (API key) at {self.host}")
                    return True
                else:
                    # UniFi OS with username/password - login via /api/auth/login
                    login_url = f"{self.host}/api/auth/login"
                    login_payload = {
                        "username": self.username,
                        "password": self.password,
                        "remember": True
                    }

                    async with self._session.post(login_url, json=login_payload) as resp:
                        if resp.status != 200:
                            # Try to get error message
                            try:
                                error_data = await resp.json()
                                error_msg = error_data.get('errors', [error_data.get('message', 'Unknown error')])
                                logger.error(f"UniFi OS login failed: {resp.status} - {error_msg}")
                            except:
                                logger.error(f"UniFi OS login failed: {resp.status}")
                            await self.disconnect()
                            return False

                        # Get CSRF token from response headers or cookies for future requests
                        csrf_token = resp.headers.get('X-CSRF-Token')
                        if csrf_token:
                            self._session.headers.update({'X-CSRF-Token': csrf_token})

                    # Test the connection by getting devices
                    test_url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
                    async with self._session.get(test_url) as resp:
                        if resp.status != 200:
                            logger.error(f"UniFi OS API test failed after login: {resp.status}")
                            await self.disconnect()
                            return False

                    logger.info(f"Successfully connected to UniFi OS (username/password) at {self.host}")
                    return True
            else:
                # Legacy - use aiounifi Controller with Configuration object
                # Parse host and port from URL
                parsed = urlparse(self.host)
                host = parsed.hostname or self.host
                port = parsed.port or 8443

                # Create Configuration object (aiounifi v85+ API)
                config = Configuration(
                    session=self._session,
                    host=host,
                    username=self.username,
                    password=self.password,
                    port=port,
                    site=self.site,
                    ssl_context=ssl_context if ssl_context else False
                )

                self.controller = Controller(config)

                # Login to controller
                await self.controller.login()
                logger.info(f"Successfully connected to UniFi controller at {self.host}")
                return True

        except Exception as e:
            logger.error(f"Failed to connect to UniFi controller: {e}")
            await self.disconnect()
            return False

    async def disconnect(self):
        """
        Disconnect from the UniFi controller
        """
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None
        self.controller = None

    async def get_clients(self) -> Dict:
        """
        Get all active clients from the UniFi controller

        Returns:
            Dictionary of clients indexed by MAC address
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            if self.is_unifi_os:
                # UniFi OS - make direct API call
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
                                'sw_port': client.get('sw_port')
                            }

                    return clients_dict
            else:
                # Legacy - use aiounifi Controller
                if not self.controller:
                    raise RuntimeError("Controller not initialized")

                # Fetch clients using request API
                request = ClientListRequest.create()
                response = await self.controller.request(request)

                # Parse response into dict keyed by MAC
                clients_dict = {}
                clients_list = response.get('data', []) if isinstance(response, dict) else []
                for client in clients_list:
                    mac = client.get('mac', '').lower()
                    if mac:
                        # Convert tx/rx rates from Kbps to Mbps
                        tx_rate = client.get('tx_rate')
                        rx_rate = client.get('rx_rate')
                        tx_rate_mbps = round(tx_rate / 1000, 1) if tx_rate else None
                        rx_rate_mbps = round(rx_rate / 1000, 1) if rx_rate else None

                        is_wired = client.get('is_wired', False)

                        clients_dict[mac] = {
                            'mac': mac,
                            'ap_mac': client.get('ap_mac'),
                            'ip': client.get('ip'),
                            'last_seen': client.get('last_seen'),
                            'rssi': client.get('rssi'),
                            'hostname': client.get('hostname'),
                            'name': client.get('name'),
                            'oui': client.get('oui'),
                            'tx_rate': tx_rate_mbps,
                            'rx_rate': rx_rate_mbps,
                            'channel': client.get('channel'),
                            'radio': client.get('radio'),
                            'uptime': client.get('uptime'),
                            'tx_bytes': client.get('tx_bytes'),
                            'rx_bytes': client.get('rx_bytes'),
                            'blocked': client.get('blocked', False),
                            'is_wired': is_wired,
                            'sw_mac': client.get('sw_mac'),
                            'sw_port': client.get('sw_port')
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
            if self.is_unifi_os:
                # UniFi OS - make direct API call
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
                        # Only include access points (type 'uap')
                        if device.get('type') == 'uap':
                            mac = device.get('mac', '').lower()
                            if mac:
                                aps_dict[mac] = {
                                    'mac': mac,
                                    'name': device.get('name'),
                                    'model': device.get('model'),
                                    'type': device.get('type')
                                }

                    return aps_dict
            else:
                # Legacy - use aiounifi Controller
                if not self.controller:
                    raise RuntimeError("Controller not initialized")

                # Fetch devices using request API
                request = DeviceListRequest.create()
                response = await self.controller.request(request)

                # Parse response into dict keyed by MAC, filter for APs
                aps_dict = {}
                devices_list = response.get('data', []) if isinstance(response, dict) else []
                for device in devices_list:
                    if device.get('type') == 'uap':
                        mac = device.get('mac', '').lower()
                        if mac:
                            aps_dict[mac] = {
                                'mac': mac,
                                'name': device.get('name'),
                                'model': device.get('model'),
                                'type': device.get('type')
                            }

                return aps_dict

        except Exception as e:
            logger.error(f"Failed to get access points from UniFi controller: {e}")
            raise

    async def get_ap_name_by_mac(self, ap_mac: str) -> Optional[str]:
        """
        Get the friendly name of an access point by its MAC address.
        Also checks gateway devices with built-in radios (UDM, UDR, UDM SE).

        Args:
            ap_mac: AP MAC address

        Returns:
            AP name if found, MAC address as fallback
        """
        try:
            normalized_mac = ap_mac.lower().replace("-", ":").replace(".", ":")

            # First check standalone APs
            aps = await self.get_access_points()
            ap = aps.get(normalized_mac)
            if ap:
                # Handle both dict (UniFi OS) and object (aiounifi) formats
                if isinstance(ap, dict):
                    return ap.get('name') or get_friendly_model_name(ap.get('model', '')) or normalized_mac
                else:
                    return ap.name or get_friendly_model_name(ap.model or '') or normalized_mac

            # Not found in APs - check all devices (for gateways with built-in radios like UDR, UDM, UDM SE)
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
            else:
                url = f"{self.host}/api/s/{self.site}/stat/device"

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

            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
            else:
                url = f"{self.host}/api/s/{self.site}/stat/device"

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
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/cmd/stamgr"
            else:
                url = f"{self.host}/api/s/{self.site}/cmd/stamgr"

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
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/cmd/stamgr"
            else:
                url = f"{self.host}/api/s/{self.site}/cmd/stamgr"

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
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/rest/user"
            else:
                url = f"{self.host}/api/s/{self.site}/rest/user"

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
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/rest/user"
            else:
                url = f"{self.host}/api/s/{self.site}/rest/user"

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

    async def get_ips_events(
        self,
        start: int = None,
        end: int = None,
        limit: int = 10000
    ) -> List[Dict]:
        """
        Get IDS/IPS threat events from the UniFi controller

        Args:
            start: Start timestamp in milliseconds (default: 24 hours ago)
            end: End timestamp in milliseconds (default: now)
            limit: Maximum number of events to return (default: 10000)

        Returns:
            List of IDS/IPS event dictionaries
        """
        if not self._session:
            raise RuntimeError("Not connected to UniFi controller. Call connect() first.")

        try:
            # Build request payload
            import time
            now_ms = int(time.time() * 1000)
            day_ago_ms = now_ms - (24 * 60 * 60 * 1000)

            payload = {
                "start": start or day_ago_ms,
                "end": end or now_ms,
                "_limit": limit
            }

            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/stat/ips/event"
            else:
                url = f"{self.host}/api/s/{self.site}/stat/ips/event"

            async with self._session.post(url, json=payload) as resp:
                if resp.status != 200:
                    logger.error(f"Failed to get IPS events: {resp.status}")
                    return []

                data = await resp.json()
                events = data.get('data', [])
                logger.info(f"Retrieved {len(events)} IPS events from UniFi")
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
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
            else:
                url = f"{self.host}/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    devices = data.get('data', [])

                    for device in devices:
                        device_type = device.get('type', '')

                        # Count device types
                        if device_type == 'uap':
                            result['ap_count'] += 1
                        elif device_type == 'usw':
                            result['switch_count'] += 1

                        # Find gateway (UDM, USG, UCG, UXG, UX)
                        if device_type in ('ugw', 'udm', 'uxg', 'ux'):
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
                            'uptime': device.get('uptime')
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
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/stat/health"
            else:
                url = f"{self.host}/api/s/{self.site}/stat/health"

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

                            # WAN-specific fields
                            if subsystem in ('wan', 'wan2'):
                                health[subsystem]['wan_ip'] = item.get('wan_ip')
                                health[subsystem]['isp_name'] = item.get('isp_name')
                                health[subsystem]['gw_name'] = item.get('gw_name')

                                # Extract uptime stats (availability, latency)
                                uptime_stats = item.get('uptime_stats', {})
                                wan_key = 'WAN' if subsystem == 'wan' else 'WAN2'
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
                                if subsystem in ('wan', 'wan2'):
                                    if not item.get('wan_ip'):
                                        reasons.append("no IP assigned")
                                    # Check for high latency or low availability
                                    uptime_stats = item.get('uptime_stats', {})
                                    wan_key = 'WAN' if subsystem == 'wan' else 'WAN2'
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
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
            else:
                url = f"{self.host}/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    devices = data.get('data', [])

                    # Check for gateway device types
                    # ux = UniFi Express, ugw = USG, udm = Dream Machine, uxg = UXG series
                    for device in devices:
                        device_type = device.get('type', '')
                        if device_type in ('ugw', 'udm', 'uxg', 'ux'):
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
            if self.is_unifi_os:
                url = f"{self.host}/proxy/network/api/s/{self.site}/stat/device"
            else:
                url = f"{self.host}/api/s/{self.site}/stat/device"

            async with self._session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    devices = data.get('data', [])

                    # Look for gateway device types
                    # ux = UniFi Express, ugw = USG, udm = Dream Machine, uxg = UXG series
                    for device in devices:
                        device_type = device.get('type', '')
                        if device_type in ('ugw', 'udm', 'uxg', 'ux'):
                            model_code = device.get('model', '').upper()
                            result["has_gateway"] = True
                            result["gateway_model"] = model_code
                            result["gateway_name"] = device.get('name') or get_friendly_model_name(model_code)
                            result["supports_ids_ips"] = model_code in IDS_IPS_SUPPORTED_MODELS

                            logger.info(
                                f"Found gateway: {result['gateway_name']} ({model_code}, type: {device_type}), "
                                f"IDS/IPS: {result['supports_ids_ips']}"
                            )
                            return result

                    logger.info("No gateway device found in devices list")
                else:
                    logger.error(f"Failed to get devices: {resp.status}")

        except Exception as e:
            logger.error(f"Failed to get gateway info: {e}")

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
