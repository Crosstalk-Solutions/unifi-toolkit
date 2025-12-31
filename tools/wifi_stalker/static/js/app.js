/**
 * Wi-Fi Stalker - Alpine.js Dashboard Application
 */

// Base path for API calls (adjust based on where Wi-Fi Stalker is mounted)
const API_BASE_PATH = '/stalker';

function dashboard() {
    return {
        // State
        devices: [],
        history: [],
        currentDevice: null,
        lastRefresh: null,
        trackedCount: 0,
        connectedCount: 0,
        refreshInterval: 60,
        unifiClients: [],
        unifiClientSearch: '',
        selectedClients: new Set(),
        isLoadingClients: false,
        searchQuery: '',
        sortColumn: null,
        sortDirection: 'asc',

        // WebSocket connection
        ws: null,
        wsConnected: false,
        wsPingIntervalId: null,
        autoRefreshIntervalId: null,

        // Modal visibility
        showAddDevice: false,
        showWebhooks: false,
        showHistory: false,
        showGetDevices: false,
        showDeviceDetails: false,
        showAddWebhook: false,
        showEditWebhook: false,

        // Device details
        deviceDetails: null,

        // Analytics data
        dwellTimeWindow: '7d',
        dwellTimeShowHours: false,
        dwellTimeData: null,
        favoriteAP: null,
        presencePattern: null,
        dwellTimeChart: null,
        analyticsLoading: false,
        analyticsError: null,

        // Webhooks
        webhooks: [],
        webhookForm: {
            id: null,
            name: '',
            webhook_type: 'slack',
            url: '',
            event_device_connected: true,
            event_device_disconnected: true,
            event_device_roamed: true,
            event_device_blocked: true,
            event_device_unblocked: true,
            enabled: true
        },

        // Form data
        newDevice: {
            mac_address: '',
            friendly_name: '',
            site_id: 'default'
        },
        toast: {
            show: false,
            message: '',
            type: 'info'
        },

        /**
         * Initialize the dashboard
         */
        async init() {
            console.log('Initializing Wi-Fi Stalker dashboard');
            await this.loadDevices();
            await this.loadStatus();
            await this.loadWebhooks();

            // Connect to WebSocket for real-time updates
            this.connectWebSocket();

            // Auto-refresh every 60 seconds (backup to WebSocket)
            // Clear any existing interval first to prevent accumulation
            if (this.autoRefreshIntervalId) {
                clearInterval(this.autoRefreshIntervalId);
            }
            this.autoRefreshIntervalId = setInterval(() => {
                this.loadDevices();
                this.loadStatus();
            }, 60000);
        },

        /**
         * Connect to WebSocket for real-time device updates
         */
        connectWebSocket() {
            // Determine WebSocket protocol (ws:// or wss://)
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}${API_BASE_PATH}/ws`;

            console.log('Connecting to WebSocket:', wsUrl);

            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.wsConnected = true;
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                console.log('WebSocket message:', data);

                if (data.type === 'device_update') {
                    this.handleDeviceUpdate(data.device);
                } else if (data.type === 'status_update') {
                    this.handleStatusUpdate(data.status);
                } else if (data.type === 'pong') {
                    // Pong response, connection is alive
                }
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.wsConnected = false;
            };

            this.ws.onclose = () => {
                console.log('WebSocket disconnected, reconnecting in 5 seconds...');
                this.wsConnected = false;

                // Clear the ping interval when disconnected
                if (this.wsPingIntervalId) {
                    clearInterval(this.wsPingIntervalId);
                    this.wsPingIntervalId = null;
                }

                // Reconnect after 5 seconds
                setTimeout(() => {
                    this.connectWebSocket();
                }, 5000);
            };

            // Send ping every 30 seconds to keep connection alive
            // Clear any existing interval first to prevent accumulation on reconnect
            if (this.wsPingIntervalId) {
                clearInterval(this.wsPingIntervalId);
            }
            this.wsPingIntervalId = setInterval(() => {
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send('ping');
                }
            }, 30000);
        },

        /**
         * Handle device update from WebSocket
         */
        handleDeviceUpdate(deviceData) {
            console.log('Device update:', deviceData);

            // Find the device in our devices array
            const index = this.devices.findIndex(d => d.id === deviceData.id);

            if (index !== -1) {
                // Update existing device
                this.devices[index] = {
                    ...this.devices[index],
                    ...deviceData
                };

                // Show toast notification for status changes
                const device = this.devices[index];
                if (deviceData.is_connected && deviceData.is_connected !== this.devices[index].is_connected) {
                    this.showToast(`${device.friendly_name || device.mac_address} connected`, 'success');
                } else if (!deviceData.is_connected && deviceData.is_connected !== this.devices[index].is_connected) {
                    this.showToast(`${device.friendly_name || device.mac_address} disconnected`, 'info');
                }
            } else {
                // New device, add to list
                this.devices.push(deviceData);
                this.showToast(`New device: ${deviceData.friendly_name || deviceData.mac_address}`, 'info');
            }

            // Update status counts
            this.trackedCount = this.devices.length;
            this.connectedCount = this.devices.filter(d => d.is_connected).length;
        },

        /**
         * Handle status update from WebSocket
         */
        handleStatusUpdate(statusData) {
            console.log('Status update:', statusData);
            this.lastRefresh = this.formatDateTime(statusData.last_refresh);
            this.trackedCount = statusData.tracked_devices;
            this.connectedCount = statusData.connected_devices;
        },

        /**
         * Load all tracked devices
         */
        async loadDevices() {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/devices`);
                const data = await response.json();
                this.devices = data.devices;
                console.log(`Loaded ${this.devices.length} devices`);

                // Also refresh status to keep counts in sync
                await this.loadStatus();
            } catch (error) {
                console.error('Failed to load devices:', error);
                this.showToast('Failed to load devices', 'error');
            }
        },

        /**
         * Load system status
         */
        async loadStatus() {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/status`);
                const data = await response.json();
                this.lastRefresh = this.formatDateTime(data.last_refresh);
                this.trackedCount = data.tracked_devices;
                this.connectedCount = data.connected_devices;
                this.refreshInterval = data.refresh_interval_seconds || 60;
            } catch (error) {
                console.error('Failed to load status:', error);
            }
        },

        /**
         * Format MAC address as user types (auto-format to AA:BB:CC:DD:EE:FF)
         */
        formatMacAddress() {
            let mac = this.newDevice.mac_address;

            // Remove all non-hex characters
            mac = mac.replace(/[^a-fA-F0-9]/g, '');

            // Limit to 12 characters
            mac = mac.substring(0, 12);

            // Add colons every 2 characters
            let formatted = '';
            for (let i = 0; i < mac.length; i++) {
                if (i > 0 && i % 2 === 0) {
                    formatted += ':';
                }
                formatted += mac[i];
            }

            this.newDevice.mac_address = formatted.toUpperCase();
        },

        /**
         * Add a new device to track
         */
        async addDevice() {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/devices`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(this.newDevice)
                });

                if (response.ok) {
                    this.showToast('Device added successfully', 'success');
                    this.showAddDevice = false;
                    this.newDevice = {
                        mac_address: '',
                        friendly_name: '',
                        site_id: 'default'
                    };
                    await this.loadDevices();
                } else {
                    const error = await response.json();
                    this.showToast(error.detail || 'Failed to add device', 'error');
                }
            } catch (error) {
                console.error('Failed to add device:', error);
                this.showToast('Failed to add device', 'error');
            }
        },

        /**
         * Delete a device
         */
        async deleteDevice(deviceId) {
            if (!confirm('Are you sure you want to stop tracking this device?')) {
                return;
            }

            try {
                const response = await fetch(`${API_BASE_PATH}/api/devices/${deviceId}`, {
                    method: 'DELETE',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    this.showToast('Device removed', 'success');
                    await this.loadDevices();
                } else {
                    this.showToast('Failed to remove device', 'error');
                }
            } catch (error) {
                console.error('Failed to delete device:', error);
                this.showToast('Failed to remove device', 'error');
            }
        },

        /**
         * View device history
         */
        async viewHistory(deviceId) {
            try {
                // Find the device in our devices array
                this.currentDevice = this.devices.find(d => d.id === deviceId);

                const response = await fetch(`${API_BASE_PATH}/api/devices/${deviceId}/history`);
                const data = await response.json();
                this.history = data.history;
                this.showHistory = true;
            } catch (error) {
                console.error('Failed to load history:', error);
                this.showToast('Failed to load history', 'error');
            }
        },

        /**
         * Load all connected clients from UniFi
         */
        async loadUniFiClients() {
            this.isLoadingClients = true;
            this.selectedClients = new Set();
            this.unifiClientSearch = '';

            try {
                const response = await fetch(`${API_BASE_PATH}/api/devices/discover/unifi`);
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Failed to load clients');
                }

                const data = await response.json();
                this.unifiClients = data.clients;

                // Pre-select already tracked devices
                this.unifiClients.forEach(client => {
                    if (client.is_tracked) {
                        this.selectedClients.add(client.mac_address);
                    }
                });

                this.showGetDevices = true;
            } catch (error) {
                console.error('Failed to load UniFi clients:', error);
                this.showToast(error.message || 'Failed to load UniFi clients', 'error');
            } finally {
                this.isLoadingClients = false;
            }
        },

        /**
         * Toggle client selection
         */
        toggleClientSelection(macAddress) {
            if (this.selectedClients.has(macAddress)) {
                this.selectedClients.delete(macAddress);
            } else {
                this.selectedClients.add(macAddress);
            }
        },

        /**
         * Check if a client is selected
         */
        isClientSelected(macAddress) {
            return this.selectedClients.has(macAddress);
        },

        /**
         * Add selected clients to tracking (Stalk button)
         */
        async stalkSelectedDevices() {
            const selectedMacs = Array.from(this.selectedClients);
            if (selectedMacs.length === 0) {
                this.showToast('No devices selected', 'warning');
                return;
            }

            let addedCount = 0;
            let errorCount = 0;

            for (const mac of selectedMacs) {
                const client = this.unifiClients.find(c => c.mac_address === mac);
                if (!client) continue;

                // Skip if already tracked
                if (client.is_tracked) {
                    continue;
                }

                try {
                    const response = await fetch(`${API_BASE_PATH}/api/devices`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify({
                            mac_address: mac,
                            friendly_name: client.name || null,
                            site_id: 'default'
                        })
                    });

                    if (response.ok) {
                        addedCount++;
                    } else {
                        errorCount++;
                    }
                } catch (error) {
                    console.error(`Failed to add device ${mac}:`, error);
                    errorCount++;
                }
            }

            // Close modal and refresh
            this.showGetDevices = false;
            await this.loadDevices();

            // Show result
            if (addedCount > 0) {
                this.showToast(`Added ${addedCount} device(s) to tracking`, 'success');
            }
            if (errorCount > 0) {
                this.showToast(`Failed to add ${errorCount} device(s)`, 'error');
            }
        },

        /**
         * View detailed device information
         */
        async viewDeviceDetails(deviceId) {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/devices/${deviceId}/details`);
                const data = await response.json();
                this.deviceDetails = data;
                this.showDeviceDetails = true;

                // Load analytics for wireless devices
                if (!data.is_wired) {
                    // Reset analytics data and set loading state
                    this.analyticsLoading = true;
                    this.analyticsError = null;
                    this.dwellTimeData = null;
                    this.favoriteAP = null;
                    this.presencePattern = null;

                    // Destroy existing chart
                    if (this.dwellTimeChart) {
                        this.dwellTimeChart.destroy();
                        this.dwellTimeChart = null;
                    }

                    try {
                        // Load analytics data in parallel
                        await Promise.all([
                            this.loadDwellTime(deviceId),
                            this.loadFavoriteAP(deviceId),
                            this.loadPresencePattern(deviceId)
                        ]);
                    } catch (analyticsError) {
                        console.error('Failed to load analytics:', analyticsError);
                        this.analyticsError = 'Failed to load analytics data';
                    } finally {
                        this.analyticsLoading = false;
                    }
                }
            } catch (error) {
                console.error('Failed to load device details:', error);
                this.showToast('Failed to load device details', 'error');
            }
        },

        /**
         * Block device in UniFi
         */
        async blockDevice(deviceId) {
            if (!confirm('Are you sure you want to block this device? It will be disconnected from the network.')) {
                return;
            }

            try {
                const response = await fetch(`${API_BASE_PATH}/api/devices/${deviceId}/block`, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    this.showToast('Device blocked successfully', 'success');
                    this.showDeviceDetails = false;
                    await this.loadDevices();
                } else {
                    const error = await response.json();
                    this.showToast(error.detail || 'Failed to block device', 'error');
                }
            } catch (error) {
                console.error('Failed to block device:', error);
                this.showToast('Failed to block device', 'error');
            }
        },

        /**
         * Unblock device in UniFi
         */
        async unblockDevice(deviceId) {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/devices/${deviceId}/unblock`, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    this.showToast('Device unblocked successfully', 'success');
                    // Refresh device details and device list
                    await this.viewDeviceDetails(deviceId);
                    await this.loadDevices();
                } else {
                    const error = await response.json();
                    this.showToast(error.detail || 'Failed to unblock device', 'error');
                }
            } catch (error) {
                console.error('Failed to unblock device:', error);
                this.showToast('Failed to unblock device', 'error');
            }
        },

        /**
         * Update device name in UniFi
         */
        async updateUniFiName(deviceId) {
            const newName = prompt('Enter new friendly name for this device:');
            if (!newName) return;

            try {
                const response = await fetch(`${API_BASE_PATH}/api/devices/${deviceId}/unifi-name?name=${encodeURIComponent(newName)}`, {
                    method: 'PUT',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    this.showToast('Device name updated successfully', 'success');
                    // Refresh device details and main list
                    await this.viewDeviceDetails(deviceId);
                    await this.loadDevices();
                } else {
                    const error = await response.json();
                    this.showToast(error.detail || 'Failed to update device name', 'error');
                }
            } catch (error) {
                console.error('Failed to update device name:', error);
                this.showToast('Failed to update device name', 'error');
            }
        },

        /**
         * Format bytes to human readable
         */
        formatBytes(bytes) {
            if (!bytes) return '-';
            const sizes = ['B', 'KB', 'MB', 'GB'];
            if (bytes === 0) return '0 B';
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
        },

        /**
         * Get radio band name
         */
        getRadioBand(radio) {
            if (!radio) return '-';
            const bands = {
                'ng': '2.4 GHz',
                'na': '5 GHz',
                '6e': '6 GHz'
            };
            return bands[radio] || radio;
        },

        /**
         * Format datetime for display (uses browser's local timezone)
         */
        formatDateTime(datetime) {
            if (!datetime) return '-';

            const date = new Date(datetime);
            // Format: "11/30/2025, 3:45:12 PM"
            return date.toLocaleString();
        },

        /**
         * Get CSS class for signal strength
         * RSSI values: -30 (excellent) to -90 (poor)
         */
        getSignalClass(rssi) {
            if (!rssi) return '';
            if (rssi >= -50) return 'signal-excellent';
            if (rssi >= -60) return 'signal-good';
            if (rssi >= -70) return 'signal-fair';
            return 'signal-poor';
        },

        /**
         * Get filtered and sorted devices
         */
        get filteredDevices() {
            let filtered = this.devices;

            // Apply search filter
            if (this.searchQuery) {
                const query = this.searchQuery.toLowerCase();
                filtered = filtered.filter(device =>
                    (device.friendly_name && device.friendly_name.toLowerCase().includes(query)) ||
                    device.mac_address.toLowerCase().includes(query) ||
                    (device.current_ip_address && device.current_ip_address.includes(query)) ||
                    (device.current_ap_name && device.current_ap_name.toLowerCase().includes(query))
                );
            }

            // Apply sorting
            if (this.sortColumn) {
                filtered = [...filtered].sort((a, b) => {
                    let aVal = a[this.sortColumn];
                    let bVal = b[this.sortColumn];

                    // Handle null/undefined values
                    if (aVal === null || aVal === undefined) aVal = '';
                    if (bVal === null || bVal === undefined) bVal = '';

                    // String comparison
                    if (typeof aVal === 'string') {
                        aVal = aVal.toLowerCase();
                        bVal = bVal.toLowerCase();
                    }

                    if (aVal < bVal) return this.sortDirection === 'asc' ? -1 : 1;
                    if (aVal > bVal) return this.sortDirection === 'asc' ? 1 : -1;
                    return 0;
                });
            }

            return filtered;
        },

        /**
         * Get filtered UniFi clients based on search query
         */
        get filteredUnifiClients() {
            if (!this.unifiClientSearch) {
                return this.unifiClients;
            }

            const query = this.unifiClientSearch.toLowerCase();
            return this.unifiClients.filter(client =>
                (client.name && client.name.toLowerCase().includes(query)) ||
                client.mac_address.toLowerCase().includes(query) ||
                (client.ip && client.ip.includes(query))
            );
        },

        /**
         * Sort table by column
         */
        sortBy(column) {
            if (this.sortColumn === column) {
                // Toggle direction if same column
                this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                // New column, default to ascending
                this.sortColumn = column;
                this.sortDirection = 'asc';
            }
        },

        /**
         * Format duration in seconds to human readable
         */
        formatDuration(seconds) {
            if (!seconds) return '-';

            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;

            if (hours > 0) {
                return `${hours}h ${minutes}m`;
            } else if (minutes > 0) {
                return `${minutes}m ${secs}s`;
            } else {
                return `${secs}s`;
            }
        },

        /**
         * Export device history to CSV
         */
        exportHistory(deviceId) {
            // Trigger download by navigating to export endpoint
            window.location.href = `${API_BASE_PATH}/api/devices/${deviceId}/history/export`;
            this.showToast('Exporting history to CSV...', 'info');
        },

        /**
         * Show toast notification
         */
        showToast(message, type = 'info') {
            this.toast = {
                show: true,
                message: message,
                type: type
            };

            setTimeout(() => {
                this.toast.show = false;
            }, 3000);
        },

        /**
         * Check if device is an Apple iPhone or iPad
         */
        isAppleDevice(deviceName) {
            if (!deviceName) return false;
            const name = deviceName.toLowerCase();
            return name.includes('iphone') || name.includes('ipad');
        },

        /**
         * Load all configured webhooks
         */
        async loadWebhooks() {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/webhooks`);
                const data = await response.json();
                this.webhooks = data.webhooks;
                console.log(`Loaded ${this.webhooks.length} webhooks`);
            } catch (error) {
                console.error('Failed to load webhooks:', error);
            }
        },

        /**
         * Save webhook (create or update)
         */
        async saveWebhook() {
            try {
                const method = this.showEditWebhook ? 'PUT' : 'POST';
                const url = this.showEditWebhook
                    ? `${API_BASE_PATH}/api/webhooks/${this.webhookForm.id}`
                    : `${API_BASE_PATH}/api/webhooks`;

                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(this.webhookForm)
                });

                if (response.ok) {
                    this.showToast('Webhook saved successfully', 'success');
                    this.showAddWebhook = false;
                    this.showEditWebhook = false;
                    await this.loadWebhooks();
                    this.resetWebhookForm();
                } else {
                    const error = await response.json();
                    this.showToast(error.detail || 'Failed to save webhook', 'error');
                }
            } catch (error) {
                console.error('Failed to save webhook:', error);
                this.showToast('Failed to save webhook', 'error');
            }
        },

        /**
         * Edit webhook
         */
        editWebhook(webhook) {
            this.webhookForm = {
                id: webhook.id,
                name: webhook.name,
                webhook_type: webhook.webhook_type,
                url: webhook.url,
                event_device_connected: webhook.event_device_connected,
                event_device_disconnected: webhook.event_device_disconnected,
                event_device_roamed: webhook.event_device_roamed,
                event_device_blocked: webhook.event_device_blocked,
                event_device_unblocked: webhook.event_device_unblocked,
                enabled: webhook.enabled
            };
            this.showEditWebhook = true;
        },

        /**
         * Delete webhook
         */
        async deleteWebhook(webhookId) {
            if (!confirm('Are you sure you want to delete this webhook?')) {
                return;
            }

            try {
                const response = await fetch(`${API_BASE_PATH}/api/webhooks/${webhookId}`, {
                    method: 'DELETE',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    this.showToast('Webhook deleted', 'success');
                    await this.loadWebhooks();
                } else {
                    this.showToast('Failed to delete webhook', 'error');
                }
            } catch (error) {
                console.error('Failed to delete webhook:', error);
                this.showToast('Failed to delete webhook', 'error');
            }
        },

        /**
         * Test webhook
         */
        async testWebhook(webhookId) {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/webhooks/${webhookId}/test`, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    this.showToast('Test notification sent successfully!', 'success');
                } else {
                    const error = await response.json();
                    this.showToast(error.detail || 'Failed to send test notification', 'error');
                }
            } catch (error) {
                console.error('Failed to test webhook:', error);
                this.showToast('Failed to send test notification', 'error');
            }
        },

        /**
         * Reset webhook form to defaults
         */
        resetWebhookForm() {
            this.webhookForm = {
                id: null,
                name: '',
                webhook_type: 'slack',
                url: '',
                event_device_connected: true,
                event_device_disconnected: true,
                event_device_roamed: true,
                event_device_blocked: true,
                event_device_unblocked: true,
                enabled: true
            };
        },

        // ==========================================
        // Analytics Methods
        // ==========================================

        /**
         * Load dwell time data for a device
         */
        async loadDwellTime(deviceId) {
            const id = deviceId || this.deviceDetails?.id;
            if (!id) return;

            try {
                const response = await fetch(
                    `${API_BASE_PATH}/api/devices/${id}/analytics/dwell-time?window=${this.dwellTimeWindow}`
                );
                this.dwellTimeData = await response.json();

                // Wait for next tick then render chart
                setTimeout(() => this.renderDwellTimeChart(), 50);
            } catch (error) {
                console.error('Failed to load dwell time:', error);
            }
        },

        /**
         * Load favorite AP for a device
         */
        async loadFavoriteAP(deviceId) {
            const id = deviceId || this.deviceDetails?.id;
            if (!id) return;

            try {
                const response = await fetch(
                    `${API_BASE_PATH}/api/devices/${id}/analytics/favorite-ap`
                );
                this.favoriteAP = await response.json();
            } catch (error) {
                console.error('Failed to load favorite AP:', error);
            }
        },

        /**
         * Load presence pattern for a device
         */
        async loadPresencePattern(deviceId) {
            const id = deviceId || this.deviceDetails?.id;
            if (!id) return;

            try {
                const response = await fetch(
                    `${API_BASE_PATH}/api/devices/${id}/analytics/presence-pattern`
                );
                this.presencePattern = await response.json();
            } catch (error) {
                console.error('Failed to load presence pattern:', error);
            }
        },

        /**
         * Render the dwell time pie chart
         */
        renderDwellTimeChart() {
            // Destroy existing chart if any
            if (this.dwellTimeChart) {
                this.dwellTimeChart.destroy();
                this.dwellTimeChart = null;
            }

            const ctx = document.getElementById('dwellTimeChart');
            if (!ctx || !this.dwellTimeData || this.dwellTimeData.total_minutes === 0) {
                return;
            }

            const labels = Object.keys(this.dwellTimeData.ap_times);
            const data = Object.values(this.dwellTimeData.ap_times);

            // Get theme-aware colors
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const textColor = isDark ? '#e5e7eb' : '#374151';

            this.dwellTimeChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: this.getChartColors(labels.length),
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: textColor,
                                padding: 10,
                                usePointStyle: true
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: (context) => {
                                    const minutes = context.raw;
                                    const total = this.dwellTimeData.total_minutes;
                                    const pct = ((minutes / total) * 100).toFixed(1);

                                    if (this.dwellTimeShowHours) {
                                        const hours = (minutes / 60).toFixed(1);
                                        return `${context.label}: ${hours}h (${pct}%)`;
                                    }
                                    return `${context.label}: ${pct}%`;
                                }
                            }
                        }
                    }
                }
            });
        },

        /**
         * Toggle between percentage and hours display
         */
        toggleDwellTimeDisplay() {
            this.dwellTimeShowHours = !this.dwellTimeShowHours;
            this.renderDwellTimeChart();
        },

        /**
         * Get chart colors (matches Network Pulse palette)
         */
        getChartColors(count) {
            const colors = [
                '#3b82f6', // blue
                '#f97316', // orange
                '#8b5cf6', // purple
                '#22c55e', // green
                '#ef4444', // red
                '#06b6d4', // cyan
                '#f59e0b', // amber
                '#ec4899', // pink
                '#14b8a6', // teal
                '#6366f1', // indigo
                '#84cc16', // lime
                '#f43f5e'  // rose
            ];
            return colors.slice(0, count);
        },

        /**
         * Format hour for heat map labels (e.g., "12a", "3p")
         */
        formatHour(hour) {
            if (hour === 0) return '12a';
            if (hour === 12) return '12p';
            if (hour < 12) return `${hour}a`;
            return `${hour - 12}p`;
        },

        /**
         * Get CSS class for heat map cell based on value
         */
        getHeatClass(value) {
            // Value is average minutes connected (0-60 range)
            if (value >= 50) return 'heat-high';      // 50+ minutes = frequently connected
            if (value >= 30) return 'heat-medium';    // 30-50 minutes
            if (value >= 10) return 'heat-low';       // 10-30 minutes
            if (value > 0) return 'heat-rare';        // 1-10 minutes
            return 'heat-never';                       // 0 minutes
        },

        /**
         * Get tooltip text for heat map cell
         */
        getHeatTooltip(hour, day, value) {
            const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
            const hourStr = this.formatHour(hour);
            const dayStr = days[day];

            if (value === 0) {
                return `${dayStr} ${hourStr}: Rarely connected`;
            }

            const avgMinutes = value;
            if (avgMinutes >= 50) {
                return `${dayStr} ${hourStr}: Usually connected (~${avgMinutes}min avg)`;
            }
            return `${dayStr} ${hourStr}: Sometimes connected (~${avgMinutes}min avg)`;
        }
    };
}
