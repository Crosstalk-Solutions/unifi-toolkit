/**
 * Network Pulse Dashboard - Alpine.js Application
 */

const API_BASE_PATH = '/pulse';

function networkPulse() {
    return {
        // State
        data: {
            gateway: {},
            wan: {},
            devices: {},
            current_tx_rate: 0,
            current_rx_rate: 0,
            access_points: [],
            top_clients: [],
            health: {},
            last_refresh: null,
            refresh_interval: 60
        },
        isLoading: true,
        isConnected: false,
        error: null,
        theme: 'dark',
        isFullscreen: false,

        // WebSocket
        ws: null,
        wsReconnectTimer: null,
        wsPingInterval: null,

        // Charts
        bandChart: null,
        ssidChart: null,
        bandwidthChart: null,
        chartsInitialized: false,
        hideBandWired: false,
        hideSsidWired: false,

        // State
        _initialized: false,

        /**
         * Initialize the dashboard
         */
        async init() {
            // Prevent double initialization
            if (this._initialized) {
                console.log('Dashboard already initialized, skipping');
                return;
            }
            this._initialized = true;

            console.log('Initializing Network Pulse dashboard');

            // Load theme from localStorage
            this.theme = localStorage.getItem('unifi-toolkit-theme') || 'light';
            document.documentElement.setAttribute('data-theme', this.theme);

            // Load chart filter preferences from localStorage
            this.hideBandWired = localStorage.getItem('unifi-toolkit-hide-band-wired') === 'true';
            this.hideSsidWired = localStorage.getItem('unifi-toolkit-hide-ssid-wired') === 'true';

            // Listen for fullscreen changes
            document.addEventListener('fullscreenchange', () => {
                this.isFullscreen = !!document.fullscreenElement;
            });

            // Load data
            await this.loadStats();

            // Connect WebSocket for real-time updates
            this.connectWebSocket();
        },

        /**
         * Load dashboard statistics from API
         */
        async loadStats() {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/stats`);

                if (!response.ok) {
                    if (response.status === 503) {
                        this.error = 'Waiting for initial data refresh...';
                        this.isLoading = true;
                        return;
                    }
                    throw new Error(`HTTP ${response.status}`);
                }

                const data = await response.json();
                this.data = data;
                this.isConnected = true;
                this.isLoading = false;
                this.error = null;

                // Initialize charts after first data load (use setTimeout to ensure DOM is ready)
                setTimeout(() => {
                    if (!this.chartsInitialized) {
                        this.initCharts();
                    } else {
                        this.updateCharts();
                    }
                }, 100);

            } catch (e) {
                console.error('Failed to load stats:', e);
                this.error = 'Failed to load dashboard data';
                this.isConnected = false;
            }
        },

        /**
         * Connect to WebSocket for real-time updates
         */
        connectWebSocket() {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                return;
            }

            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}${API_BASE_PATH}/ws`;

            console.log('Connecting to WebSocket:', wsUrl);

            try {
                this.ws = new WebSocket(wsUrl);

                this.ws.onopen = () => {
                    console.log('WebSocket connected');
                    this.isConnected = true;

                    // Clear any reconnect timer
                    if (this.wsReconnectTimer) {
                        clearTimeout(this.wsReconnectTimer);
                        this.wsReconnectTimer = null;
                    }

                    // Start ping interval
                    this.wsPingInterval = setInterval(() => {
                        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                            this.ws.send(JSON.stringify({ type: 'ping' }));
                        }
                    }, 30000);
                };

                this.ws.onmessage = (event) => {
                    try {
                        const message = JSON.parse(event.data);

                        if (message.type === 'stats_update' && message.data) {
                            console.log('Received stats update via WebSocket');
                            this.data = message.data;
                            this.isLoading = false;
                            this.error = null;

                            // Update charts with new data
                            if (this.chartsInitialized) {
                                this.updateCharts();
                            }
                        } else if (message.type === 'pong') {
                            // Pong received, connection is alive
                        }
                    } catch (e) {
                        console.error('Failed to parse WebSocket message:', e);
                    }
                };

                this.ws.onclose = () => {
                    console.log('WebSocket disconnected');
                    this.isConnected = false;

                    // Clear ping interval
                    if (this.wsPingInterval) {
                        clearInterval(this.wsPingInterval);
                        this.wsPingInterval = null;
                    }

                    // Reconnect after delay
                    this.wsReconnectTimer = setTimeout(() => {
                        console.log('Attempting WebSocket reconnection...');
                        this.connectWebSocket();
                    }, 5000);
                };

                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                };

            } catch (e) {
                console.error('Failed to create WebSocket:', e);
                // Retry connection
                this.wsReconnectTimer = setTimeout(() => {
                    this.connectWebSocket();
                }, 5000);
            }
        },

        /**
         * Toggle dark/light theme
         */
        toggleTheme() {
            this.theme = this.theme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', this.theme);
            localStorage.setItem('unifi-toolkit-theme', this.theme);

            // Recreate charts with new theme colors
            if (this.chartsInitialized) {
                this.destroyCharts();
                this.initCharts();
            }
        },

        /**
         * Toggle fullscreen mode
         */
        toggleFullscreen() {
            if (!document.fullscreenElement) {
                document.documentElement.requestFullscreen().catch(e => {
                    console.error('Fullscreen request failed:', e);
                });
            } else {
                document.exitFullscreen();
            }
        },

        /**
         * Toggle wired clients in band chart
         */
        toggleBandWired() {
            this.hideBandWired = !this.hideBandWired;
            localStorage.setItem('unifi-toolkit-hide-band-wired', this.hideBandWired);
            // Recreate charts since Chart.js doesn't handle segment removal well
            this.destroyCharts();
            this.initCharts();
        },

        /**
         * Toggle wired clients in SSID chart
         */
        toggleSsidWired() {
            this.hideSsidWired = !this.hideSsidWired;
            localStorage.setItem('unifi-toolkit-hide-ssid-wired', this.hideSsidWired);
            // Recreate charts since Chart.js doesn't handle segment removal well
            this.destroyCharts();
            this.initCharts();
        },

        /**
         * Format bytes to human-readable string
         */
        formatBytes(bytes) {
            if (bytes === null || bytes === undefined) return '0 B';
            if (bytes === 0) return '0 B';

            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            const value = bytes / Math.pow(1024, i);

            return value.toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
        },

        /**
         * Format bandwidth rate (bytes/sec) to human-readable string
         */
        formatBandwidth(bytesPerSec) {
            if (bytesPerSec === null || bytesPerSec === undefined) return '0 bps';
            if (bytesPerSec === 0) return '0 bps';

            // Convert to bits per second
            const bitsPerSec = bytesPerSec * 8;

            const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
            const i = Math.floor(Math.log(bitsPerSec) / Math.log(1000));
            const value = bitsPerSec / Math.pow(1000, i);

            return value.toFixed(1) + ' ' + units[Math.min(i, units.length - 1)];
        },

        /**
         * Format percentage
         */
        formatPercent(value) {
            if (value === null || value === undefined) return 'N/A';
            return value.toFixed(1) + '%';
        },

        /**
         * Format timestamp to local time
         */
        formatTime(timestamp) {
            if (!timestamp) return 'Never';

            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        },

        /**
         * Get status emoji based on status string
         */
        getStatusEmoji(status) {
            switch (status) {
                case 'ok': return '🟢';
                case 'warning': return '🟡';
                case 'error': return '🔴';
                default: return '⚪';
            }
        },

        /**
         * Get theme-aware chart colors
         */
        getChartColors() {
            const isDark = this.theme === 'dark';
            return {
                // Band colors
                bands: {
                    '2.4 GHz': '#f97316',  // Orange
                    '5 GHz': '#3b82f6',    // Blue
                    '6 GHz': '#8b5cf6',    // Purple
                    'Wired': '#22c55e',    // Green
                    'Unknown': '#6b7280'   // Gray
                },
                // Text colors
                text: isDark ? '#f1f5f9' : '#1a1a2e',
                textSecondary: isDark ? '#94a3b8' : '#6b7280',
                // Grid colors
                grid: isDark ? '#334155' : '#e5e7eb',
                // Background
                background: isDark ? '#1e293b' : '#ffffff'
            };
        },

        /**
         * Generate colors for SSID chart (dynamic based on count)
         */
        generateSsidColors(count) {
            const baseColors = [
                '#3b82f6', '#f97316', '#22c55e', '#8b5cf6',
                '#ec4899', '#14b8a6', '#f59e0b', '#6366f1',
                '#84cc16', '#06b6d4', '#ef4444', '#a855f7'
            ];
            const colors = [];
            for (let i = 0; i < count; i++) {
                colors.push(baseColors[i % baseColors.length]);
            }
            return colors;
        },

        /**
         * Initialize all charts
         */
        initCharts() {
            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                console.error('Chart.js not loaded');
                return;
            }

            const colors = this.getChartColors();

            // Band Chart (Doughnut)
            const bandCtx = document.getElementById('bandChart');
            if (bandCtx && this.data.chart_data?.clients_by_band) {
                const bandData = this.data.chart_data.clients_by_band;
                const filteredBandData = this.hideBandWired
                    ? Object.fromEntries(Object.entries(bandData).filter(([key]) => key !== 'Wired'))
                    : bandData;
                const bandLabels = Object.keys(filteredBandData);
                const bandValues = Object.values(filteredBandData);
                const bandColors = bandLabels.map(label => colors.bands[label] || colors.bands['Unknown']);

                this.bandChart = new Chart(bandCtx, {
                    type: 'doughnut',
                    data: {
                        labels: bandLabels,
                        datasets: [{
                            data: bandValues,
                            backgroundColor: bandColors,
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
                                    color: colors.text,
                                    padding: 15,
                                    usePointStyle: true
                                }
                            }
                        }
                    }
                });
            }

            // SSID Chart (Doughnut)
            const ssidCtx = document.getElementById('ssidChart');
            if (ssidCtx && this.data.chart_data?.clients_by_ssid) {
                const ssidData = this.data.chart_data.clients_by_ssid;
                const filteredSsidData = this.hideSsidWired
                    ? Object.fromEntries(Object.entries(ssidData).filter(([key]) => key !== 'Wired'))
                    : ssidData;
                const ssidLabels = Object.keys(filteredSsidData);
                const ssidValues = Object.values(filteredSsidData);
                const ssidColors = this.generateSsidColors(ssidLabels.length);

                this.ssidChart = new Chart(ssidCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ssidLabels,
                        datasets: [{
                            data: ssidValues,
                            backgroundColor: ssidColors,
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
                                    color: colors.text,
                                    padding: 15,
                                    usePointStyle: true
                                }
                            }
                        }
                    }
                });
            }

            // Bandwidth Chart (Horizontal Bar)
            const bwCtx = document.getElementById('bandwidthChart');
            if (bwCtx && this.data.top_clients?.length > 0) {
                const topClients = this.data.top_clients.slice(0, 5);
                const clientNames = topClients.map(c => c.name || c.hostname || 'Unknown');
                const clientBandwidth = topClients.map(c => c.total_bytes);

                this.bandwidthChart = new Chart(bwCtx, {
                    type: 'bar',
                    data: {
                        labels: clientNames,
                        datasets: [{
                            data: clientBandwidth,
                            backgroundColor: '#F15A29',
                            borderRadius: 4
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                callbacks: {
                                    label: (context) => {
                                        return this.formatBytes(context.raw);
                                    }
                                }
                            }
                        },
                        scales: {
                            x: {
                                ticks: {
                                    color: colors.textSecondary,
                                    callback: (value) => this.formatBytes(value)
                                },
                                grid: {
                                    color: colors.grid
                                }
                            },
                            y: {
                                ticks: {
                                    color: colors.text
                                },
                                grid: {
                                    display: false
                                }
                            }
                        }
                    }
                });
            }

            this.chartsInitialized = true;
            console.log('Charts initialized');
        },

        /**
         * Update chart data without recreating
         */
        updateCharts() {
            // Update Band Chart
            if (this.bandChart && this.data.chart_data?.clients_by_band) {
                const bandData = this.data.chart_data.clients_by_band;
                const filteredBandData = this.hideBandWired
                    ? Object.fromEntries(Object.entries(bandData).filter(([key]) => key !== 'Wired'))
                    : bandData;
                const colors = this.getChartColors();
                const bandLabels = Object.keys(filteredBandData);
                const bandValues = Object.values(filteredBandData);
                const bandColors = bandLabels.map(label => colors.bands[label] || colors.bands['Unknown']);

                this.bandChart.data.labels = bandLabels;
                this.bandChart.data.datasets[0].data = bandValues;
                this.bandChart.data.datasets[0].backgroundColor = bandColors;
                this.bandChart.update('none');
            }

            // Update SSID Chart
            if (this.ssidChart && this.data.chart_data?.clients_by_ssid) {
                const ssidData = this.data.chart_data.clients_by_ssid;
                const filteredSsidData = this.hideSsidWired
                    ? Object.fromEntries(Object.entries(ssidData).filter(([key]) => key !== 'Wired'))
                    : ssidData;
                const ssidLabels = Object.keys(filteredSsidData);
                const ssidValues = Object.values(filteredSsidData);
                const ssidColors = this.generateSsidColors(ssidLabels.length);

                this.ssidChart.data.labels = ssidLabels;
                this.ssidChart.data.datasets[0].data = ssidValues;
                this.ssidChart.data.datasets[0].backgroundColor = ssidColors;
                this.ssidChart.update('none');
            }

            // Update Bandwidth Chart
            if (this.bandwidthChart && this.data.top_clients?.length > 0) {
                const topClients = this.data.top_clients.slice(0, 5);
                const clientNames = topClients.map(c => c.name || c.hostname || 'Unknown');
                const clientBandwidth = topClients.map(c => c.total_bytes);

                this.bandwidthChart.data.labels = clientNames;
                this.bandwidthChart.data.datasets[0].data = clientBandwidth;
                this.bandwidthChart.update('none');
            }
        },

        /**
         * Destroy all chart instances
         */
        destroyCharts() {
            if (this.bandChart) {
                this.bandChart.destroy();
                this.bandChart = null;
            }
            if (this.ssidChart) {
                this.ssidChart.destroy();
                this.ssidChart = null;
            }
            if (this.bandwidthChart) {
                this.bandwidthChart.destroy();
                this.bandwidthChart = null;
            }
            this.chartsInitialized = false;
        }
    };
}
