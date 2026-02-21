/**
 * Network Pulse AP Detail Page - Alpine.js Application
 */

const API_BASE_PATH = '/pulse';

function apDetail() {
    return {
        // State
        apMac: '',
        ap: null,
        clients: [],
        clientsByBand: {},
        isLoading: true,
        error: null,
        theme: 'auto',

        // Chart instance
        bandChart: null,

        /**
         * Resolve theme preference (auto -> light/dark based on OS)
         */
        getResolvedTheme(preference) {
            if (preference === 'dark') return 'dark';
            if (preference === 'light') return 'light';
            return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        },

        /**
         * Initialize the AP detail page
         */
        async init() {
            console.log('Initializing AP Detail page');

            // Extract AP MAC from URL path
            const path = window.location.pathname;
            const match = path.match(/\/pulse\/ap\/(.+)$/);
            if (match) {
                this.apMac = decodeURIComponent(match[1]);
            } else {
                this.error = 'Invalid AP URL';
                this.isLoading = false;
                return;
            }

            // Load theme from localStorage (resolve 'auto' to light/dark for display)
            const preference = localStorage.getItem('unifi-toolkit-theme') || 'auto';
            this.theme = this.getResolvedTheme(preference);
            document.documentElement.setAttribute('data-theme', this.theme);

            // Load data
            await this.loadData();
        },

        /**
         * Load AP details from API
         */
        async loadData() {
            try {
                const response = await fetch(`${API_BASE_PATH}/api/stats/ap/${encodeURIComponent(this.apMac)}`);

                if (!response.ok) {
                    if (response.status === 404) {
                        this.error = 'AP not found';
                    } else if (response.status === 503) {
                        this.error = 'Waiting for data refresh...';
                    } else {
                        this.error = `Error loading AP details: ${response.status}`;
                    }
                    this.isLoading = false;
                    return;
                }

                const data = await response.json();
                this.ap = data.ap_info;
                this.clients = data.clients || [];
                this.clientsByBand = data.clients_by_band || {};

                this.isLoading = false;
                this.error = null;

                // Initialize chart after data loads
                this.$nextTick(() => {
                    this.initChart();
                });

            } catch (e) {
                console.error('Failed to load AP details:', e);
                this.error = 'Failed to load AP details';
                this.isLoading = false;
            }
        },

        /**
         * Get chart colors based on theme
         */
        getChartColors() {
            const isDark = this.theme === 'dark';
            return {
                bands: {
                    '2.4 GHz': '#f97316',  // Orange
                    '5 GHz': '#3b82f6',    // Blue
                    '6 GHz': '#8b5cf6',    // Purple
                    'Wired': '#22c55e',    // Green
                    'Unknown': '#6b7280'   // Gray
                },
                text: isDark ? '#f1f5f9' : '#1a1a2e'
            };
        },

        /**
         * Initialize the band distribution chart
         */
        initChart() {
            const ctx = document.getElementById('apBandChart');
            if (!ctx || Object.keys(this.clientsByBand).length === 0) {
                return;
            }

            const colors = this.getChartColors();
            const labels = Object.keys(this.clientsByBand);
            const values = Object.values(this.clientsByBand);
            const backgroundColors = labels.map(label => colors.bands[label] || colors.bands['Unknown']);

            this.bandChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: backgroundColors,
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
        },

        /**
         * Format uptime from seconds to readable string
         */
        formatUptime(seconds) {
            if (!seconds) return '-';

            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);

            if (days > 0) {
                return `${days}d ${hours}h`;
            } else if (hours > 0) {
                return `${hours}h ${minutes}m`;
            } else {
                return `${minutes}m`;
            }
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
         * Get CSS class for radio band badge
         */
        getBandClass(radio) {
            if (!radio) return '';
            if (radio === '2.4 GHz') return 'band-24';
            if (radio === '5 GHz') return 'band-5';
            if (radio === '6 GHz') return 'band-6';
            return '';
        },

        /**
         * Get CSS class for signal strength
         */
        getSignalClass(rssi) {
            if (!rssi) return '';
            if (rssi >= -50) return 'signal-good';
            if (rssi >= -70) return 'signal-medium';
            return 'signal-poor';
        }
    };
}
