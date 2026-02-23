/**
 * Threat Watch - IDS/IPS Monitoring Dashboard
 * Alpine.js Application
 */

function dashboard() {
    return {
        // State
        events: [],
        stats: {
            highCount: 0,
            mediumCount: 0,
            lowCount: 0,
            blockedCount: 0,
            ignoredCount: 0,
            byCategory: [],
            topAttackers: []
        },
        categories: [],
        webhooks: [],
        ignoreRules: [],

        // UI State
        isLoading: false,
        activeTab: 'events',
        showWebhooks: false,
        showAddWebhook: false,
        showEditWebhook: false,
        showAddIgnoreRule: false,
        showEditIgnoreRule: false,
        showEventDetails: false,
        eventDetails: null,

        // Pagination
        currentPage: 1,
        pageSize: 50,
        totalEvents: 0,
        events24h: 0,
        totalPages: 1,
        hasMore: false,

        // Filters
        filters: {
            timeRange: '7d',
            severity: '',
            action: '',
            category: '',
            search: '',
            includeIgnored: false
        },

        // Sorting
        sortColumn: 'timestamp',
        sortDirection: 'desc',

        // Status
        lastRefresh: null,
        refreshInterval: 60,

        // Webhook Form
        webhookForm: {
            id: null,
            name: '',
            webhook_type: 'slack',
            url: '',
            min_severity: 2,
            event_alert: true,
            event_block: true,
            enabled: true
        },

        // Ignore Rule Form
        ignoreRuleForm: {
            id: null,
            ip_address: '',
            description: '',
            ignore_high: false,
            ignore_medium: true,
            ignore_low: true,
            match_source: true,
            match_destination: false,
            enabled: true
        },

        // Toast
        toast: {
            show: false,
            message: '',
            type: 'info'
        },

        // WebSocket
        ws: null,

        /**
         * Initialize the dashboard
         */
        async init() {
            await this.loadStatus();
            await this.loadEvents();
            await this.loadStats();
            await this.loadCategories();
            await this.loadWebhooks();
            await this.loadIgnoreRules();
            this.connectWebSocket();

            // Auto-refresh every minute
            setInterval(() => {
                this.loadEvents();
                this.loadStats();
                this.loadStatus();
            }, 60000);
        },

        /**
         * Load system status
         */
        async loadStatus() {
            try {
                const response = await fetch('/threats/api/status');
                if (response.ok) {
                    const data = await response.json();
                    this.lastRefresh = this.formatDateTime(data.last_refresh);
                    this.totalEvents = data.total_events;
                    this.events24h = data.events_24h;
                    this.refreshInterval = data.refresh_interval_seconds;
                }
            } catch (error) {
                console.error('Failed to load status:', error);
            }
        },

        /**
         * Load threat events
         */
        async loadEvents() {
            this.isLoading = true;
            try {
                const params = new URLSearchParams();
                params.append('page', this.currentPage);
                params.append('page_size', this.pageSize);

                if (this.filters.timeRange) params.append('time_range', this.filters.timeRange);
                if (this.filters.severity) params.append('severity', this.filters.severity);
                if (this.filters.action) params.append('action', this.filters.action);
                if (this.filters.category) params.append('category', this.filters.category);
                if (this.filters.search) params.append('search', this.filters.search);
                if (this.filters.includeIgnored) params.append('include_ignored', 'true');
                if (this.sortColumn) params.append('sort', this.sortColumn);
                if (this.sortDirection) params.append('sort_direction', this.sortDirection);

                const response = await fetch(`/threats/api/events?${params}`);
                if (response.ok) {
                    const data = await response.json();
                    this.events = data.events;
                    this.totalEvents = data.total;
                    this.totalPages = Math.ceil(data.total / this.pageSize);
                    this.hasMore = data.has_more;
                }
            } catch (error) {
                console.error('Failed to load events:', error);
                this.showToast('Failed to load events', 'error');
            } finally {
                this.isLoading = false;
            }
        },

        /**
         * Load statistics
         */
        async loadStats() {
            try {
                const params = new URLSearchParams();
                if (this.filters.timeRange) params.append('time_range', this.filters.timeRange);
                if (this.filters.includeIgnored) params.append('include_ignored', 'true');

                const response = await fetch(`/threats/api/events/stats?${params}`);
                if (response.ok) {
                    const data = await response.json();

                    // Extract severity counts
                    this.stats.highCount = data.by_severity.find(s => s.severity === 1)?.count || 0;
                    this.stats.mediumCount = data.by_severity.find(s => s.severity === 2)?.count || 0;
                    this.stats.lowCount = data.by_severity.find(s => s.severity === 3)?.count || 0;
                    this.stats.blockedCount = data.blocked_count || 0;
                    this.stats.ignoredCount = data.ignored_count || 0;

                    this.stats.byCategory = data.by_category || [];
                    this.stats.topAttackers = data.top_attackers || [];
                }
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        },

        /**
         * Load categories for filter dropdown
         */
        async loadCategories() {
            try {
                const response = await fetch('/threats/api/events/categories');
                if (response.ok) {
                    const data = await response.json();
                    this.categories = data.categories || [];
                }
            } catch (error) {
                console.error('Failed to load categories:', error);
            }
        },

        /**
         * Load webhooks
         */
        async loadWebhooks() {
            try {
                const response = await fetch('/threats/api/webhooks');
                if (response.ok) {
                    const data = await response.json();
                    this.webhooks = data.webhooks || [];
                }
            } catch (error) {
                console.error('Failed to load webhooks:', error);
            }
        },

        /**
         * Save webhook (create or update)
         */
        async saveWebhook() {
            try {
                const isEdit = this.showEditWebhook;
                const method = isEdit ? 'PUT' : 'POST';
                const url = isEdit
                    ? `/threats/api/webhooks/${this.webhookForm.id}`
                    : '/threats/api/webhooks';

                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(this.webhookForm)
                });

                if (response.ok) {
                    this.showToast(isEdit ? 'Webhook updated' : 'Webhook created', 'success');
                    this.showAddWebhook = false;
                    this.showEditWebhook = false;
                    this.resetWebhookForm();
                    await this.loadWebhooks();
                } else {
                    const data = await response.json();
                    this.showToast(data.detail || 'Failed to save webhook', 'error');
                }
            } catch (error) {
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
                min_severity: webhook.min_severity,
                event_alert: webhook.event_alert,
                event_block: webhook.event_block,
                enabled: webhook.enabled
            };
            this.showEditWebhook = true;
        },

        /**
         * Test webhook
         */
        async testWebhook(webhookId) {
            try {
                const response = await fetch(`/threats/api/webhooks/${webhookId}/test`, {
                    method: 'POST',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    this.showToast('Test webhook sent successfully', 'success');
                } else {
                    const data = await response.json();
                    this.showToast(data.detail || 'Failed to send test webhook', 'error');
                }
            } catch (error) {
                this.showToast('Failed to send test webhook', 'error');
            }
        },

        /**
         * Delete webhook
         */
        async deleteWebhook(id) {
            if (!confirm('Are you sure you want to delete this webhook?')) return;

            try {
                const response = await fetch(`/threats/api/webhooks/${id}`, {
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
                this.showToast('Failed to delete webhook', 'error');
            }
        },

        /**
         * Reset webhook form
         */
        resetWebhookForm() {
            this.webhookForm = {
                id: null,
                name: '',
                webhook_type: 'slack',
                url: '',
                min_severity: 2,
                event_alert: true,
                event_block: true,
                enabled: true
            };
        },

        /**
         * Load ignore rules
         */
        async loadIgnoreRules() {
            try {
                const response = await fetch('/threats/api/ignore-rules');
                if (response.ok) {
                    const data = await response.json();
                    this.ignoreRules = data.rules || [];
                }
            } catch (error) {
                console.error('Failed to load ignore rules:', error);
            }
        },

        /**
         * Save ignore rule (create or update)
         */
        async saveIgnoreRule() {
            try {
                const isEdit = this.showEditIgnoreRule;
                const method = isEdit ? 'PUT' : 'POST';
                const url = isEdit
                    ? `/threats/api/ignore-rules/${this.ignoreRuleForm.id}`
                    : '/threats/api/ignore-rules';

                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify(this.ignoreRuleForm)
                });

                if (response.ok) {
                    this.showToast(isEdit ? 'Ignore rule updated' : 'Ignore rule created', 'success');
                    this.showAddIgnoreRule = false;
                    this.showEditIgnoreRule = false;
                    this.resetIgnoreRuleForm();
                    await this.loadIgnoreRules();
                } else {
                    const data = await response.json();
                    this.showToast(data.detail || 'Failed to save ignore rule', 'error');
                }
            } catch (error) {
                this.showToast('Failed to save ignore rule', 'error');
            }
        },

        /**
         * Edit ignore rule
         */
        editIgnoreRule(rule) {
            this.ignoreRuleForm = {
                id: rule.id,
                ip_address: rule.ip_address,
                description: rule.description || '',
                ignore_high: rule.ignore_high,
                ignore_medium: rule.ignore_medium,
                ignore_low: rule.ignore_low,
                match_source: rule.match_source,
                match_destination: rule.match_destination,
                enabled: rule.enabled
            };
            this.showEditIgnoreRule = true;
        },

        /**
         * Delete ignore rule
         */
        async deleteIgnoreRule(id) {
            if (!confirm('Are you sure you want to delete this ignore rule?')) return;

            try {
                const response = await fetch(`/threats/api/ignore-rules/${id}`, {
                    method: 'DELETE',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (response.ok) {
                    this.showToast('Ignore rule deleted', 'success');
                    await this.loadIgnoreRules();
                } else {
                    this.showToast('Failed to delete ignore rule', 'error');
                }
            } catch (error) {
                this.showToast('Failed to delete ignore rule', 'error');
            }
        },

        /**
         * Reset ignore rule form
         */
        resetIgnoreRuleForm() {
            this.ignoreRuleForm = {
                id: null,
                ip_address: '',
                description: '',
                ignore_high: false,
                ignore_medium: true,
                ignore_low: true,
                match_source: true,
                match_destination: false,
                enabled: true
            };
        },

        /**
         * Quick-ignore from event details - opens form pre-filled with event's source IP
         */
        openIgnoreFromEvent() {
            if (this.eventDetails && this.eventDetails.src_ip) {
                this.ignoreRuleForm = {
                    id: null,
                    ip_address: this.eventDetails.src_ip,
                    description: '',
                    ignore_high: false,
                    ignore_medium: true,
                    ignore_low: true,
                    match_source: true,
                    match_destination: false,
                    enabled: true
                };
                this.showEventDetails = false;
                this.showAddIgnoreRule = true;
            }
        },

        /**
         * View event details
         */
        async viewEventDetails(eventId) {
            try {
                const response = await fetch(`/threats/api/events/${eventId}`);
                if (response.ok) {
                    this.eventDetails = await response.json();
                    this.showEventDetails = true;
                }
            } catch (error) {
                this.showToast('Failed to load event details', 'error');
            }
        },

        /**
         * Filter by IP address
         */
        filterByIp(ip) {
            this.filters.search = ip;
            this.activeTab = 'events';
            this.currentPage = 1;
            this.loadEvents();
        },

        /**
         * Filter by category
         */
        filterByCategory(category) {
            this.filters.category = category;
            this.activeTab = 'events';
            this.currentPage = 1;
            this.loadEvents();
        },

        /**
         * Pagination - next page
         */
        nextPage() {
            if (this.hasMore) {
                this.currentPage++;
                this.loadEvents();
            }
        },

        /**
         * Pagination - previous page
         */
        prevPage() {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.loadEvents();
            }
        },

        /**
         * Sort by column
         */
        sortBy(column) {
            if (this.sortColumn === column) {
                this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                this.sortColumn = column;
                this.sortDirection = 'desc';
            }
            this.loadEvents();
        },

        /**
         * Connect WebSocket for real-time updates
         */
        connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;

            try {
                this.ws = new WebSocket(wsUrl);

                this.ws.onopen = () => {
                    console.log('WebSocket connected');
                };

                this.ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    if (data.type === 'threat_update') {
                        this.showToast(`${data.new_events} new threat events detected`, 'warning');
                        this.loadEvents();
                        this.loadStats();
                    }
                };

                this.ws.onclose = () => {
                    console.log('WebSocket disconnected, reconnecting...');
                    setTimeout(() => this.connectWebSocket(), 5000);
                };

                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                };
            } catch (error) {
                console.error('Failed to connect WebSocket:', error);
            }
        },

        /**
         * Format datetime for display
         */
        formatDateTime(dateStr) {
            if (!dateStr) return '-';
            const date = new Date(dateStr);
            return date.toLocaleString();
        },

        /**
         * Get severity CSS class
         */
        getSeverityClass(severity) {
            switch (severity) {
                case 1: return 'severity-high';
                case 2: return 'severity-medium';
                case 3: return 'severity-low';
                default: return 'severity-low';
            }
        },

        /**
         * Get severity label
         */
        getSeverityLabel(severity) {
            switch (severity) {
                case 1: return 'High';
                case 2: return 'Medium';
                case 3: return 'Low';
                default: return 'Unknown';
            }
        },

        /**
         * Truncate text
         */
        truncate(text, length) {
            if (!text) return '';
            if (text.length <= length) return text;
            return text.substring(0, length) + '...';
        },

        /**
         * Check if an IP address is RFC1918 private
         * 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
         */
        isPrivateIP(ip) {
            if (!ip) return false;
            const parts = ip.split('.').map(Number);
            if (parts.length !== 4) return false;
            // 10.0.0.0/8
            if (parts[0] === 10) return true;
            // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
            if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
            // 192.168.0.0/16
            if (parts[0] === 192 && parts[1] === 168) return true;
            return false;
        },

        /**
         * Show toast notification
         */
        showToast(message, type = 'info') {
            this.toast.message = message;
            this.toast.type = type;
            this.toast.show = true;

            setTimeout(() => {
                this.toast.show = false;
            }, 4000);
        }
    };
}
