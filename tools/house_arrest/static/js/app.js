/* House Arrest dashboard
 *
 * Behaviour worth keeping:
 *  - Applying always previews first. Apply stays disabled until a review has
 *    been generated, and any change to the device or preset clears it.
 *  - A lockdown whose policy no longer matches a client is never reported as
 *    protecting anything. That rule drives the trust strip at the top.
 *  - Preset consequences come from the server (policies.py), not from copy
 *    written here, so the interface can't describe behaviour it doesn't have.
 */
function houseArrest() {
    return {
        // Tab is remembered so a refresh does not bounce you back to the
        // first section mid-task.
        tab: 'networks',
        dnsResolvers: '',
        dnsNetworks: [],
        dnsBlockDot: false,
        dnsPreview: null,
        dnsCaveats: [],
        dnsPreviewing: false,
        dnsApplying: false,
        loading: true,
        previewing: false,
        applying: false,
        state: { connected: false, arrests: [], health: [], custom_policy_count: 0, total_policy_count: 0 },
        clients: [],
        networks: [],
        networkPresets: [],
        presets: [],
        pathLabels: {},
        assetVersion: '',
        toggle: null,
        wlans: [],
        wlansLoading: false,
        wlanToggle: null,
        showReturnTraffic: false,
        dnsFixDhcp: false,
        dhcpPreview: null,
        dhcpPreviewing: false,
        dhcpApplying: false,
        inspection: null,
        openBlocked: null,
        blockedFlows: [],
        blockedLoading: false,
        // network isolation
        isoNetworkId: '',
        isoPreset: '',
        isoPreview: null,
        isoNote: null,
        isoPreviewing: false,
        isoApplying: false,
        error: null,
        message: null,

        // lockdown form
        preset: '',
        selectedMacs: [],
        deviceSearch: '',
        deviceFilter: '',
        pickerOpen: false,
        labelTouched: false,
        label: '',
        networkId: '',
        allowInbound: true,
        preview: null,

        setTab(name) {
            this.tab = name;
            try { localStorage.setItem('house-arrest-tab', name); } catch (e) { /* private mode */ }
        },

        async init() {
            try {
                const saved = localStorage.getItem('house-arrest-tab');
                if (saved) this.tab = saved;
            } catch (e) { /* private mode */ }

            this.presets = this.readJson('ha-presets', []);
            this.pathLabels = this.readJson('ha-path-labels', {});
            this.networkPresets = this.readJson('ha-network-presets', []);
            this.assetVersion = this.readJson('ha-asset-version', '');
            if (this.networkPresets.length) this.isoPreset = this.networkPresets[0].value;
            if (this.presets.length) this.preset = this.presets[0].value;

            await this.refresh();
            this.loadNetworks();
            this.loadWlans();
            this.loadInspection();
            setInterval(() => this.refresh(true), 60000);
        },

        readJson(id, fallback) {
            const el = document.getElementById(id);
            if (!el) return fallback;
            try {
                return JSON.parse(el.textContent);
            } catch (e) {
                console.error('[HouseArrest] could not parse ' + id, e);
                return fallback;
            }
        },

        // ---- state ----

        get brokenCount() {
            return this.state.arrests.filter(a => a.status && a.status !== 'ok').length;
        },

        headline() {
            if (!this.state.connected) return 'Controller unreachable';
            if (this.brokenCount === 1) return '1 lockdown is not enforcing';
            if (this.brokenCount > 1) return this.brokenCount + ' lockdowns are not enforcing';
            if (this.state.arrests.length === 0) return 'Connected — nothing locked down';
            return 'All lockdowns enforcing';
        },

        currentNetworkPreset() {
            return this.networkPresets.find(p => p.value === this.isoPreset) || null;
        },

        isoSummary() {
            const p = this.currentNetworkPreset();
            return p ? p.effects.summary : '';
        },

        isoCaveats() {
            const p = this.currentNetworkPreset();
            return p ? p.caveats : [];
        },

        // Preset-keyed isolation diagram. One image per network preset so the
        // picture never contradicts the verdict the way a single static graphic
        // would — the same rule the device tab's scenario images follow.
        isoImage() {
            if (!this.isoPreset) return '';
            return '/arrest/static/images/isolation-' + this.isoPreset + '.png' +
                (this.assetVersion ? '?v=' + this.assetVersion : '');
        },
        isoImageAlt() {
            const p = this.currentNetworkPreset();
            return p ? ('Network isolation — ' + p.label + '. ' + p.effects.summary) : '';
        },

        async isoDryRun() {
            this.message = null;
            this.isoPreviewing = true;
            try {
                const res = await fetch('api/isolate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({
                        preset: this.isoPreset,
                        network_id: this.isoNetworkId,
                        dry_run: true
                    })
                });
                const data = await res.json();
                if (!res.ok || data.error) {
                    this.message = { kind: 'danger', text: data.detail || data.error || 'Review failed' };
                    return;
                }
                this.isoNote = data.note || null;
                this.isoPreview = data.changes || {};
            } finally {
                this.isoPreviewing = false;
            }
        },

        async isoApply() {
            if (!this.isoPreview) return;
            this.isoApplying = true;
            this.message = null;
            try {
                const res = await fetch('api/isolate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({
                        preset: this.isoPreset,
                        network_id: this.isoNetworkId,
                        dry_run: false
                    })
                });
                const data = await res.json();
                if (data.error) {
                    this.message = { kind: 'danger', text: data.error };
                } else {
                    const net = this.networks.find(n => n.id === this.isoNetworkId);
                    this.message = data.note
                        ? { kind: 'ok', text: data.note }
                        : {
                            kind: 'ok',
                            text: (net ? net.name : 'Network') + ' isolated - ' +
                                  Object.keys(data.changes || {}).length + ' setting(s) changed.'
                          };
                    this.isoPreview = null;
                    this.isoNetworkId = '';
                    await this.refresh(true);
                    this.loadInspection();
                }
            } finally {
                this.isoApplying = false;
            }
        },

        isoChangeLines() {
            const friendly = {
                network_isolation_enabled: v => v
                    ? 'Isolate Network: on - blocked from reaching your other networks'
                    : 'Isolate Network: off - can reach your other networks again',
                internet_access_enabled: v => v
                    ? 'Allow Internet Access: on - internet restored'
                    : 'Allow Internet Access: off - no internet for this network'
            };
            return Object.entries(this.isoPreview || {}).map(
                ([k, v]) => (friendly[k] ? friendly[k](v) : k + ' = ' + v)
            );
        },

        async releaseNetwork(networkId, label) {
            this.message = null;
            const res = await fetch('api/release-network', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({
                    preset: 'full_isolation', network_id: networkId, dry_run: false
                })
            });
            const data = await res.json();
            this.message = data.error
                ? { kind: 'danger', text: data.error }
                : { kind: 'ok', text: data.note || (label + ' released.') };
            await this.refreshAll();
        },

        async releaseLegacy() {
            this.message = null;
            const res = await fetch('api/release', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({ kind: 'network', dry_run: false })
            });
            const data = await res.json();
            this.message = data.error
                ? { kind: 'danger', text: data.error }
                : { kind: 'ok', text: (data.deleted || []).length + ' leftover rules removed.' };
            await this.refreshAll();
        },

        dnsReady() {
            return this.dnsNetworks.length > 0 && this.dnsResolverList().length > 0;
        },

        dnsResolverList() {
            return (this.dnsResolvers || '')
                .split(',').map(x => x.trim()).filter(Boolean);
        },

        async dnsDryRun() {
            this.message = null;
            this.dnsPreviewing = true;
            try {
                const res = await fetch('api/dns-lockdown', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({
                        network_ids: this.dnsNetworks,
                        resolver_ips: this.dnsResolverList(),
                        block_dot: this.dnsBlockDot,
                        dry_run: true
                    })
                });
                const data = await res.json();
                if (!res.ok || data.error) {
                    this.message = { kind: 'danger', text: data.detail || data.error || 'Review failed' };
                    return;
                }
                this.dnsPreview = data.payloads;
                this.dnsCaveats = data.caveats || [];
                // Preview both halves together, so "Review changes" shows the
                // whole change rather than only the firewall part.
                this.dhcpPreview = this.dnsFixDhcp
                    ? await this.dhcpPreviewFor(true)
                    : null;
            } finally {
                this.dnsPreviewing = false;
            }
        },

        async dnsApply() {
            if (!this.dnsPreview) return;
            this.dnsApplying = true;
            this.message = null;
            try {
                const res = await fetch('api/dns-lockdown', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({
                        network_ids: this.dnsNetworks,
                        resolver_ips: this.dnsResolverList(),
                        block_dot: this.dnsBlockDot,
                        dry_run: false
                    })
                });
                const data = await res.json();
                if (data.error) {
                    this.message = { kind: 'danger', text: data.error };
                } else {
                    this.message = {
                        kind: 'ok',
                        text: 'DNS lockdown applied — ' + data.created.length + ' rules created.'
                    };
                    // DHCP goes second on purpose: the rules are the half
                    // that can fail and roll itself back, and there is no
                    // sense repointing every device on a network at resolvers
                    // whose allow rule did not survive.
                    if (this.dnsFixDhcp) {
                        try {
                            const dhcp = await this.dhcpPreviewFor(false);
                            this.dhcpPreview = dhcp;
                            const failed = (dhcp.changes || []).filter(c => !c.applied);
                            if (failed.length) {
                                this.message = {
                                    kind: 'warn',
                                    text: 'Rules applied, but DHCP did not take on ' +
                                          failed.length + ' network(s) — check the UniFi UI.'
                                };
                            } else {
                                this.message.text +=
                                    ' DHCP now hands out the approved resolvers.';
                            }
                        } catch (e) {
                            this.message = {
                                kind: 'warn',
                                text: 'Rules applied, but the DHCP change failed: ' + e.message
                            };
                        }
                    }
                    this.dnsPreview = null;
                    this.dhcpPreview = null;
                    this.dnsCaveats = [];
                    // Clear what was just consumed, keep what is reusable. The
                    // approved resolver list is almost always the same for the
                    // next network, so it stays; the network selection and the
                    // per-lockdown options do not carry over, and leaving them
                    // ticked invites applying the same thing twice without
                    // noticing.
                    this.dnsNetworks = [];
                    this.dnsBlockDot = false;
                    this.dnsFixDhcp = false;
                    await this.refreshAll();
                    await this.loadNetworks();
                }
            } finally {
                this.dnsApplying = false;
            }
        },

        async dnsRelease(label) {
            this.message = null;
            const res = await fetch('api/dns-release?label=' + encodeURIComponent(label), { method: 'POST', headers: { 'X-Requested-With': 'XMLHttpRequest' } });
            const data = await res.json();
            this.message = data.error
                ? { kind: 'danger', text: data.error }
                : { kind: 'ok', text: 'DNS lockdown removed for ' + label + '.' };
            await this.refreshAll();
        },

        async toggleBlocked(label) {
            if (this.openBlocked === label) { this.openBlocked = null; return; }
            this.openBlocked = label;
            this.showReturnTraffic = false;
            this.blockedLoading = true;
            this.blockedFlows = [];
            try {
                const res = await fetch('api/blocked?label=' + encodeURIComponent(label));
                if (res.ok) this.blockedFlows = await res.json();
            } finally {
                this.blockedLoading = false;
            }
        },

        when(ms) {
            if (!ms) return '';
            const d = new Date(ms);
            const mins = Math.round((Date.now() - ms) / 60000);
            if (mins < 1) return 'just now';
            if (mins < 60) return mins + 'm ago';
            if (mins < 1440) return Math.round(mins / 60) + 'h ago';
            return d.toLocaleDateString();
        },

        stateText(status) {
            if (status === 'ok') return 'Enforcing';
            // The rules are live, but the VLAN move is waiting on a reconnect.
            if (status === 'pending_move') return 'Rules live — VLAN move pending reconnect';
            if (status === 'rotated') return 'MAC changed — not enforcing';
            return 'Not enforcing';
        },

        async refreshAll() {
            await this.refresh();
            await this.loadInspection();
            await this.loadNetworks();
        },

        async refresh(quiet = false) {
            if (!quiet) this.loading = true;
            try {
                const res = await fetch('api/state');
                this.state = await res.json();
                this.error = this.state.error || null;
                if (this.state.connected && this.clients.length === 0) {
                    await this.loadClients();
                }
            } catch (e) {
                this.error = 'Failed to reach the House Arrest API: ' + e;
            } finally {
                this.loading = false;
            }
        },

        async loadClients() {
            try {
                const res = await fetch('api/clients');
                if (res.ok) this.clients = await res.json();
            } catch (e) {
                /* picker stays empty; the rest of the page still works */
            }
        },

        async loadNetworks() {
            try {
                const res = await fetch('api/networks');
                if (res.ok) this.networks = await res.json();
            } catch (e) {
                /* Networks-tab selectors stay empty rather than silently wrong */
            }
        },

        async loadInspection() {
            this.inspection = { loading: true, findings: [] };
            try {
                const res = await fetch('api/inspect');
                this.inspection = await res.json();
            } catch (e) {
                this.inspection = { error: String(e), findings: [] };
            }
        },

        // ---- path diagram ----

        currentPreset() {
            return this.presets.find(p => p.value === this.preset) || null;
        },

        pathRows() {
            const p = this.currentPreset();
            const effects = p ? p.effects : { internet: 'block', networks: 'block', peers: 'allow' };
            const rows = ['internet', 'networks', 'peers'].map(key => ({
                key,
                label: this.pathLabels[key] || key,
                verdict: effects[key],
                fixed: key === 'peers'
            }));
            // The inbound direction is a choice, not a preset property, so it
            // is appended rather than living in PRESET_EFFECTS.
            rows.push({
                key: 'inbound',
                label: this.pathLabels['inbound'] || 'You reaching in to it',
                verdict: this.allowInbound ? 'allow' : 'block',
                fixed: false
            });
            return rows;
        },

        // ---- Wi-Fi client isolation ----
        //
        // The only control in this tool that reaches traffic between devices on
        // the same VLAN. A firewall policy never sees that traffic, so no
        // per-device preset can do this job — which is exactly the gap the LG
        // network-scanning reporting is about.
        //
        // Kept as its own action rather than bundled into a preset: isolation
        // belongs to the SSID, so containing one television also stops every
        // phone on that SSID casting or printing. That is the user's call.

        async loadWlans() {
            this.wlansLoading = true;
            try {
                const res = await fetch('api/wlans');
                this.wlans = res.ok ? await res.json() : [];
            } catch (e) {
                this.wlans = [];
            } finally {
                this.wlansLoading = false;
            }
        },

        openWlanToggle(w) {
            this.wlanToggle = {
                id: w.id,
                name: w.name,
                isolated: w.isolated,
                client_count: w.client_count,
                next: !w.isolated,
                saving: false,
                error: null,
            };
        },

        async applyWlanToggle() {
            if (!this.wlanToggle) return;
            this.wlanToggle.saving = true;
            this.wlanToggle.error = null;
            try {
                const res = await fetch('api/wlan-isolation', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({
                        wlan_id: this.wlanToggle.id,
                        enabled: this.wlanToggle.next,
                    }),
                });
                if (!res.ok) {
                    const body = await res.json().catch(() => ({}));
                    this.wlanToggle.error = body.detail ||
                        'The controller rejected the change. Nothing was altered.';
                    this.wlanToggle.saving = false;
                    return;
                }
                const name = this.wlanToggle.name;
                const on = this.wlanToggle.next;
                this.wlanToggle = null;
                this.message = {
                    kind: '',
                    text: on
                        ? `Client isolation is on for ${name}. Devices there can no longer reach each other.`
                        : `Client isolation is off for ${name}. Devices there can reach each other again.`,
                };
                // Re-read rather than patching locally: the table should show
                // what the controller actually has.
                await this.loadWlans();
            } catch (e) {
                this.wlanToggle.error = String(e);
                this.wlanToggle.saving = false;
            }
        },

        // ---- blocked traffic: attempts vs return traffic ----
        //
        // The server tags each aggregated destination as "connection" or
        // "return_traffic". Return traffic is UDP aimed at an ephemeral port,
        // which is the far side of a conversation the OTHER device opened —
        // measured at 100% of one real device's blocked traffic over 7 days.
        // Showing it inline made the panel useless, so it is parked behind a
        // disclosure with its count stated. It is never discarded.

        connectionFlows() {
            return this.blockedFlows.filter(f => f.kind !== 'return_traffic');
        },

        returnFlows() {
            return this.blockedFlows.filter(f => f.kind === 'return_traffic');
        },

        returnAttempts() {
            return this.returnFlows().reduce((n, f) => n + (f.count || 0), 0);
        },

        // Distinct peers, not rows: a destination can appear more than once
        // because rows are split by which rule blocked them.
        returnDeviceCount() {
            return new Set(this.returnFlows().map(f => f.destination)).size;
        },

        shownFlows() {
            return this.showReturnTraffic ? this.blockedFlows : this.connectionFlows();
        },

        // ---- DHCP name servers ----
        //
        // Previewed and applied as part of the DNS flow rather than from its
        // own button: it is an option ON a lockdown, not a separate task. It is
        // also the likeliest way to take a network's DNS out, so it belongs in
        // the same review as the firewall rules.

        // Networks already covered by a DNS lockdown. The server refuses these
        // outright; the picker greys them out so it never gets that far.
        dnsLockedIds() {
            return (this.state.dns_lockdowns || [])
                .flatMap(l => l.network_ids || []);
        },

        // Advertised resolvers on the CHOSEN networks that are not on the
        // approved list. Each one is a device about to be told to use a
        // resolver these rules will block — the exact self-inflicted outage
        // the DHCP checkbox exists to prevent.
        staleResolverCount() {
            const approved = this.dnsResolverList();
            if (!approved.length) return 0;
            return this.networks
                .filter(n => this.dnsNetworks.includes(n.id))
                .reduce((total, n) => total +
                    (n.dhcp_dns || []).filter(ip => !approved.includes(ip)).length, 0);
        },

        // True only when at least one network would actually change. Saying
        // "will change" over a list where every row already matches is a small
        // lie, and this tool does not get to tell small ones.
        dhcpChangesNeeded() {
            const changes = (this.dhcpPreview && this.dhcpPreview.changes) || [];
            return changes.some(c => c.current.join(',') !== c.proposed.join(','));
        },

        async dhcpPreviewFor(dryRun) {
            const res = await fetch('api/dhcp-dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({
                    network_ids: this.dnsNetworks,
                    resolver_ips: this.dnsResolverList(),
                    dry_run: dryRun,
                }),
            });
            const body = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(body.detail || 'DHCP request failed.');
            if (body.error) throw new Error(body.error);
            return body;
        },

        // ---- editable matrix cells ----
        //
        // Only the four columns that are a single boolean on the network can be
        // flipped here. The server enforces the same list, so this is about
        // what the UI offers, not about what it is allowed to do.

        EDITABLE: {
            isolation: { on: 'On', off: 'Off' },
            internet:  { on: 'Allowed', off: 'Blocked' },
            mdns:      { on: 'On', off: 'Off' },
        },

        // The server decides per cell, not per column. Editability can depend
        // on site-wide state, not just on which column this is, so the browser
        // asks rather than infers.
        cellEditable(row, col) {
            const cell = row.cells[col.key];
            return !!(cell && cell.editable) &&
                Object.prototype.hasOwnProperty.call(this.EDITABLE, col.key);
        },

        // The matrix cell label is the source of truth for the current value,
        // so the dialog reads the state off the same thing the user just
        // clicked rather than re-deriving it from a second copy of the data.
        openToggle(row, col) {
            const spec = this.EDITABLE[col.key];
            if (!spec || !this.cellEditable(row, col)) return;
            const cell = row.cells[col.key] || {};
            const isOn = cell.label === spec.on;
            const next = !isOn;

            this.toggle = {
                networkId: row.id,
                networkName: row.name,
                vlan: row.vlan,
                column: col.key,
                columnLabel: col.label,
                detail: cell.detail || '',
                currentLabel: isOn ? spec.on : spec.off,
                nextLabel: next ? spec.on : spec.off,
                // Each cell's "on" label maps to the field being true:
                // isolation On, and internet Allowed. So the value
                // to write is simply the state being moved to.
                value: next,
                warning: this.toggleWarning(col.key, next),
                saving: false,
                error: null,
            };
        },

        toggleWarning(key, next) {
            const W = {
                isolation: [
                    'Devices here will be able to reach your other networks again. If House Arrest isolated this network, this releases it.',
                    'Every device on this network loses access to your other networks, now and in future.',
                ],
                internet: [
                    'Every device on this network loses internet access, now and in future.',
                    'Devices here get internet access back.',
                ],
                mdns: [
                    'Removes this network from the site-wide Gateway mDNS Proxy list — the one shared list all networks use. Devices here stop discovering, and being discovered by, devices on your other mDNS-enabled networks. Casting and AirPlay across this boundary will break.',
                    'Adds this network to the site-wide Gateway mDNS Proxy list — the one shared list all networks use. Service discovery (casting, AirPlay) will cross this boundary, which also advertises what lives here to your other networks.',
                ],
            };
            const pair = W[key];
            return pair ? (next ? pair[1] : pair[0]) : '';
        },

        async applyToggle() {
            if (!this.toggle) return;
            this.toggle.saving = true;
            this.toggle.error = null;
            try {
                const res = await fetch('api/network-setting', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({
                        network_id: this.toggle.networkId,
                        column: this.toggle.column,
                        value: this.toggle.value,
                    }),
                });
                if (!res.ok) {
                    const body = await res.json().catch(() => ({}));
                    this.toggle.error = body.detail ||
                        'The controller rejected the change. Nothing was altered.';
                    this.toggle.saving = false;
                    return;
                }
                const name = this.toggle.networkName;
                const label = this.toggle.columnLabel;
                const to = this.toggle.nextLabel;
                this.toggle = null;
                this.message = { kind: '', text: `${label} for ${name} is now ${to}.` };
                // Re-read rather than patching the cell locally: the matrix is
                // supposed to show what the controller actually has.
                await this.loadInspection();
                this.refresh(true);
            } catch (e) {
                this.toggle.error = String(e);
                this.toggle.saving = false;
            }
        },

        // ---- scenario infographic ----
        //
        // The picture beside the verdict list. There is one image per
        // (preset, inbound) pair rather than one per preset, because the
        // inbound direction is a checkbox rather than a preset property — a
        // single per-preset picture would contradict the list the moment the
        // box was unticked, which is exactly the kind of quiet lie this tool
        // exists to avoid. Filenames are built from the same two values the
        // rows are, so the two cannot drift apart.

        scenarioKey() {
            const preset = this.preset ||
                (this.presets.length ? this.presets[0].value : 'full_lockdown');
            return preset + '-' + (this.allowInbound ? 'inbound' : 'noinbound');
        },

        scenarioImage() {
            return '/arrest/static/images/scenario-' + this.scenarioKey() + '.png' +
                (this.assetVersion ? '?v=' + this.assetVersion : '');
        },

        // Generated from the rendered verdicts rather than written by hand, so
        // a screen reader gets the diagram's actual content.
        scenarioAlt() {
            const p = this.currentPreset();
            const verdicts = this.pathRows()
                .map(r => r.label + ': ' + this.verdictText(r).toLowerCase())
                .join('. ');
            return 'Diagram of ' + (p ? p.label : 'this lockdown') + '. ' + verdicts + '.';
        },

        scenarioCaption() {
            const p = this.currentPreset();
            const name = p ? p.label : 'This lockdown';
            return name + (this.allowInbound
                ? ' — other devices can still reach in to it'
                : ' — nothing can reach in to it');
        },

        pathStroke(verdict) {
            if (verdict === 'block') return 'var(--state-broken)';
            if (verdict === 'moved') return 'var(--state-rotated)';
            return 'var(--state-enforcing)';
        },

        verdictText(path) {
            if (path.verdict === 'block') return 'Blocked';
            // "moved" is deliberately not "blocked": relocating a device changes
            // which peers it can reach, it does not cut peer traffic.
            if (path.verdict === 'moved') return 'Changes with the VLAN';
            return 'Still reachable';
        },

        pathNote() {
            return 'Devices on the same VLAN talk to each other without passing the ' +
                   'gateway, so no firewall policy can separate them. UniFi can do it ' +
                   'at the switch, via Device Isolation on the network — but that ' +
                   'applies to every device on that VLAN, not just this one. For one ' +
                   'device alone, give it a dedicated VLAN in UniFi itself (its switch ' +
                   'port or a dedicated Wi-Fi network), then lock that VLAN down here.';
        },

        canReview() {
            return this.selectedMacs.length > 0;
        },

        reviewHint() {
            return 'Review first — nothing reaches your gateway until you apply.';
        },

        // ---- form ----

        selectedClients() {
            return this.selectedMacs
                .map(m => this.clients.find(c => c.mac === m))
                .filter(Boolean);
        },

        selectedNames() {
            const names = this.selectedClients().map(c => c.name || c.mac);
            if (names.length <= 2) return names.join(' and ');
            return names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1];
        },

        randomizedClients() {
            return this.selectedClients().filter(c => c.locally_administered);
        },

        // MACs already under an active arrest. Selecting one again would just
        // bounce off the server's duplicate guard, so the picker greys them
        // out and says why instead of letting the request fail later.
        isArrested(mac) {
            return this.state.arrests.some(a => (a.macs || []).includes(mac));
        },

        clientNetworks() {
            const names = new Set();
            this.clients.forEach(c => { if (c.network) names.add(c.network); });
            return Array.from(names).sort((a, b) => a.localeCompare(b));
        },

        filteredClients() {
            const q = this.deviceSearch.trim().toLowerCase();
            // The MAC fallback only runs when the query actually looks like a
            // MAC fragment. Without the gate, the hex letters hiding in a name
            // search ("testclient" contains "ece") match unrelated MAC tails —
            // measured: it selected the wrong device on Enter.
            const looksLikeMac = /^[0-9a-f]{2}([:\-. ]?[0-9a-f]{1,2})*$/.test(q);
            const qMac = looksLikeMac ? q.replace(/[^0-9a-f]/g, '') : '';
            return this.clients.filter(c => {
                if (this.deviceFilter && c.network !== this.deviceFilter) return false;
                if (!q) return true;
                if ((c.name || '').toLowerCase().includes(q)) return true;
                if ((c.ip || '').includes(q)) return true;
                // Separators are ignored, so "a690" still finds b8:a1:75:28:a6:90.
                if (qMac && c.mac.replace(/[^0-9a-f]/g, '').includes(qMac)) return true;
                return false;
            });
        },

        toggleDevice(mac) {
            const i = this.selectedMacs.indexOf(mac);
            if (i >= 0) this.selectedMacs.splice(i, 1);
            else this.selectedMacs.push(mac);
            this.deviceSearch = '';
            this.preview = null;
            this.message = null;
            this.autoLabel();
            // Keep typing where the user expects: picking a row moves focus to
            // the row, so a second search would otherwise go nowhere.
            if (this.$refs.deviceSearch) this.$refs.deviceSearch.focus();
        },

        removeDevice(mac) {
            this.selectedMacs = this.selectedMacs.filter(m => m !== mac);
            this.preview = null;
            this.autoLabel();
        },

        removeLastDevice() {
            if (this.selectedMacs.length) this.removeDevice(this.selectedMacs[this.selectedMacs.length - 1]);
        },

        toggleFirstMatch() {
            const first = this.filteredClients().find(c => !this.isArrested(c.mac));
            if (first) this.toggleDevice(first.mac);
        },

        // Keep the label in step with the selection until the user edits it
        // themselves — then it is theirs and we stop touching it.
        autoLabel() {
            if (this.labelTouched && this.label) return;
            const cs = this.selectedClients();
            if (cs.length === 0) { this.label = ''; this.labelTouched = false; return; }
            const first = cs[0].name || cs[0].mac;
            this.label = cs.length === 1 ? first : first + ' + ' + (cs.length - 1) + ' more';
        },

        reviewTitle() {
            const n = this.preview ? this.preview.length : 0;
            return 'Review: ' + n + (n === 1 ? ' policy' : ' policies') +
                   ' will be added to your gateway';
        },

        reviewLines() {
            const p = this.currentPreset();
            const lines = [];
            if (p) {
                const rows = this.pathRows().filter(r => r.verdict === 'block');
                rows.forEach(r => lines.push(r.label + ' — blocked'));
                if (!rows.length) lines.push('Nothing blocked by this preset');
            }
            (this.preview || []).forEach(pol => {
                lines.push('Policy "' + pol.name + '" at index ' + pol.index);
            });
            return lines;
        },

        async dryRun() {
            this.message = null;
            this.previewing = true;
            try {
                const res = await fetch('api/lockdown', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({
                        preset: this.preset,
                        macs: this.selectedMacs,
                        label: this.label,
                        network_id: this.networkId || null,
                        allow_inbound: this.allowInbound,
                        dry_run: true
                    })
                });
                const data = await res.json();
                if (!res.ok || data.error) {
                    this.message = { kind: 'danger', text: data.detail || data.error || 'Review failed' };
                    return;
                }
                this.preview = data.payloads;
            } finally {
                this.previewing = false;
            }
        },

        async apply() {
            if (!this.preview) return;
            this.applying = true;
            this.message = null;
            try {
                const res = await fetch('api/lockdown', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({
                        preset: this.preset,
                        macs: this.selectedMacs,
                        label: this.label,
                        network_id: this.networkId || null,
                        allow_inbound: this.allowInbound,
                        dry_run: false
                    })
                });
                const data = await res.json();
                if (data.error) {
                    this.message = { kind: 'danger', text: data.error };
                } else {
                    this.message = {
                        kind: 'ok',
                        text: this.label + ' is under house arrest — ' +
                              data.created.length + ' policies written to your gateway.'
                    };
                    this.preview = null;
                    this.selectedMacs = [];
                    this.labelTouched = false;
                    this.label = '';
                    this.networkId = '';
                    await this.refresh(true);
                }
            } finally {
                this.applying = false;
            }
        },

        async release(labelToRelease) {
            this.message = null;
            const res = await fetch('api/release', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                body: JSON.stringify({ label: labelToRelease, kind: 'device', dry_run: false })
            });
            const data = await res.json();
            if (data.error) {
                this.message = { kind: 'danger', text: data.error };
            } else {
                const refused = (data.refused || []).length;
                this.message = {
                    kind: refused ? 'warn' : 'ok',
                    text: 'Released ' + labelToRelease + ' — ' + data.deleted.length +
                          ' policies removed' + (refused ? ', ' + refused + ' refused.' : '.')
                };
                await this.refresh(true);
            }
        }
    };
}
