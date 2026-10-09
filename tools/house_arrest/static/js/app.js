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
        // Optional per-device switch-ACL neighbour block, offered on Internet
        // only. Off by default: it also breaks casting/printing between the
        // device and its neighbours. Quarantine applies it without asking.
        // (The "let other devices reach it" checkbox was removed 2026-10-02;
        // each preset now fixes that, see inboundAllowed().)
        blockNeighbours: false,
        preview: null,
        previewCaveats: [],

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

        get brokenDevices() {
            return this.state.arrests.filter(a => a.status && a.status !== 'ok').length;
        },

        get brokenDns() {
            return (this.state.dns_lockdowns || [])
                .filter(l => l.disabled_count > 0 || l.network_missing).length;
        },

        get brokenCount() {
            return this.brokenDevices + this.brokenDns;
        },

        // The strip sits above every tab, so it names the tab the problem is
        // on. Without that, a DNS problem read as a Devices problem.
        headline() {
            if (!this.state.connected) return 'Controller unreachable';
            if (this.brokenCount) {
                const n = this.brokenCount;
                const what = n === 1 ? '1 lockdown needs' : n + ' lockdowns need';
                const where = [];
                if (this.brokenDevices) where.push('Devices');
                if (this.brokenDns) where.push('DNS');
                return what + ' attention on the ' + where.join(' and ') +
                    (where.length > 1 ? ' tabs' : ' tab');
            }
            if (this.state.arrests.length === 0) return 'Connected. Nothing is locked down.';
            return 'All lockdowns enforcing';
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
                    // Anything applying also did to device lockdowns (re-created
                    // behind the new allow, or failed to) belongs in the result.
                    const notices = (data.notices || []).join(' ');
                    this.message = {
                        kind: data.notices_failed ? 'warn' : 'ok',
                        text: 'DNS lockdown applied: ' + data.created.length + ' rules created.' +
                            (notices ? ' ' + notices : '')
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
                                    text: 'DNS Lockdown rules applied, but the DHCP change did not take on ' +
                                          failed.length + ' network(s). Check the UniFi UI.' +
                                          (notices ? ' ' + notices : '')
                                };
                            } else {
                                this.message.text +=
                                    ' DHCP now hands out your approved DNS servers.';
                            }
                        } catch (e) {
                            this.message = {
                                kind: 'warn',
                                text: 'DNS Lockdown rules applied, but the DHCP change failed: ' + e.message +
                                    (notices ? ' ' + notices : '')
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

        // DNS lockdown row state. Any rule toggled off in the UniFi UI means
        // the set is not fully enforcing, and green would be a lie.
        dnsStateText(l) {
            if (l.network_missing) return 'Network deleted in UniFi. Release this lockdown to remove its rules.';
            if (!l.disabled_count) return 'Enforcing';
            if (l.disabled_count >= l.policy_ids.length) return 'Disabled in UniFi — not enforcing';
            return l.disabled_count + ' of ' + l.policy_ids.length + ' rules disabled in UniFi';
        },

        stateText(status) {
            if (status === 'ok') return 'Enforcing';
            if (status === 'disabled') return 'Disabled in UniFi — not enforcing';
            // The rules are live, but the VLAN move is waiting on a reconnect.
            if (status === 'pending_move') return 'Rules live — VLAN move pending reconnect';
            if (status === 'rotated') return 'MAC changed. Not enforcing.';
            if (status === 'dns_blocked') return 'Blocking this device\'s DNS';
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
            } finally {
                // Explicit false, not merely absent. MEASURED 2026-09-18:
                // Alpine leaves a bound `disabled` attribute IN PLACE when the
                // binding evaluates to undefined, so replacing this object
                // with an API response that has no `loading` key left the
                // re-read button permanently disabled after the first load.
                this.inspection.loading = false;
            }
        },

        // ---- path diagram ----

        currentPreset() {
            return this.presets.find(p => p.value === this.preset) || null;
        },

        pathRows() {
            const p = this.currentPreset();
            const effects = p ? p.effects : { internet: 'block', networks: 'block', peers: 'allow' };
            const neighbours = this.neighbourBlockActive();
            const rows = ['internet', 'networks', 'peers'].map(key => ({
                key,
                label: this.pathLabels[key] || key,
                // The neighbour block is enforced by switches, and only as far
                // as they can reach, so it gets its own verdict rather than a
                // flat "Blocked" that would overclaim.
                verdict: (key === 'peers' && neighbours) ? 'switch' : effects[key],
                fixed: key === 'peers' && !this.neighbourOffered()
            }));
            // Network-wide settings (Networks tab) apply whatever this preset
            // says. Where every selected device's network agrees, show the
            // real result; mixed selections get one note under the rows.
            const iso = this.netFact('network_isolated');
            const noNet = this.netFact('network_internet_off');
            const devIso = this.netFact('network_device_isolation');
            rows.forEach(r => {
                if (r.key === 'internet' && r.verdict === 'allow' && noNet === 'all') {
                    r.verdict = 'block'; r.text = 'Blocked by this device\'s network settings';
                }
                if (r.key === 'networks' && r.verdict === 'allow' && iso === 'all') {
                    // Rules that get through the isolation (listed on the
                    // Networks tab) mean "blocked" is not the whole story.
                    const holes = Math.max(...this.selectedClients()
                        .map(c => c.network_isolation_exceptions || 0));
                    r.verdict = 'block';
                    r.text = holes
                        ? 'Blocked by this device\'s network settings, except ' + holes +
                          (holes === 1 ? ' rule' : ' rules') + ' listed on the Networks tab'
                        : 'Blocked by this device\'s network settings';
                }
                if (r.key === 'peers' && r.verdict === 'allow' && devIso === 'all') {
                    r.verdict = 'switch'; r.text = 'Blocked by Device isolation on this device\'s network, on supported switches only';
                }
            });
            // Your other networks starting connections to it. Fixed by the
            // preset since 2026-10-02 (only Quarantine blocks it). Devices on
            // its own network are the "peers" row: their traffic never passes
            // the gateway, so this rule never applied to them.
            rows.push({
                key: 'inbound',
                label: this.pathLabels['inbound'] || 'Your other networks connecting to this device',
                verdict: this.inboundAllowed() ? 'allow' : 'block',
                fixed: true
            });
            const inRow = rows[rows.length - 1];
            if (inRow.verdict === 'allow' && iso === 'all') {
                inRow.verdict = 'block'; inRow.text = 'Blocked by this device\'s network settings';
            }
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
            device_isolation: { on: 'On', off: 'Off' },
            internet:  { on: 'Allowed', off: 'Blocked' },
            mdns:      { on: 'On', off: 'Off' },
        },

        // A cell can qualify its state ("On · 4 of 41"), so "is it on" means
        // the label is the on-word, alone or followed by that qualifier.
        cellIsOn(cell, spec) {
            const label = (cell && cell.label) || '';
            return label === spec.on || label.startsWith(spec.on + ' ·');
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
            const isOn = this.cellIsOn(cell, spec);
            const next = !isOn;

            // The isolation diagrams are keyed to flag combinations, so the
            // dialog can show the exact state this click lands the network in:
            // read both flags off the row, override the one being toggled.
            let img = null;
            if (col.key === 'isolation' || col.key === 'internet') {
                const isoCell = row.cells['isolation'] || {};
                const inetCell = row.cells['internet'] || {};
                let iso = isoCell.label === 'On';
                let inet = inetCell.label === 'Allowed';
                if (col.key === 'isolation') iso = next;
                if (col.key === 'internet') inet = next;
                if (iso && !inet) img = 'full_isolation';
                else if (iso && inet) img = 'isolate_networks';
                else if (!iso && !inet) img = 'no_internet';
                // both open = the normal state, no diagram needed
            }
            const imgPreset = img ? this.networkPresets.find(p => p.value === img) : null;

            this.toggle = {
                isoImage: img
                    ? '/arrest/static/images/isolation-' + img + '.png' +
                      (this.assetVersion ? '?v=' + this.assetVersion : '')
                    : null,
                isoCaption: imgPreset
                    ? 'Where this leaves ' + row.name + ': ' + imgPreset.effects.summary
                    : '',
                isoAlt: imgPreset
                    ? 'Diagram: ' + imgPreset.label + '. ' + imgPreset.effects.summary
                    : '',
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
                warning: this.toggleWarning(col.key, next, row),
                saving: false,
                error: null,
            };
        },

        // mDNS and isolation interact (measured 2026-10-08): with both on,
        // other networks see the devices here but cannot connect to them.
        // Whichever of the two is being changed, the warning must not promise
        // the opposite of what the other one does.
        toggleWarning(key, next, row) {
            const cells = (row && row.cells) || {};
            const isolated = (cells.isolation || {}).label === 'On';
            const mdnsOn = (cells.mdns || {}).label === 'On';
            if (key === 'mdns' && next && isolated) {
                return 'Adds this network to the Gateway mDNS Proxy list, a single list shared by every network on the site. Your other mDNS-enabled networks will see the devices here, but network isolation is on, so connecting to them will still fail. Casting and AirPlay will only work for a device that a firewall rule you added lets through.';
            }
            if (key === 'isolation' && next && mdnsOn) {
                return 'Every device on this network loses access to your other networks, now and in future. mDNS forwarding is on, so your other networks will still see the devices here, but connecting to them will fail.';
            }
            const W = {
                isolation: [
                    'Devices on this network will be able to reach your other networks again.',
                    'Every device on this network loses access to your other networks, now and in future.',
                ],
                internet: [
                    'Every device on this network loses internet access, now and in future.',
                    'Devices here get internet access back.',
                ],
                device_isolation: [
                    'Devices on this network will be able to reach each other again.',
                    'Devices on this network will stop reaching each other. Device isolation only fully works for wired devices plugged into a UniFi switch model that supports it, and hovering the cell shows how many devices that is. Wi-Fi devices are only partly blocked, so turn on Wi-Fi client isolation for those as well. Casting, AirPlay, and printing between devices on this network will stop working.',
                ],
                mdns: [
                    'Removes this network from the Gateway mDNS Proxy list, a single list shared by every network on the site. Devices here will stop discovering, and being discovered by, devices on your other mDNS-enabled networks. Casting and AirPlay between them will stop working.',
                    'Adds this network to the Gateway mDNS Proxy list, a single list shared by every network on the site. Casting and AirPlay will work between this network and your other mDNS-enabled networks, which also means those networks can see what devices are here.',
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

        // Selected wireless devices whose own SSID already has Client
        // Isolation on. For them the diagram's green same-VLAN path
        // overstates reality — isolation already cuts peer traffic, which is
        // stricter than anything these firewall rules do.
        isolatedSelected() {
            const isolatedSsids = new Set(
                (this.wlans || []).filter(w => w.isolated).map(w => w.name));
            return this.selectedClients().filter(
                c => c.essid && isolatedSsids.has(c.essid));
        },

        isolatedSelectedNote() {
            const hits = this.isolatedSelected();
            if (!hits.length) return '';
            const names = hits.map(c => c.name || c.mac).join(' and ');
            const ssids = [...new Set(hits.map(c => c.essid))].join(', ');
            return 'Better than the picture shows: ' + names +
                (hits.length === 1 ? ' is' : ' are') + ' on Wi-Fi ' +
                (ssids.includes(',') ? 'networks ' : 'network ') + ssids +
                ', which already has Client Isolation on, so the green ' +
                '"same VLAN" path is already cut for ' +
                (hits.length === 1 ? 'it' : 'them') +
                ' at the Wi-Fi level, before these rules even apply.';
        },

        // Each picture draws one RESULT: the four verdicts in pathRows() order
        // (internet, other networks, same network, inbound). The picture is
        // chosen from the rows, not the preset name, so a device whose own
        // network settings change a row still gets the picture of what
        // actually happens. Until 2026-10-08 it was chosen by preset and
        // hidden whenever a row was rewritten, which on an isolated network
        // hid it for every preset except Quarantine.
        SCENARIOS: {
            'allow,block,allow,allow':  'internet_only',
            'allow,block,switch,allow': 'internet_only-neighbours',
            'allow,block,allow,block':  'internet_only-isolated',
            'allow,block,switch,block': 'internet_only-neighbours-isolated',
            'block,allow,allow,allow':  'lan_only',
            'block,block,allow,allow':  'full_lockdown',
            'block,block,allow,block':  'cut_off-noneighbours',
            'block,block,switch,block': 'cut_off',
        },

        SCENARIO_CAPTIONS: {
            'internet_only': 'your other networks can still reach this device',
            'internet_only-neighbours': 'other devices on the same network are blocked, and your other networks can still reach this device',
            'internet_only-isolated': 'this device can reach the internet and devices on its own network, nothing else',
            'internet_only-neighbours-isolated': 'this device can reach the internet and nothing else',
            'lan_only': 'this device can reach your local devices, never the internet',
            'full_lockdown': 'your other networks can still reach this device',
            'cut_off-noneighbours': 'other devices on the same network can still reach this device',
            'cut_off': 'nothing in or out',
        },

        // Null when no picture draws this result; the template then shows a
        // hint rather than a picture that contradicts the list.
        scenarioKey() {
            const result = this.pathRows().map(r => r.verdict).join(',');
            return this.SCENARIOS[result] || null;
        },

        scenarioMatchesRows() {
            return this.scenarioKey() !== null;
        },

        scenarioImage() {
            const key = this.scenarioKey();
            if (!key) return '';
            return '/arrest/static/images/scenario-' + key + '.png' +
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

        // Captions describe the picture, which describes the result. When the
        // device's network settings changed a row, say so, or a "LAN only"
        // caption over a Quarantine-shaped picture would look like a mistake.
        scenarioCaption() {
            const p = this.currentPreset();
            const name = p ? p.label : 'This lockdown';
            const key = this.scenarioKey();
            if (!key) return '';
            const changed = this.pathRows().some(r => r.text);
            return name + (changed ? ' with this device\'s network settings' : '') +
                ': ' + this.SCENARIO_CAPTIONS[key];
        },

        pathStroke(verdict) {
            if (verdict === 'block' || verdict === 'switch') return 'var(--state-broken)';
            if (verdict === 'moved') return 'var(--state-rotated)';
            return 'var(--state-enforcing)';
        },

        verdictText(path) {
            if (path.text) return path.text;
            if (path.verdict === 'block') return 'Blocked';
            // "moved" is deliberately not "blocked": relocating a device changes
            // which peers it can reach, it does not cut peer traffic.
            if (path.verdict === 'moved') return 'Changes with the VLAN';
            if (path.verdict === 'switch') return 'Blocked, on supported switches only';
            return 'Still reachable';
        },

        // ---- preset comparison grid ----
        //
        // Read from each preset's effects (the same data the server builds
        // rules from), not hand-written, so the grid can't drift.

        compareColumns() {
            return [
                { key: 'internet', label: 'This device can reach the internet' },
                { key: 'networks', label: 'This device can reach your other networks' },
                { key: 'inbound', label: 'Your other networks can reach this device' },
                { key: 'peers', label: 'Other devices on the same network' },
            ];
        },

        compareCell(p, key) {
            const e = p.effects || {};
            if (key === 'inbound') {
                return p.inbound === false
                    ? { kind: 'block', text: 'Blocked' }
                    : { kind: 'allow', text: 'Allowed' };
            }
            if (key === 'peers') {
                if (p.neighbour_always) {
                    return { kind: 'block', text: 'Blocked, on supported switches only' };
                }
                if (p.neighbour_block) {
                    return { kind: 'option', text: 'Allowed, or blocked with the checkbox' };
                }
                return { kind: 'allow', text: 'Allowed' };
            }
            return e[key] === 'block'
                ? { kind: 'block', text: 'Blocked' }
                : { kind: 'allow', text: 'Allowed' };
        },

        // The one line shown on the collapsed chart. Built from the same rows
        // the chart draws, so the two can never disagree, and it always names
        // what is still reachable, because that is the part people miss.
        //
        // The rows mean two directions, so the sentence keeps them apart: the
        // first three are what the DEVICE can reach, the last is what can
        // reach IT. One flat "blocked / reachable" list put "your other
        // networks" on both sides and read as a contradiction.
        pathsSummary() {
            const one = this.selectedMacs.length <= 1;
            const join = (xs, last) => xs.length <= 1 ? (xs[0] || '')
                : xs.slice(0, -1).join(', ') + ' ' + last + ' ' + xs[xs.length - 1];
            const phrase = {
                internet: 'the internet',
                networks: 'your other networks',
                peers: 'other devices on the same network',
            };
            const rows = this.pathRows();
            const out = rows.filter(r => r.key !== 'inbound');
            const name = r => phrase[r.key] +
                (r.verdict === 'switch' ? ' (on supported switches only)' : '');
            const cant = out.filter(r => r.verdict !== 'allow').map(name);
            const can = out.filter(r => r.verdict === 'allow').map(name);
            const parts = [];
            if (cant.length) parts.push((one ? 'This device can\'t reach ' : 'These devices can\'t reach ') + join(cant, 'or') + '.');
            if (can.length) parts.push((one ? 'This device can still reach ' : 'These devices can still reach ') + join(can, 'and') + '.');
            const inbound = rows.find(r => r.key === 'inbound');
            if (inbound) {
                parts.push(inbound.verdict === 'allow'
                    ? 'Your other networks can still connect to ' + (one ? 'this device.' : 'these devices.')
                    : 'Your other networks can\'t connect to ' + (one ? 'this device.' : 'these devices.'));
            }
            return parts.join(' ');
        },

        // Only while the neighbour block is on. Otherwise the "What no
        // firewall rule can stop" box below says the same thing at full size,
        // with what to do about it, and saying it twice was noise.
        pathNote() {
            if (!this.neighbourBlockActive()) return '';
            return 'Devices on the same network talk to each other directly, ' +
                   'without going through your gateway, so firewall rules can\'t ' +
                   'block that. The neighbour block works on your switches ' +
                   'instead, which is how it reaches that traffic.';
        },

        // ---- the selected devices' own network settings ----

        // 'all' | 'some' | 'none' of the selected devices sit on a network
        // with this setting. Unknown (null) counts as not set.
        netFact(key) {
            const cs = this.selectedClients();
            if (!cs.length) return 'none';
            const n = cs.filter(c => c[key] === true).length;
            return n === 0 ? 'none' : (n === cs.length ? 'all' : 'some');
        },

        networkSettingsNote() {
            const mixed = ['network_isolated', 'network_internet_off', 'network_device_isolation']
                .some(k => this.netFact(k) === 'some');
            return mixed
                ? 'Some of the selected devices are on networks with their own settings ' +
                  '(isolated, no internet, or device isolation) that block more than ' +
                  'shown here.'
                : '';
        },

        // A preset that cannot deliver what its name promises, because the
        // device's network has already taken that access away.
        presetConflicts() {
            const p = this.currentPreset();
            if (!p) return [];
            const one = this.selectedMacs.length <= 1;
            const out = [];
            if (p.effects.internet === 'allow' && this.netFact('network_internet_off') !== 'none') {
                out.push((one ? 'This device\'s network has' : 'Some of these devices are on networks with') +
                    ' internet turned off on the Networks tab, so ' + p.label +
                    ' can\'t give ' + (one ? 'this device' : 'those devices') + ' internet access.');
            }
            if (p.effects.networks === 'allow' && this.netFact('network_isolated') !== 'none') {
                out.push((one ? 'This device\'s network is' : 'Some of these devices are on networks that are') +
                    ' isolated on the Networks tab, so ' + p.label + ' can\'t let ' +
                    (one ? 'this device' : 'those devices') + ' reach your other networks, only ' +
                    'other devices on the same network.');
            }
            return out;
        },

        // ---- neighbour block (switch ACL pair) ----

        neighbourOffered() {
            const p = this.currentPreset();
            return !!(p && p.neighbour_block);
        },

        // False only when the controller says NO switch on the site supports
        // switch ACLs. Unknown (null) still offers it; the server re-checks.
        neighbourSupported() {
            return this.state.switch_acl_supported !== false;
        },

        // Quarantine includes the neighbour block; no checkbox.
        neighbourAlways() {
            const p = this.currentPreset();
            return !!(p && p.neighbour_always);
        },

        neighbourBlockActive() {
            if (!this.neighbourOffered() || !this.neighbourSupported()) return false;
            return this.neighbourAlways() || this.blockNeighbours;
        },

        // Whether your other networks can still start connections to it. Fixed
        // by the preset; only Quarantine says no.
        inboundAllowed() {
            const p = this.currentPreset();
            return !p || p.inbound !== false;
        },

        // Wording for the neighbour section, singular or plural, for the
        // checkbox (Internet only) or the fixed panel (Quarantine).
        neighbourText() {
            const many = this.selectedMacs.length > 1;
            const where = many
                ? 'the result depends on where each device is connected. House Arrest checks each one and shows the result below.'
                : 'the result depends on where this device is connected. House Arrest checks and shows the result below.';
            const limits = 'This block only works on UniFi switch models that support it, so ' + where;
            if (this.neighbourAlways()) {
                return {
                    title: 'Other devices on the same network are blocked too',
                    body: (many
                        ? 'Quarantine also blocks traffic between these devices and the other devices on their networks, in both directions. The rest of each network is not changed: those other devices can still reach each other. '
                        : 'Quarantine also blocks traffic between this device and the other devices on the same network, in both directions. The rest of the network is not changed: those other devices can still reach each other. ') + limits,
                    unsupported: 'None of your UniFi switches support this, so other devices on the same network can still reach ' +
                        
                        (many ? 'these devices' : 'this device') + '. Giving ' + (many ? 'these devices a VLAN' : 'this device a VLAN') +
                        ' of ' + (many ? 'their' : 'its') + ' own in UniFi removes those neighbours.',
                };
            }
            return {
                title: many
                    ? 'Also block these devices from the other devices on their networks'
                    : 'Also block this device from the other devices on its network',
                body: (many
                    ? 'Blocks traffic between these devices and the other devices on their networks, in both directions, so casting or printing to or from these devices also stops working. The rest of each network is not changed: those other devices can still reach each other. To block every device on a network from every other, use Device isolation on the Networks tab. '
                    : 'Blocks traffic between this device and the other devices on its network, in both directions, so casting or printing to or from this device also stops working. The rest of the network is not changed: those other devices can still reach each other. To block every device on a network from every other, use Device isolation on the Networks tab. ') + limits,
                unsupported: 'None of your UniFi switches support this, so this option isn\'t available. For Wi-Fi devices, turn on Wi-Fi client isolation for their network instead.',
            };
        },

        // One coverage verdict per selected device, from the picker data, so
        // the choice is made knowing how much of it will actually hold.
        neighbourCoverage() {
            return this.selectedClients().map(c => ({
                mac: c.mac,
                name: c.name || c.mac,
                status: c.neighbour_coverage || 'unknown',
                dns: c.neighbour_dns_note || '',
                note: c.neighbour_coverage_note ||
                      'UniFi doesn\'t currently know where this device is connected (it may be offline), so House Arrest can\'t tell how well the neighbour block will work.',
            }));
        },

        coverageLabel(status) {
            return {
                covered: 'Fully blocked',
                partial: 'Partly blocked',
                none: 'Not blocked',
                unknown: 'Unknown',
            }[status] || 'Unknown';
        },

        canReview() {
            return this.selectedMacs.length > 0;
        },

        reviewHint() {
            return 'Review first. Nothing reaches your gateway until you apply.';
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
            const all = this.preview || [];
            const sw = all.filter(p => p.acl_index !== undefined).length;
            const fw = all.length - sw;
            let t = 'Review: ' + fw + (fw === 1 ? ' policy' : ' policies') + ' for your gateway';
            if (sw) t += ' and ' + sw + ' rules for your switches';
            return t;
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
                if (pol.acl_index !== undefined) {
                    lines.push('Switch rule "' + pol.name + '" — ' +
                        (pol.action === 'ALLOW' ? 'keeps the gateway reachable' : 'blocks the device\'s neighbours'));
                } else {
                    lines.push('Policy "' + pol.name + '" at index ' + pol.index);
                }
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
                        allow_inbound: this.inboundAllowed(),
                        // Quarantine applies it server-side; only Internet
                        // only sends the checkbox.
                        block_neighbours: !this.neighbourAlways() && this.neighbourBlockActive(),
                        dry_run: true
                    })
                });
                const data = await res.json();
                if (!res.ok || data.error) {
                    this.message = { kind: 'danger', text: data.detail || data.error || 'Review failed' };
                    return;
                }
                this.preview = data.payloads;
                this.previewCaveats = data.caveats || [];
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
                        allow_inbound: this.inboundAllowed(),
                        // Quarantine applies it server-side; only Internet
                        // only sends the checkbox.
                        block_neighbours: !this.neighbourAlways() && this.neighbourBlockActive(),
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
                              data.created.length + (data.created.length === 1 ? ' rule' : ' rules') + ' written.'
                    };
                    this.preview = null;
                    this.selectedMacs = [];
                    this.labelTouched = false;
                    this.label = '';
                    this.networkId = '';
                    this.blockNeighbours = false;
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
