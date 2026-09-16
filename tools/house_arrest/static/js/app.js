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
        loading: true,
        previewing: false,
        applying: false,
        state: { connected: false, arrests: [], health: [], custom_policy_count: 0, total_policy_count: 0 },
        clients: [],
        networks: [],
        networkPresets: [],
        presets: [],
        pathLabels: {},
        inspection: null,
        openBlocked: null,
        blockedFlows: [],
        blockedLoading: false,
        // network isolation
        isoNetworkId: '',
        isoPreset: '',
        isoPreview: null,
        isoPreviewing: false,
        isoApplying: false,
        error: null,
        message: null,

        // lockdown form
        preset: '',
        selectedMac: '',
        label: '',
        networkId: '',
        preview: null,

        async init() {
            this.presets = this.readJson('ha-presets', []);
            this.pathLabels = this.readJson('ha-path-labels', {});
            this.networkPresets = this.readJson('ha-network-presets', []);
            if (this.networkPresets.length) this.isoPreset = this.networkPresets[0].value;
            if (this.presets.length) this.preset = this.presets[0].value;

            await this.refresh();
            this.loadNetworks();
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

        async isoDryRun() {
            this.message = null;
            this.isoPreviewing = true;
            try {
                const res = await fetch('api/isolate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
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
                this.isoPreview = data.payloads;
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
                    headers: { 'Content-Type': 'application/json' },
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
                    this.message = {
                        kind: 'ok',
                        text: (net ? net.name : 'Network') + ' isolated — ' +
                              data.created.length + ' policies written.'
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

        async releaseNetwork(label) {
            this.message = null;
            const res = await fetch('api/release', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ label: label, kind: 'network', dry_run: false })
            });
            const data = await res.json();
            if (data.error) {
                this.message = { kind: 'danger', text: data.error };
            } else {
                this.message = {
                    kind: 'ok',
                    text: 'Released ' + label + ' — ' + data.deleted.length + ' policies removed.'
                };
                await this.refresh(true);
                this.loadInspection();
            }
        },

        async toggleBlocked(label) {
            if (this.openBlocked === label) { this.openBlocked = null; return; }
            this.openBlocked = label;
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
                /* quarantine stays unavailable rather than silently wrong */
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
            return ['internet', 'networks', 'peers'].map(key => ({
                key,
                label: this.pathLabels[key] || key,
                verdict: effects[key],
                fixed: key === 'peers'
            }));
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
            const p = this.currentPreset();
            if (p && p.requires_network) {
                const n = this.networks.find(x => x.id === this.networkId);
                const where = n ? n.name + ' (VLAN ' + n.vlan + ')' : 'the network you pick';
                return 'Moving the device to ' + where + ' does not stop it talking to ' +
                       'whatever else lives there — that traffic never passes the gateway. ' +
                       'Pick a network with isolation on if it should be alone.';
            }
            return 'Devices on the same VLAN talk to each other without passing the ' +
                   'gateway, so no firewall policy can separate them. UniFi can do it ' +
                   'at the switch, via Device Isolation on the network — but that ' +
                   'applies to every device on that VLAN, not just this one. To ' +
                   'change it for this device alone, use Quarantine and move it.';
        },

        canReview() {
            if (!this.selectedMac) return false;
            const p = this.currentPreset();
            if (p && p.requires_network && !this.networkId) return false;
            return true;
        },

        reviewHint() {
            const p = this.currentPreset();
            if (p && p.requires_network && !this.networkId) {
                return 'Choose a VLAN to move the device into first.';
            }
            return 'Review first — nothing reaches your gateway until you apply.';
        },

        // ---- form ----

        selectedClient() {
            return this.clients.find(c => c.mac === this.selectedMac) || null;
        },

        onDeviceChange() {
            const c = this.selectedClient();
            this.preview = null;
            this.message = null;
            if (c) this.label = c.name || c.mac;
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
            if (p && p.requires_network) {
                const n = this.networks.find(x => x.id === this.networkId);
                if (n) lines.push('Moved to ' + n.name + ' (VLAN ' + n.vlan + ')');
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
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        preset: this.preset,
                        macs: [this.selectedMac],
                        label: this.label,
                        network_id: this.networkId || null,
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
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        preset: this.preset,
                        macs: [this.selectedMac],
                        label: this.label,
                        network_id: this.networkId || null,
                        dry_run: false
                    })
                });
                const data = await res.json();
                if (data.error) {
                    this.message = { kind: 'danger', text: data.error };
                } else {
                    this.message = data.move_note
                        ? { kind: 'warn', text: this.label + ' — ' + data.move_note }
                        : {
                            kind: 'ok',
                            text: this.label + ' is under house arrest — ' +
                                  data.created.length + ' policies written to your gateway.'
                          };
                    this.preview = null;
                    this.selectedMac = '';
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
                headers: { 'Content-Type': 'application/json' },
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
