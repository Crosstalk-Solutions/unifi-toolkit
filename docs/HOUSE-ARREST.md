# House Arrest

Lock a device or a whole network down using UniFi's zone-based firewall — wired
or wireless, reversible in one click, and honest about exactly what is and is
not being blocked.

House Arrest is three tools sharing one page:

| Tool | What it does |
|---|---|
| **Networks** | An editable audit matrix of your VLANs (isolation, internet access, mDNS, DNS), plus per-SSID Wi-Fi client isolation |
| **DNS Lockdown** | Force chosen networks to use only approved DNS resolvers and block everything else answering DNS |
| **Devices** | Per-device lockdown presets by MAC address: Full lockdown, Internet only, or LAN only |

## Requirements

- A **UniFi OS console with the zone-based firewall** (UniFi Network 9.0 or
  later on UDM/UCG-class gateways). House Arrest writes zone-based firewall
  policies; consoles still on the legacy ruleset are not supported.
- **Stable (GA) firmware.** Early Access firmware changes APIs without notice
  and is not supported anywhere in the toolkit.
- The toolkit connected with an **API key** (Settings → Admins & Users →
  your admin → API key).

## The design rule everything follows

**House Arrest never claims protection it is not delivering.** That one rule
explains most of what you'll see in the UI:

- Every change is **previewed before it is applied** (dry-run first, always).
- After applying a DNS lockdown, the stored rule order is **read back and
  verified** — if the gateway placed the allow rule after the blocks (which
  would kill DNS on those networks), everything is rolled back automatically.
- Every rule House Arrest creates carries a `[HouseArrest]` marker in its
  description. **Release deletes exactly those rules and refuses to touch
  anything else** — it can never delete a rule you made yourself.
- A lockdown is re-checked on every refresh. If a rule stops matching (the
  device's MAC changed), gets **disabled in the UniFi UI**, or disappears, the
  dashboard says so instead of showing a comforting green dot.
- Known limitations are stated next to the claims they qualify, not buried
  here in the docs. (They're also listed below, because docs should be honest
  too.)

## Networks tab

An audit matrix of your VLANs: firewall zone, network isolation, internet
access, mDNS forwarding, and the DNS servers DHCP hands out. Cells marked with
a pencil can be changed right from the table — each change gets a confirm
dialog showing a diagram of the exact state that click lands the network in.

- **Network isolation** and **Internet access** write UniFi's own per-network
  settings (the same switches as Settings → Networks), so House Arrest and
  the UniFi UI can never disagree about them.
- **mDNS** is one site-wide list in UniFi (the Gateway mDNS Proxy scope).
  Toggling it here adds or removes that network from the shared list — the
  dialog says so explicitly.
- **DNS** is read-only in the matrix; change it from the DNS Lockdown tab.

**Wi-Fi client isolation** (below the matrix) stops devices on an SSID from
reaching each other. It is the only control in the toolkit that touches
traffic between neighbours on the same VLAN — firewall policies never see
that traffic. Wireless clients only; wired devices are unaffected.

## DNS Lockdown tab

Allow only specific DNS servers of your choosing and block all non-authorized
DNS resolution on the networks you pick.

**WARNING: this will break any device with hardcoded DNS server settings** —
that's the point, but it means you should check the "what each network hands
out now" table before applying.

Options and safeguards:

- **Also point DHCP at these resolvers** — recommended. DHCP decides which
  resolver devices are *told* to use; the firewall rules decide which they
  *may* use. If DHCP keeps advertising a resolver the rules block, devices on
  that network lose DNS at their next lookup. The tab highlights exactly this
  conflict before you apply.
- **Also block DNS-over-TLS (port 853)** — a device that can't reach 853
  usually falls back to plain DNS on 53, which the rules then catch.
- Public resolvers (like 1.1.1.1) are handled correctly: the allow rule is
  written on the internet side, where that traffic actually flows.
- Networks already under a DNS lockdown are greyed out in the picker —
  stacking a second lockdown on the first is refused, not silently doubled.

## Devices tab

Select one or more devices (searchable by name, IP, or MAC — several devices
can share one lockdown) and choose a preset:

| Preset | Internet | Your other networks | Same-VLAN neighbours |
|---|---|---|---|
| **Full lockdown** | Blocked | Blocked | Still reachable |
| **Internet only** | Allowed | Blocked | Still reachable |
| **LAN only** | Blocked | Allowed | Still reachable |

**"Let other devices still reach this device"** (on by default) lets the
locked device answer when something contacts it — so a camera or smart bulb
stays usable — while still blocking everything the device starts itself.
Untick it for absolute isolation in both directions.

The **blocked traffic view** shows what each lockdown actually stopped in the
last 24 hours, attributed to House Arrest's own rules by ID — another rule's
blocks are never counted.

### Why there is no "move it to another VLAN" preset

An earlier beta had a Quarantine preset that moved the device to a VLAN using
UniFi's per-client network override. On wired clients that override was
measured **half-applying**: the device got an address on the new VLAN but had
no working connectivity at all, while the controller reported two different
locations for it. A quarantine whose outcome can't even be reported coherently
can't be verified, so the preset was removed. If a device needs its own VLAN,
assign it natively in UniFi (the switch port's network, or a dedicated Wi-Fi
network), then lock that VLAN down from the Networks and DNS tabs.

## Known limitations (measured, not guessed)

These are stated in the UI next to the features they qualify. Collected here:

- **Same-VLAN traffic cannot be filtered by any firewall rule.** Traffic
  between devices on the same VLAN never passes the gateway. The two real
  fixes: give the device a dedicated VLAN in UniFi, or (wireless only) turn on
  Wi-Fi client isolation for its SSID.
- **Connections already open keep running** when a lockdown is applied. The
  gateway's connection tracking lets established sessions finish; new
  connections are blocked immediately.
- **DNS-over-HTTPS (port 443) is not covered** by DNS Lockdown — it is
  indistinguishable from ordinary HTTPS at this layer.
- **A resolver on the device's own subnet can't be blocked** — queries to it
  never cross the gateway.
- **The gateway itself stays reachable** — DHCP and the gateway's own services
  are never blocked, so a locked-down device keeps its address.
- **Rule order is assigned by the gateway.** If one of your own ALLOW rules
  sits ahead of a House Arrest block in the same zone pair, it wins — the
  Devices tab warns when this is detected, and it's worth checking in the
  UniFi UI.

## Troubleshooting

- **A lockdown shows "not enforcing"** — the device's MAC probably changed
  (phones and laptops randomize MACs per network). Release and re-apply with
  the new MAC, or disable MAC randomization for your own network on that
  device. House Arrest flags this rather than pretending the old rule still
  works.
- **A lockdown shows "disabled in UniFi"** — one or more of its rules was
  toggled off in the UniFi UI. Re-enable it there, or release and re-apply.
- **A network lost DNS entirely after a lockdown** — its DHCP was advertising
  a resolver the rules now block, and devices were still using it. Tick
  "Also point DHCP at these resolvers" and wait for lease renewal, or release
  the lockdown. (Also worth knowing: if your approved resolvers all sit behind
  one switch, that switch is now a single point of failure for DNS on the
  locked networks.)
- When reporting an issue, use the dashboard footer's **Debug Info** →
  copy-to-clipboard — it includes the gateway model, firmware, and toolkit
  version, which is the first thing needed to diagnose anything.
