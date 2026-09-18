# House Arrest

Lock a device or a whole network down using UniFi's zone-based firewall.
Wired or wireless, reversible in one click, and honest about exactly what is
and is not being blocked.

House Arrest is three tools sharing one page:

| Tool | What it does |
|---|---|
| **Networks** | An editable audit matrix of your VLANs (isolation, internet access, mDNS, DNS), plus per-SSID Wi-Fi client isolation |
| **DNS Lockdown** | Force chosen networks to use only approved DNS resolvers and block everything else answering DNS |
| **Devices** | Per-device lockdown presets by MAC address: Full lockdown, Internet only, or LAN only |

## Requirements

- A **UniFi OS console with the zone-based firewall** (UniFi Network 9.0 or
  later on UDM and UCG-class gateways). House Arrest writes zone-based
  firewall policies, so consoles still on the legacy ruleset are not
  supported.
- **Stable (GA) firmware.** Early Access firmware changes APIs without
  notice and is not supported anywhere in the toolkit.
- The toolkit connected with an **API key** (Settings, Admins & Users, your
  admin, API key).

## The design rule everything follows

House Arrest never claims protection it is not delivering. That one rule
explains most of what you'll see in the UI:

- Every change is previewed before it is applied. You always get a dry run
  first.
- After a DNS lockdown is applied, the stored rule order is read back and
  verified. If the gateway placed the allow rule after the blocks, which
  would kill DNS on those networks, everything is rolled back automatically.
- Every rule House Arrest creates carries a `[HouseArrest]` marker in its
  description. Release deletes exactly those rules and refuses to touch
  anything else, so it can never delete a rule you made yourself.
- A lockdown is re-checked on every refresh. If a rule stops matching
  because the device's MAC changed, gets disabled in the UniFi UI, or
  disappears, the dashboard says so instead of showing a comforting green
  dot.
- Known limitations are stated in the UI next to the claims they qualify.
  They are also collected below.

## Networks tab

An audit matrix of your VLANs: firewall zone, network isolation, internet
access, mDNS forwarding, and the DNS servers DHCP hands out. Cells marked
with a pencil can be changed right from the table, and each change gets a
confirm dialog showing a diagram of the exact state that click lands the
network in.

- **Network isolation** and **Internet access** write UniFi's own
  per-network settings, the same switches as Settings, Networks. House
  Arrest and the UniFi UI can never disagree about them.
- **mDNS** is one site-wide list in UniFi (the Gateway mDNS Proxy scope).
  Toggling it here adds or removes that network from the shared list, and
  the dialog says so before you confirm.
- **DNS** is read-only in the matrix. Change it from the DNS Lockdown tab.

**Wi-Fi client isolation** sits below the matrix. It stops devices on a
Wi-Fi SSID from reaching each other, and it is the only setting in the
toolkit that can affect traffic between neighbours on the same VLAN.
Firewall policies never see that traffic. Wireless clients only; wired
devices are unaffected.

## DNS Lockdown tab

Allow only specific DNS servers of your choosing and block all
non-authorized DNS resolution on the networks you pick.

**WARNING: this will break any device with hardcoded DNS server settings.**
That is usually why you want it, but check the "what each network hands out
now" table before applying.

Options and safeguards:

- **Also point DHCP at these resolvers.** Recommended. DHCP decides which
  resolver devices are told to use, and the firewall rules decide which they
  may use. If DHCP keeps advertising a resolver the rules block, devices on
  that network lose DNS at their next lookup. The tab highlights exactly
  this conflict before you apply.
- **Also block DNS-over-TLS (port 853).** A device that can't reach 853
  usually falls back to plain DNS on 53, which the rules then catch.
- Public resolvers like 1.1.1.1 are handled correctly. The allow rule is
  written on the internet side, where that traffic actually flows.
- Networks already under a DNS lockdown are greyed out in the picker.
  Stacking a second lockdown on top of the first is refused rather than
  silently doubled up.

## Devices tab

Select one or more devices (searchable by name, IP, or MAC, and several
devices can share one lockdown), then choose a preset:

| Preset | Internet | Your other networks | Same-VLAN neighbours |
|---|---|---|---|
| **Full lockdown** | Blocked | Blocked | Still reachable |
| **Internet only** | Allowed | Blocked | Still reachable |
| **LAN only** | Blocked | Allowed | Still reachable |

**"Let other devices still reach this device"** is on by default. The
locked device can't start connections out, but it can still answer when
something contacts it, so a camera or smart bulb stays usable. Untick it for
absolute isolation in both directions.

The **blocked traffic view** shows what each lockdown actually stopped in
the last 24 hours, attributed to House Arrest's own rules by ID. Another
rule's blocks are never counted.

### Why there is no "move it to another VLAN" preset

An earlier beta had a Quarantine preset that moved the device to a VLAN
using UniFi's per-client network override. On wired clients that override
was measured half-applying: the device got an address on the new VLAN but
had no working connectivity at all, while the controller reported two
different locations for it. Since the outcome couldn't even be reported
coherently, it couldn't be verified either, so the preset was removed. If a
device needs its own VLAN, assign it natively in UniFi (the switch port's
network, or a dedicated Wi-Fi network), then lock that VLAN down from the
Networks and DNS tabs.

## Known limitations

These were all measured on real hardware, and each one is stated in the UI
next to the feature it qualifies. Collected here:

- **Same-VLAN traffic cannot be filtered by any firewall rule.** Traffic
  between devices on the same VLAN never passes the gateway. The two real
  fixes: give the device a dedicated VLAN in UniFi, or turn on Wi-Fi client
  isolation for its SSID (wireless only).
- **Connections already open keep running** when a lockdown is applied. The
  gateway's connection tracking lets established sessions finish. New
  connections are blocked immediately.
- **DNS-over-HTTPS (port 443) is not covered** by DNS Lockdown. At this
  layer it looks like any other HTTPS traffic.
- **A resolver on the device's own subnet can't be blocked.** Queries to it
  never cross the gateway.
- **The gateway itself stays reachable.** DHCP and the gateway's own
  services are never blocked, so a locked-down device keeps its address.
- **Rule order is assigned by the gateway.** If one of your own ALLOW rules
  sits ahead of a House Arrest block in the same zone pair, your rule wins.
  The Devices tab warns when it detects this, and it's worth checking in
  the UniFi UI.

## Troubleshooting

- **A lockdown shows "not enforcing".** The device's MAC probably changed;
  phones and laptops randomize MACs per network. Release and re-apply with
  the new MAC, or turn off MAC randomization for your own network on that
  device.
- **A lockdown shows "disabled in UniFi".** One or more of its rules was
  toggled off in the UniFi UI. Re-enable it there, or release and re-apply.
- **A network lost DNS entirely after a lockdown.** Its DHCP was advertising
  a resolver the rules now block, and devices were still using it. Tick
  "Also point DHCP at these resolvers" and wait for lease renewal, or
  release the lockdown. Also worth knowing: if your approved resolvers all
  sit behind one switch, that switch is now a single point of failure for
  DNS on the locked networks.
- When reporting an issue, use the **Debug Info** link in the dashboard
  footer and copy it into the report. It includes the gateway model,
  firmware, and toolkit version, which is the first thing needed to diagnose
  anything.
