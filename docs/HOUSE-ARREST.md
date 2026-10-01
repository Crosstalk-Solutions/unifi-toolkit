# House Arrest

Lock a device or a whole network down using UniFi's zone-based firewall.
Wired or wireless, reversible in one click, and honest about exactly what is
and is not being blocked.

House Arrest is three tools sharing one page:

| Tool | What it does |
|---|---|
| **Networks** | An editable table of your VLANs (network isolation, device isolation, internet access, mDNS, DNS), plus per-SSID Wi-Fi client isolation |
| **DNS Lockdown** | Force chosen networks to use only the DNS servers you approve, and block every other DNS server |
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
- A lockdown is re-checked on every refresh. If one of its rules stops
  working, because the device's MAC changed, someone turned the rule off in
  the UniFi UI, or the rule was deleted, the dashboard says so instead of
  showing a green dot.
- Known limitations are stated in the UI next to the claims they qualify.
  They are also collected below.

## Networks tab

A table of your VLANs showing each network's firewall zone, network
isolation, device isolation, internet access, mDNS forwarding, and the DNS
servers DHCP hands out. Cells marked with a pencil can be changed right from
the table. Each change opens a confirm dialog with a diagram of how the
network will be set up after you confirm.

- **Network isolation** and **Internet access** change the same settings you
  would find in UniFi under Settings, Networks. House Arrest and the UniFi UI
  always show the same value for them.
- **Device isolation** stops wired devices on a network from reaching each
  other. It is the same setting as Device Isolation (ACL) in UniFi. Device
  isolation only works on UniFi switch models that support MAC-based access
  control lists (ACLs), and only for traffic that passes through one of those
  switches. House Arrest attempts to determine whether your switches are
  compatible, and shows "Not supported" in this column if none of them are.
- **mDNS** is a single site-wide list in UniFi (the Gateway mDNS Proxy
  scope). Turning mDNS on or off for one network here adds or removes it from
  that shared list, and the confirm dialog says so before you apply it.
- **DNS** is read-only in the table. Change it from the DNS Lockdown tab.

**Wi-Fi client isolation** is listed below the table, one row per SSID. It
stops wireless devices on the same SSID from reaching each other. It has no
effect on wired devices, so use Device isolation for those.

## DNS Lockdown tab

DNS Lockdown lets devices on the networks you pick use only the DNS servers
you approve, and blocks every other DNS server.

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
- Public DNS servers such as 1.1.1.1 can be approved just like one on your
  own network.
- Networks already under a DNS lockdown are greyed out in the picker.
  Stacking a second lockdown on top of the first is refused rather than
  silently doubled up.

### What DNS Lockdown cannot stop: DNS-over-HTTPS

DoH is DNS wrapped in ordinary HTTPS on port 443. At the firewall it is
indistinguishable from any other web traffic, so there is no rule this tool
(or any port-based firewall) can write that blocks DoH without blocking the
web itself. A browser with "secure DNS" turned on, or a device with a DoH
resolver built in, can resolve names right past a DNS lockdown.

Blocking DoH by destination is a losing game: it means maintaining a list of
every DoH provider's addresses, the list is never complete, and popular
providers share addresses with regular web services. House Arrest does not
pretend to do this.

What actually works:

- Turn off secure DNS in the browser or app itself (Chrome, Edge, and
  Firefox all have a setting for it).
- For a device you don't trust to behave, don't fight its resolver. Use a
  Devices-tab preset that cuts its internet access entirely. If the device
  needs to reach one specific service, write that allow rule yourself in
  UniFi. House Arrest never creates allow rules on the Devices tab, because
  an allow rule can quietly reopen a network you isolated.
- Some resolvers and firewalls handle Firefox specifically through its
  canary domain (`use-application-dns.net`); that only affects Firefox, and
  only when Firefox chooses to honor it.

The UI states this limitation on the DNS Lockdown tab itself, so nobody has
to find it here first.

## Devices tab

Pick one or more devices (search by name, IP, or MAC), then choose a preset:

| Preset | Internet | Your other networks | Same-VLAN neighbours |
|---|---|---|---|
| **Full lockdown** | Blocked | Blocked | Still reachable, unless you turn on the neighbour block |
| **Internet only** | Allowed | Blocked | Still reachable, unless you turn on the neighbour block |
| **LAN only** | Blocked | Allowed | Still reachable |

**"Let other devices still reach this device"** is on by default. With it
on, the locked device can't start connections to anything its preset
blocks, but it can still answer when another device contacts it, so a
camera or smart bulb stays usable. Untick it to also stop devices on your
other networks from starting connections to it.

**"Also cut it off from devices on its own network"** (the neighbour block)
is offered with Full lockdown and Internet only. It stops the device and the
other devices on its VLAN from reaching each other in either direction,
which no firewall rule can do. The preset still applies as usual, so a
device under Internet only keeps its internet access.

The neighbour block uses the same switch capability as Device isolation. It
only works on UniFi switch models that support MAC-based ACLs, and only for
traffic that passes through one of those switches. House Arrest attempts to
work out where each selected device is connected, and shows one result per
device before you apply:

- **Fully blocked**: every path between the device and its neighbours
  passes through a switch that can block it.
- **Partly blocked**: some neighbours connect to the device through a switch
  that can't block it, so those neighbours can still reach it.
- **Not blocked**: none of the switches between the device and its
  neighbours can block it.
- **Unknown**: UniFi doesn't currently know where the device is connected,
  usually because it is offline.

If the device gets its DNS from a server on its own network, such as a
Pi-hole, the neighbour block still lets the device reach that server, so
websites and apps keep loading by name. Switch rules can't filter by port, so
the device can reach that DNS server on any port, not only DNS. If UniFi
doesn't know the DNS server's MAC address (usually because it's offline),
House Arrest won't apply the neighbour block, because the device would lose
DNS.

If none of your switches support ACLs, the neighbour block is greyed out.
While it is on, casting, printing, and anything else between the device and
its neighbours stop working too.

The **blocked traffic view** shows what each lockdown stopped in the last 24
hours. It only counts traffic blocked by House Arrest's own rules, never
blocks from your other firewall rules.

## Known limitations

These were all measured on real hardware, and each one is stated in the UI
next to the feature it qualifies. Collected here:

- **No firewall rule can block traffic between devices on the same VLAN.**
  That traffic never passes through the gateway. To block it, move the
  device to its own VLAN, turn on Wi-Fi client isolation for its SSID
  (wireless devices), or use Device isolation or the neighbour block (wired
  devices, on switches that support ACLs). Two wired devices plugged into
  the same switch that doesn't support ACLs can still reach each other.
- **Connections already open keep running** when a lockdown is applied. The
  gateway's connection tracking lets established sessions finish. New
  connections are blocked immediately.
- **DNS-over-HTTPS (port 443) is not covered** by DNS Lockdown, and cannot
  be. At this layer it looks like any other HTTPS traffic. See the DoH
  section under DNS Lockdown above for what actually works.
- **DNS Lockdown can't block a DNS server on the device's own VLAN.**
  Queries to it never pass through the gateway.
- **The gateway itself stays reachable.** DHCP and the gateway's own
  services are never blocked, so a locked-down device keeps its address.
- **The gateway decides the order rules run in.** If one of your own allow
  rules runs before a House Arrest block, your rule wins and the traffic gets
  through. The Devices tab warns you when it detects this, but it's worth
  checking the rule order in the UniFi UI as well.

## Troubleshooting

- **A lockdown shows "not enforcing".** The device's MAC probably changed;
  phones and laptops randomize MACs per network. Release and re-apply with
  the new MAC, or turn off MAC randomization for your own network on that
  device.
- **A lockdown shows "disabled in UniFi".** One or more of its rules was
  toggled off in the UniFi UI. Re-enable it there, or release and re-apply.
- **Devices ignore your approved resolvers entirely, and nothing here
  shows red.** Check Settings, CyberSecure in UniFi. With Encrypted DNS
  enabled, the gateway intercepts DNS and resolves through its own encrypted
  upstreams, so your Pi-hole or AdGuard never sees the queries no matter
  what the firewall rules say. Content Filter and Ad Blocking also put the
  gateway in the resolution path for covered networks. The DNS Lockdown tab
  warns about all three when it can read those settings.
- **A network lost DNS entirely after a lockdown.** Its DHCP was advertising
  a resolver the rules now block, and devices were still using it. Tick
  "Also point DHCP at these resolvers" and wait for lease renewal, or
  release the lockdown.
- When reporting an issue, use the **Debug Info** link in the dashboard
  footer and copy it into the report. It includes the gateway model,
  firmware, and toolkit version, which is the first thing needed to diagnose
  anything.
