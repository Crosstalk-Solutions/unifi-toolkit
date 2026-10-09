# House Arrest

Lock a device or a whole network down using UniFi's zone-based firewall.
Wired or wireless, reversible in one click, and honest about exactly what is
and is not being blocked.

House Arrest is three tools sharing one page:

| Tool | What it does |
|---|---|
| **Networks** | An editable table of your VLANs (network isolation, device isolation, internet access, mDNS, DNS), plus per-SSID Wi-Fi client isolation |
| **DNS Lockdown** | Force chosen networks to use only the DNS servers you approve, and block every other DNS server |
| **Devices** | Per-device lockdown presets by MAC address: Internet only, LAN only, No internet, or Quarantine |

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
- After a DNS Lockdown or an Internet only lockdown is applied, the stored
  rule order is read back and verified. If the gateway placed an allow rule
  after the block it has to beat, which would cut DNS, House Arrest undoes
  the change automatically.
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

**Wi-Fi client isolation** is listed below the table, one row per SSID.
Client isolation stops wireless devices on the same SSID from reaching each
other. Wired devices aren't affected, so use Device isolation for those.

## DNS Lockdown tab

DNS Lockdown lets devices on the networks you pick use only your approved
DNS servers, and blocks every other DNS server.

**WARNING: DNS Lockdown will break any device with a hardcoded DNS server.**
That is usually why you want it, but check the "What each network hands out
now" table before applying.

Options and safeguards:

- **Also point DHCP at your approved DNS servers.** Recommended. DHCP tells
  devices which DNS server to use, and DNS Lockdown decides which DNS servers
  devices are allowed to use. If DHCP keeps handing out a DNS server that DNS
  Lockdown blocks, devices on that network lose DNS. The tab highlights this
  conflict before you apply.
- **Also block DNS-over-TLS (port 853).** A device that can't reach port 853
  usually falls back to ordinary DNS on port 53, which DNS Lockdown then
  controls.
- Public DNS servers such as 1.1.1.1 can be approved just like one on your
  own network.
- Networks that already have a DNS Lockdown are greyed out in the picker.
  A second DNS Lockdown on the same network is refused rather than silently
  doubled up.
- If a device on one of these networks is already under a Devices-tab
  lockdown, House Arrest re-creates that device's block after the new DNS
  rules, so the device keeps reaching your approved DNS servers. The result
  message says which devices were moved.

### What DNS Lockdown cannot stop: DNS-over-HTTPS

DoH is DNS wrapped in ordinary HTTPS on port 443. At the firewall it is
indistinguishable from any other web traffic, so there is no rule this tool
(or any port-based firewall) can write that blocks DoH without blocking the
web itself. A browser with "secure DNS" turned on, or a device with DoH
built in, can look up names right past a DNS Lockdown.

Blocking DoH by destination is a losing game: it means maintaining a list of
every DoH provider's addresses, the list is never complete, and popular
providers share addresses with regular web services. House Arrest does not
pretend to do this.

What actually works:

- Turn off secure DNS in the browser or app itself (Chrome, Edge, and
  Firefox all have a setting for it).
- For a device you don't trust to behave, don't fight its DNS settings. Use
  a Devices-tab preset that cuts its internet access entirely (No internet or
  Quarantine). If the device needs to reach one specific service, write that
  allow rule yourself in UniFi. The Devices tab only ever writes one kind of
  allow rule, the narrow DNS rule described under "DNS under Internet only"
  below, because a broader allow rule could quietly reopen a network you
  isolated.
- Some DNS servers and firewalls handle Firefox specifically through its
  canary domain (`use-application-dns.net`). That only affects Firefox, and
  only when Firefox chooses to honor it.

The UI states this limitation on the DNS Lockdown tab itself, so nobody has
to find it here first.

## Devices tab

Pick one or more devices (search by name, IP, or MAC), then choose a preset.
The presets run from most to least permissive:

| Preset | This device can reach the internet | This device can reach your other networks | Your other networks can reach this device | Other devices on the same network |
|---|---|---|---|---|
| **Internet only** | Allowed | Blocked | Allowed | Allowed, or blocked with the checkbox |
| **LAN only** | Blocked | Allowed | Allowed | Allowed |
| **No internet** | Blocked | Blocked | Allowed | Allowed |
| **Quarantine** | Blocked | Blocked | Blocked | Blocked, on supported switches only |

The same grid is on the page under **Compare the presets**. **What this
blocks** sums up the preset you picked in one sentence, and opens to show a
diagram.

"Your other networks can reach this device" means devices on your other
networks can start a connection to this device, on any port, so the app or
web page you control it with keeps working. This device can only answer
them. Quarantine is the preset that blocks this too.

Lockdowns made with earlier versions keep working and can still be
released. Earlier versions had a "Let other devices still reach this
device" checkbox and a preset called Full lockdown, which is now No
internet.

### Other devices on the same network

No firewall rule can block traffic between devices on the same network,
because that traffic never passes through the gateway. House Arrest blocks it
with switch rules instead (the neighbour block). **Quarantine** always
includes the neighbour block. **Internet only** offers it as a checkbox,
**Also block this device from the other devices on its network**, because it
has a cost: casting and printing between this device and its neighbours stop
working. The neighbour block also stops this device announcing itself for
casting (AirPlay and Google Cast), so devices on your other networks stop
finding it too, even with mDNS forwarding turned on.

The neighbour block applies only to the devices you select. The other devices
on the network can still reach each other. To block every device on a network
from every other, use Device isolation on the Networks tab.

The neighbour block uses the same switch capability as Device isolation. It
only works on UniFi switch models that support MAC-based ACLs, and only for
traffic that passes through one of those switches. House Arrest attempts to
work out where each selected device is connected, and shows one result per
device before you apply:

- **Fully blocked**: every path between this device and its neighbours
  passes through a switch that can block it.
- **Partly blocked**: some neighbours connect to this device through a
  switch that can't block it, so those neighbours can still reach this
  device.
- **Not blocked**: none of the switches between this device and its
  neighbours can block it.
- **Unknown**: UniFi doesn't currently know where this device is connected,
  usually because it is offline.

If none of your switches support ACLs, the checkbox is greyed out, and
Quarantine says that other devices on the same network can still reach this
device.

### DNS under Internet only

Internet only keeps this device's DNS working, including when its DNS server
is on another network:

- If the network hands out a DNS server on **another VLAN** (a Pi-hole on
  your main network, for example), Internet only adds one narrow allow rule:
  this device to those DNS servers, on port 53 only. The rule is created
  before the block, and its position is checked after applying. It is never
  added on an isolated network, because there it would punch through the
  isolation. On an isolated network, DNS to another VLAN only works through
  a DNS Lockdown, and the review step says so.
- If the DNS server is on **the same network** and you tick the neighbour
  block, the neighbour block still lets this device reach that DNS server.
  Switch rules can't filter by port, so this device can reach that DNS server
  on any port, not only DNS. If UniFi doesn't know the DNS server's MAC
  address (usually because it's offline), House Arrest won't apply the
  neighbour block, because this device would lose DNS.

Quarantine adds none of these DNS rules. A quarantined device can still look up names, through the gateway and through your approved DNS servers if its network has a DNS Lockdown, but it can't connect to anything on the internet.

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
- **Connections already open keep running** when a lockdown is applied,
  except under Quarantine. The gateway's connection tracking lets established
  sessions finish, and new connections are blocked immediately. Quarantine's
  rules match every connection, not just new ones, so Quarantine cuts open
  connections too.
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
  toggled off in the UniFi UI. Re-enable the rule there, or release the
  lockdown and apply it again.
- **A lockdown says it is blocking the device's DNS.** The lockdown's block
  runs before a rule meant to let the device reach its DNS servers, for
  example after rules were reordered in UniFi. Release the lockdown and
  apply it again, which puts the rules back in the right order.
- **Devices ignore your approved DNS servers entirely, and nothing here
  shows red.** Check Settings, CyberSecure in UniFi. With Encrypted DNS
  enabled, the gateway intercepts DNS and sends it to its own encrypted DNS
  servers, so your Pi-hole or AdGuard never sees the queries, whatever the
  firewall rules say. Content Filter and Ad Blocking also put the
  gateway in the resolution path for covered networks. The DNS Lockdown tab
  warns about all three when it can read those settings.
- **A network lost DNS entirely after a DNS Lockdown.** Its DHCP was handing
  out a DNS server that DNS Lockdown now blocks, and devices were still using
  it. Tick "Also point DHCP at your approved DNS servers" and wait for the
  DHCP leases to renew, or release the DNS Lockdown.
- When reporting an issue, use the **Debug Info** link in the dashboard
  footer and copy it into the report. It includes the gateway model,
  firmware, and toolkit version, which is the first thing needed to diagnose
  anything.
