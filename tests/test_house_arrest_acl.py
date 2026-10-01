"""
Tests for House Arrest's switch-ACL features: coverage verdicts, the Device
Isolation matrix cell, and the per-device neighbour block.

Pure functions only. The topology below is the one measured on a live console
on 2026-09-29 (see docs/house-arrest-design.md, "MEASURED 2026-09-29"):
Ultra -> Pro Max [ACL] -> Pro XG [ACL] -> gateway, and
U6+ AP -> Ultra 210W -> Industrial -> Pro Max.
"""
import pytest

from tools.house_arrest import policies as P


def _dev(mac, name, acl=False, uplink=None, dtype="usw", **extra):
    d = {"mac": mac, "name": name, "type": dtype,
         "switch_caps": {"max_custom_mac_acls": 256 if acl else 0}}
    if uplink:
        d["uplink"] = {"uplink_mac": uplink}
    d.update(extra)
    return d


GW = _dev("a8:9c:6c:90:e3:80", "UCG", dtype="udm",
          network_table=[{"mac": "a8:9c:6c:90:e3:85"}],
          ethernet_table=[{"mac": "a8:9c:6c:90:e3:80"}, {"mac": "a8:9c:6c:90:e3:86"}])
TOPOLOGY = [
    GW,
    _dev("00:00:00:00:00:01", "Pro XG", acl=True, uplink="a8:9c:6c:90:e3:80"),
    _dev("00:00:00:00:00:02", "Pro Max", acl=True, uplink="00:00:00:00:00:01"),
    _dev("00:00:00:00:00:03", "Ultra", uplink="00:00:00:00:00:02"),
    _dev("00:00:00:00:00:04", "Industrial", uplink="00:00:00:00:00:02"),
    _dev("00:00:00:00:00:05", "Ultra 210W", uplink="00:00:00:00:00:04"),
    _dev("00:00:00:00:00:06", "U6+", dtype="uap", uplink="00:00:00:00:00:05"),
    _dev("00:00:00:00:00:07", "Island switch"),   # no uplink, no ACL
]


class TestAclCoverage:
    def test_capability_comes_from_switch_caps(self):
        assert P.acl_capable({"switch_caps": {"max_custom_mac_acls": 128}})
        assert not P.acl_capable({"switch_caps": {"max_custom_mac_acls": 0}})
        assert not P.acl_capable({"switch_caps": {}})
        assert not P.acl_capable(None)

    def test_wired_on_capable_switch_is_covered(self):
        c = {"is_wired": True, "sw_mac": "00:00:00:00:00:02"}
        cov = P.client_coverage(c, TOPOLOGY)
        assert cov["status"] == P.COVERED
        assert cov["enforcer"] == "Pro Max"

    def test_wired_below_capable_switch_is_partial(self):
        c = {"is_wired": True, "sw_mac": "00:00:00:00:00:03"}
        cov = P.client_coverage(c, TOPOLOGY)
        assert cov["status"] == P.PARTIAL
        assert cov["enforcer"] == "Pro Max"
        assert "Ultra" in P.coverage_sentence(cov)

    def test_wifi_is_never_fully_covered(self):
        c = {"is_wired": False, "ap_mac": "00:00:00:00:00:06"}
        cov = P.client_coverage(c, TOPOLOGY)
        assert cov["status"] == P.PARTIAL
        assert "Wi-Fi client isolation" in P.coverage_sentence(cov)

    def test_no_capable_switch_anywhere_is_none(self):
        c = {"is_wired": True, "sw_mac": "00:00:00:00:00:07"}
        assert P.client_coverage(c, TOPOLOGY)["status"] == P.NOT_COVERED

    def test_unplaced_or_offline_is_unknown_not_none(self):
        assert P.client_coverage(None, TOPOLOGY)["status"] == P.UNKNOWN
        c = {"is_wired": True, "sw_mac": "ff:ff:ff:00:00:00"}
        assert P.client_coverage(c, TOPOLOGY)["status"] == P.UNKNOWN

    def test_unfollowable_path_is_unknown_not_none(self):
        # Measured 2026-09-29: an AP still named a since-removed switch as its
        # uplink. That must read "unknown", never "not covered".
        ap = _dev("00:00:00:00:00:20", "Shed AP", dtype="uap", uplink="de:ad:00:00:00:00")
        c = {"is_wired": False, "ap_mac": "00:00:00:00:00:20"}
        cov = P.client_coverage(c, TOPOLOGY + [ap])
        assert cov["status"] == P.UNKNOWN
        assert "full path" in P.coverage_sentence(cov)

    def test_uplink_loop_does_not_hang(self):
        a = _dev("00:00:00:00:00:0a", "A", uplink="00:00:00:00:00:0b")
        b = _dev("00:00:00:00:00:0b", "B", uplink="00:00:00:00:00:0a")
        c = {"is_wired": True, "sw_mac": "00:00:00:00:00:0a"}
        assert P.client_coverage(c, [a, b])["status"] == P.NOT_COVERED

    def test_network_counts(self):
        clients = {
            "m1": {"network_id": "n", "is_wired": True, "sw_mac": "00:00:00:00:00:02"},
            "m2": {"network_id": "n", "is_wired": True, "sw_mac": "00:00:00:00:00:03"},
            "m3": {"network_id": "other", "is_wired": True, "sw_mac": "00:00:00:00:00:02"},
        }
        counts = P.network_isolation_coverage("n", clients, TOPOLOGY)
        assert counts[P.COVERED] == 1 and counts[P.PARTIAL] == 1
        assert sum(counts.values()) == 2


NO_ACL_SITE = [GW,
               _dev("00:00:00:00:00:13", "Ultra", uplink="a8:9c:6c:90:e3:80"),
               _dev("00:00:00:00:00:16", "U6+", dtype="uap", uplink="00:00:00:00:00:13")]


class TestSiteSupport:
    def test_site_with_a_capable_switch(self):
        assert P.site_acl_capable(TOPOLOGY) is True

    def test_all_unifi_but_no_capable_switch(self):
        assert P.site_acl_capable(NO_ACL_SITE) is False
        c = {"is_wired": True, "sw_mac": "00:00:00:00:00:13"}
        assert P.client_coverage(c, NO_ACL_SITE)["status"] == P.NOT_COVERED

    def test_unreadable_devices_is_unknown_not_no(self):
        assert P.site_acl_capable([]) is None

    def test_cell_not_supported_is_grey_and_locked(self):
        cell = P.device_isolation_cell(False, None, site_supported=False)
        assert cell["label"] == "Not supported"
        assert cell["state"] == "neutral" and not cell["editable"]

    def test_cell_not_supported_even_if_switched_on_in_unifi(self):
        cell = P.device_isolation_cell(True, None, site_supported=False)
        assert cell["label"] == "Not supported"
        assert "turned on in UniFi" in cell["detail"]

    def test_matrix_passes_the_site_flag(self):
        nets = [{"_id": "n1", "name": "IoT", "vlan": 107, "purpose": "corporate"}]
        m = P.build_isolation_matrix(nets, [], device_isolation_ids=[],
                                     switch_acl_supported=False)
        assert m["rows"][0]["cells"]["device_isolation"]["label"] == "Not supported"


class TestSharedPort:
    def _clients(self, *entries):
        return {e["mac"]: e for e in entries}

    def test_shared_port_on_capable_switch_is_partial(self):
        tv = {"mac": "aa:00:00:00:00:01", "is_wired": True,
              "sw_mac": "00:00:00:00:00:02", "sw_port": 5}
        other = {"mac": "aa:00:00:00:00:02", "is_wired": True,
                 "sw_mac": "00:00:00:00:00:02", "sw_port": 5}
        cov = P.client_coverage(tv, TOPOLOGY, self._clients(tv, other))
        assert cov["status"] == P.PARTIAL and cov["shared_port"]
        sentence = P.coverage_sentence(cov)
        assert "another switch" in sentence and "virtual machines" in sentence

    def test_own_port_on_capable_switch_stays_covered(self):
        tv = {"mac": "aa:00:00:00:00:01", "is_wired": True,
              "sw_mac": "00:00:00:00:00:02", "sw_port": 5}
        other = {"mac": "aa:00:00:00:00:02", "is_wired": True,
                 "sw_mac": "00:00:00:00:00:02", "sw_port": 6}
        assert P.client_coverage(tv, TOPOLOGY, self._clients(tv, other))["status"] == P.COVERED

    def test_wifi_clients_never_count_as_port_sharers(self):
        tv = {"mac": "aa:00:00:00:00:01", "is_wired": True,
              "sw_mac": "00:00:00:00:00:02", "sw_port": 5}
        phone = {"mac": "aa:00:00:00:00:03", "is_wired": False,
                 "sw_mac": "00:00:00:00:00:02", "sw_port": 5}
        assert P.client_coverage(tv, TOPOLOGY, self._clients(tv, phone))["status"] == P.COVERED

    def test_network_counts_apply_the_shared_port_check(self):
        a = {"mac": "a1", "network_id": "n", "is_wired": True,
             "sw_mac": "00:00:00:00:00:02", "sw_port": 5}
        b = {"mac": "a2", "network_id": "n", "is_wired": True,
             "sw_mac": "00:00:00:00:00:02", "sw_port": 5}
        counts = P.network_isolation_coverage("n", self._clients(a, b), TOPOLOGY)
        assert counts[P.COVERED] == 0 and counts[P.PARTIAL] == 2


ZONES = [{"_id": "zi", "zone_key": "internal"}, {"_id": "ze", "zone_key": "external"},
         {"_id": "zg", "zone_key": "gateway"}]
IOT = {"_id": "iot", "name": "IoT", "ip_subnet": "192.168.107.1/24",
       "firewall_zone_id": "zi", "network_isolation_enabled": True}


def _allow(name, src, dst, **kw):
    p = {"name": name, "action": "ALLOW", "enabled": True, "predefined": False,
         "source": src, "destination": dst}
    p.update(kw)
    return p


class TestIsolationExceptions:
    def test_outbound_from_the_network(self):
        p = _allow("IoT to NAS", {"matching_target": "NETWORK", "network_ids": ["iot"], "zone_id": "zi"},
                   {"matching_target": "IP", "ips": ["192.168.200.12"], "zone_id": "zi", "port": "445"})
        out = P.isolation_exceptions(IOT, ZONES, [p])
        assert out == ['"IoT to NAS" (your rule, port 445)']

    def test_any_source_counts_for_every_network_in_the_zone(self):
        p = _allow("SSH to box", {"matching_target": "ANY", "zone_id": "zi"},
                   {"matching_target": "IP", "ips": ["192.168.14.104"], "zone_id": "zi"})
        assert P.isolation_exceptions(IOT, ZONES, [p]) == ['"SSH to box" (your rule)']

    def test_inbound_into_the_network(self):
        p = _allow("LAN to HA", {"matching_target": "NETWORK", "network_ids": ["default"], "zone_id": "zi"},
                   {"matching_target": "IP", "ips": ["192.168.107.99"], "zone_id": "zi"})
        assert P.isolation_exceptions(IOT, ZONES, [p]) == ['"LAN to HA" (your rule, into this network)']

    def test_dns_lockdown_allow_is_named_as_such(self):
        p = _allow("House Arrest DNS: IoT - allow", {"matching_target": "NETWORK", "network_ids": ["iot"], "zone_id": "zi"},
                   {"matching_target": "IP", "ips": ["192.168.200.50"], "zone_id": "zi", "port": "53"},
                   description=P.describe_dns("Allow 192.168.200.50 for IoT"))
        assert P.isolation_exceptions(IOT, ZONES, [p]) == ["DNS to 192.168.200.50 (House Arrest DNS Lockdown)"]

    def test_not_holes(self):
        src = {"matching_target": "NETWORK", "network_ids": ["iot"], "zone_id": "zi"}
        internet = _allow("to web", src, {"matching_target": "ANY", "zone_id": "ze"})
        to_gateway = _allow("to gw", src, {"matching_target": "ANY", "zone_id": "zg"})
        same_net = _allow("inside", src, {"matching_target": "IP", "ips": ["192.168.107.5"], "zone_id": "zi"})
        disabled = _allow("off", src, {"matching_target": "IP", "ips": ["192.168.200.12"], "zone_id": "zi"}, enabled=False)
        generated = _allow("x (Return)", src, {"matching_target": "IP", "ips": ["192.168.200.12"], "zone_id": "zi"}, predefined=True)
        block = dict(_allow("blk", src, {"matching_target": "ANY", "zone_id": "zi"}), action="BLOCK")
        assert P.isolation_exceptions(IOT, ZONES, [internet, to_gateway, same_net, disabled, generated, block]) == []

    def test_hover_caps_the_list_for_big_rule_sets(self):
        many = [f'"rule {i}" (your rule)' for i in range(50)] + ["DNS to 1.2.3.4 (House Arrest DNS Lockdown)"]
        m = P.build_isolation_matrix([IOT], ZONES, isolation_exceptions={"iot": many})
        detail = m["rows"][0]["cells"]["isolation"]["detail"]
        assert "51 rules let" in detail and "and 48 more" in detail
        assert detail.index("House Arrest DNS") < detail.index('"rule 0"')
        assert '"rule 10"' not in detail
        assert "Policy Table" in detail and len(detail) < 500

    def test_matrix_hover_lists_exceptions_and_stays_green(self):
        m = P.build_isolation_matrix([IOT], ZONES, isolation_exceptions={"iot": ['"LAN to HA" (your rule)']})
        cell = m["rows"][0]["cells"]["isolation"]
        assert cell["label"] == "On" and cell["state"] == "good"
        assert "LAN to HA" in cell["detail"]


class TestDeviceIsolationCell:
    # Colours follow every other column: On green, Off amber. Coverage gaps are
    # carried in the hover detail, not the colour (decided 2026-09-29).
    def test_on_is_green_and_counts_live_in_detail(self):
        cell = P.device_isolation_cell(
            True, {P.COVERED: 4, P.PARTIAL: 35, P.NOT_COVERED: 1, P.UNKNOWN: 1})
        assert cell["state"] == "good" and cell["label"] == "On"
        assert "41 devices" in cell["detail"] and "4 are fully blocked" in cell["detail"]
        assert cell["editable"]

    def test_off_is_amber(self):
        cell = P.device_isolation_cell(False, None)
        assert cell["label"] == "Off" and cell["state"] == "warn"

    def test_off_counts_say_would_be_not_are(self):
        # An Off cell must never read as if devices are already blocked.
        cell = P.device_isolation_cell(
            False, {P.COVERED: 4, P.PARTIAL: 0, P.NOT_COVERED: 0, P.UNKNOWN: 0})
        assert "Turning on Device isolation would" in cell["detail"]
        assert "4 would be fully blocked" in cell["detail"]
        assert "are fully blocked" not in cell["detail"]

    def test_single_device_is_not_pluralised(self):
        cell = P.device_isolation_cell(
            True, {P.COVERED: 1, P.PARTIAL: 0, P.NOT_COVERED: 0, P.UNKNOWN: 0})
        assert "1 device online" in cell["detail"]

    def test_unreadable_coverage_is_said_in_detail(self):
        cell = P.device_isolation_cell(True, None)
        assert cell["label"] == "On"
        assert "couldn't read" in cell["detail"]

    def test_matrix_unknown_when_setting_unreadable(self):
        nets = [{"_id": "n1", "name": "IoT", "vlan": 107, "purpose": "corporate"}]
        m = P.build_isolation_matrix(nets, [], device_isolation_ids=None)
        cell = m["rows"][0]["cells"]["device_isolation"]
        assert cell["label"] == "Unknown" and not cell["editable"]

    def test_matrix_not_offered_on_vpn_or_transit(self):
        nets = [{"_id": "v", "name": "Office VPN", "purpose": "site-vpn"},
                {"_id": "t", "name": "ISP handoff", "vlan": 305, "purpose": "vlan-only"}]
        m = P.build_isolation_matrix(nets, [], device_isolation_ids=["v", "t"])
        for row in m["rows"]:
            cell = row["cells"]["device_isolation"]
            assert cell["label"] == "—" and not cell["editable"]

    def test_matrix_reads_list_membership(self):
        nets = [{"_id": "n1", "name": "IoT", "vlan": 107, "purpose": "corporate"}]
        m = P.build_isolation_matrix(
            nets, [], device_isolation_ids=["n1"],
            coverage={"n1": {P.COVERED: 1, P.PARTIAL: 0, P.NOT_COVERED: 0, P.UNKNOWN: 0}})
        assert m["rows"][0]["cells"]["device_isolation"]["label"] == "On"


class TestNeighbourAcls:
    def test_gateway_macs_include_lan_and_interfaces(self):
        macs = P.gateway_lan_macs(TOPOLOGY)
        assert "a8:9c:6c:90:e3:85" in macs      # what a LAN device ARPs to
        assert "a8:9c:6c:90:e3:80" in macs      # the device MAC
        assert "a8:9c:6c:90:e3:86" in macs
        assert "00:00:00:00:00:02" not in macs  # switches are not gateways

    def test_pair_is_allow_then_block(self):
        allow, block = P.build_neighbour_acls(
            ["DC:A6:32:08:36:42"], "net1", P.gateway_lan_macs(TOPOLOGY), "Roku", [7, 8])
        assert allow["action"] == "ALLOW" and allow["acl_index"] == 7
        assert block["action"] == "BLOCK" and block["acl_index"] == 8
        assert block["traffic_destination"]["specific_mac_addresses"] == []
        dst = allow["traffic_destination"]["specific_mac_addresses"]
        assert "a8:9c:6c:90:e3:85" in dst and "ff:ff:ff:ff:ff:ff" in dst
        assert allow["traffic_source"]["specific_mac_addresses"] == ["dc:a6:32:08:36:42"]
        assert allow["mac_acl_network_id"] == "net1"

    def test_pair_refuses_without_gateway_macs(self):
        with pytest.raises(ValueError):
            P.build_neighbour_acls(["dc:a6:32:08:36:42"], "net1", [], "x", [0, 1])

    def test_name_fits_the_32_char_limit(self):
        name = P.acl_rule_name("A very long device name that overflows")
        assert len(name) <= 32 and name.startswith("[HouseArrest] ")

    def test_only_ours_are_matched(self):
        ours = {"name": "[HouseArrest] Roku", "action": "BLOCK",
                "traffic_source": {"specific_mac_addresses": ["aa:bb:cc:dd:ee:ff"]}}
        unifi = dict(ours, predefined=True)
        user = dict(ours, name="My own rule")
        found = P.neighbour_acls_for([ours, unifi, user], ["AA:BB:CC:DD:EE:FF"])
        assert found == [ours]

    def test_state_detects_lone_block_as_broken(self):
        src = {"specific_mac_addresses": ["aa:bb:cc:dd:ee:ff"]}
        allow = {"name": "[HouseArrest] x", "action": "ALLOW", "traffic_source": src}
        block = {"name": "[HouseArrest] x", "action": "BLOCK", "traffic_source": src}
        macs = ["aa:bb:cc:dd:ee:ff"]
        assert P.neighbour_block_state([], macs) is None
        assert P.neighbour_block_state([allow, block], macs) == "ok"
        assert P.neighbour_block_state([block], macs) == "broken"
        assert P.neighbour_block_state([allow, dict(block, enabled=False)], macs) == "disabled"

    def test_indexes_go_after_existing(self):
        assert P.next_acl_indexes([{"acl_index": 4}, {"acl_index": 9}], 2) == [10, 11]
        assert P.next_acl_indexes([], 2) == [0, 1]

    def test_lan_only_does_not_offer_neighbour_block(self):
        offered = {p["value"]: p["neighbour_block"] for p in P.preset_catalog()}
        assert offered[P.LAN_ONLY] is False
        assert offered[P.FULL_LOCKDOWN] and offered[P.INTERNET_ONLY]


# MEASURED 2026-10-01: the neighbour block cut a same-VLAN Pi-hole, so names
# stopped resolving under Internet only. Its resolvers now go in the ALLOW.
DEFAULT_NET = {"_id": "def", "ip_subnet": "192.168.200.1/24",
               "dhcpd_dns_enabled": True,
               "dhcpd_dns_1": "192.168.200.50", "dhcpd_dns_2": "192.168.200.51",
               "dhcpd_dns_3": "1.1.1.1"}
LIVE = {
    "dc:a6:32:2b:88:66": {"mac": "dc:a6:32:2b:88:66", "ip": "192.168.200.50", "name": "pihole1"},
    "dc:a6:32:08:57:35": {"mac": "dc:a6:32:08:57:35", "ip": "192.168.200.51", "name": "pihole2"},
}


class TestSameNetworkResolvers:
    def test_finds_same_vlan_resolvers_and_skips_remote_ones(self):
        found, missing = P.same_network_resolvers(DEFAULT_NET, LIVE)
        assert [r["name"] for r in found] == ["pihole1", "pihole2"]
        assert missing == []          # 1.1.1.1 is routed via the gateway

    def test_offline_resolver_is_reported_missing_not_dropped(self):
        live = {k: v for k, v in LIVE.items() if v["name"] == "pihole1"}
        found, missing = P.same_network_resolvers(DEFAULT_NET, live)
        assert [r["name"] for r in found] == ["pihole1"]
        assert missing == ["192.168.200.51"]

    def test_gateway_dns_default_needs_nothing(self):
        net = {"_id": "n", "ip_subnet": "192.168.3.1/24"}
        assert P.same_network_resolvers(net, LIVE) == ([], [])

    def test_disabled_dhcp_dns_override_is_ignored(self):
        net = dict(DEFAULT_NET, dhcpd_dns_enabled=False)
        assert P.same_network_resolvers(net, LIVE) == ([], [])

    def test_resolvers_join_the_allow_not_the_block(self):
        allow, block = P.build_neighbour_acls(
            ["d8:3a:dd:d1:e4:cf"], "def", ["a8:9c:6c:90:e3:85"], "t", [0, 1],
            resolver_macs=["DC:A6:32:2B:88:66"])
        dest = allow["traffic_destination"]["specific_mac_addresses"]
        assert "dc:a6:32:2b:88:66" in dest and "a8:9c:6c:90:e3:85" in dest
        assert block["traffic_destination"]["specific_mac_addresses"] == []

    def test_a_locked_pihole_is_not_allowed_to_itself(self):
        allow, _ = P.build_neighbour_acls(
            ["dc:a6:32:2b:88:66"], "def", ["a8:9c:6c:90:e3:85"], "t", [0, 1],
            resolver_macs=["dc:a6:32:2b:88:66"])
        assert "dc:a6:32:2b:88:66" not in allow["traffic_destination"]["specific_mac_addresses"]

    def test_card_reads_resolvers_back_from_the_stored_rule(self):
        rules = P.build_neighbour_acls(
            ["d8:3a:dd:d1:e4:cf"], "def", ["a8:9c:6c:90:e3:85"], "t", [0, 1],
            resolver_macs=["dc:a6:32:2b:88:66", "dc:a6:32:08:57:35"])
        got = P.acl_allowed_resolvers(rules, ["d8:3a:dd:d1:e4:cf"], LIVE)
        assert [r["name"] for r in got] == ["pihole1", "pihole2"]
        note = P.resolver_note(got)
        assert "pihole1 and pihole2" in note and "any port" in note

    def test_no_resolvers_no_note(self):
        assert P.resolver_note([]) is None
