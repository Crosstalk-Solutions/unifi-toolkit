"""
Tests for the 2026-10-02 Devices tab redesign and the Internet only DNS fixes.

Shapes come from the live measurements recorded in docs/house-arrest-design.md
("MEASURED 2026-10-01 (afternoon)"): testclient on HA-Test (192.168.3.0/24,
not isolated) resolving through Pi-holes on Default (192.168.200.50/.51), all
in the Internal zone.
"""
from tools.house_arrest import policies as P

INTERNAL = "zone-internal"
EXTERNAL = "zone-external"
ZONES = [{"_id": INTERNAL, "zone_key": "internal", "name": "Internal"},
         {"_id": EXTERNAL, "zone_key": "external", "name": "External"}]
DEFAULT = {"_id": "net-default", "name": "Default", "purpose": "corporate",
           "ip_subnet": "192.168.200.1/24", "firewall_zone_id": INTERNAL,
           "dhcpd_dns_enabled": True,
           "dhcpd_dns_1": "192.168.200.50", "dhcpd_dns_2": "192.168.200.51"}
HA_TEST = {"_id": "net-hatest", "name": "HA-Test", "purpose": "corporate",
           "ip_subnet": "192.168.3.1/24", "firewall_zone_id": INTERNAL,
           "network_isolation_enabled": False, "dhcpd_dns_enabled": True,
           "dhcpd_dns_1": "192.168.200.50", "dhcpd_dns_2": "192.168.200.51"}
NETWORKS = [DEFAULT, HA_TEST]
MAC = "dc:a6:32:08:36:42"


class TestPresetNames:
    def test_quarantine_has_its_own_key(self):
        # "quarantine" still means the removed VLAN-move preset, which release
        # treats specially. The new preset must never share it.
        assert P.CUT_OFF != P.QUARANTINE
        assert P.PRESET_LABELS[P.CUT_OFF] == "Quarantine"
        assert not P.requires_network(P.CUT_OFF)
        assert P.QUARANTINE not in P.PRESETS

    def test_offered_order(self):
        # Most to least permissive; Quarantine on the far right.
        assert P.PRESETS == (P.INTERNET_ONLY, P.LAN_ONLY, P.FULL_LOCKDOWN, P.CUT_OFF)
        assert P.PRESET_LABELS[P.FULL_LOCKDOWN] == "No internet"

    def test_new_and_legacy_quarantine_are_told_apart(self):
        new = {"description": "[HouseArrest] Quarantine for TV"}
        old = {"description": "[HouseArrest] Quarantine + VLAN move for TV"}
        assert P.preset_from_policy(new) == P.CUT_OFF
        assert P.preset_from_policy(old) == P.QUARANTINE
        assert P.requires_network(P.preset_from_policy(old))

    def test_lockdowns_made_before_the_rename_are_still_recognised(self):
        old = {"description": "[HouseArrest] Full lockdown for Roku"}
        assert P.preset_from_policy(old) == P.FULL_LOCKDOWN
        new = {"description": "[HouseArrest] No internet for Roku"}
        assert P.preset_from_policy(new) == P.FULL_LOCKDOWN

    def test_a_label_prefix_alone_does_not_match(self):
        assert P.preset_from_policy({"description": "[HouseArrest] Quarantined thing"}) is None


class TestQuarantineRules:
    def test_two_blocks_matching_every_state(self):
        rules = P.build_lockdown(
            preset=P.CUT_OFF, macs=[MAC], device_label="TV",
            client_zone_id=INTERNAL, external_zone_id=EXTERNAL,
            indexes=[10000, 10001], allow_inbound=P.inbound_for(P.CUT_OFF))
        assert len(rules) == 2 == P.policy_count(P.CUT_OFF)
        assert {r["destination"]["zone_id"] for r in rules} == {INTERNAL, EXTERNAL}
        assert all(r["connection_state_type"] == "ALL" for r in rules)

    def test_caveats_say_dns_lookups_still_work(self):
        # MEASURED 2026-10-02: under Quarantine, gateway DNS and a DNS
        # Lockdown's approved servers still answered; the internet did not.
        text = " ".join(P.caveats_for(P.CUT_OFF))
        assert "can still look up names" in text
        assert "path out over DNS" in text
        assert "already open" in text


class TestDeviceDnsResolvers:
    def test_cross_vlan_resolvers_are_kept(self):
        allow, skipped = P.device_dns_resolvers([HA_TEST], NETWORKS, ZONES, INTERNAL)
        assert allow == ["192.168.200.50", "192.168.200.51"] and skipped == []

    def test_same_subnet_resolvers_need_nothing(self):
        allow, skipped = P.device_dns_resolvers([DEFAULT], NETWORKS, ZONES, INTERNAL)
        assert allow == [] and skipped == []

    def test_isolated_network_is_skipped_never_punched_through(self):
        iso = dict(HA_TEST, network_isolation_enabled=True)
        allow, skipped = P.device_dns_resolvers([iso], NETWORKS, ZONES, INTERNAL)
        assert allow == [] and skipped == ["net-hatest"]

    def test_gateway_dns_needs_nothing(self):
        net = dict(HA_TEST, dhcpd_dns_enabled=False)
        assert P.device_dns_resolvers([net], NETWORKS, ZONES, INTERNAL) == ([], [])

    def test_internet_resolvers_need_nothing(self):
        net = dict(HA_TEST, dhcpd_dns_1="1.1.1.1", dhcpd_dns_2="")
        assert P.device_dns_resolvers([net], NETWORKS, ZONES, INTERNAL) == ([], [])


class TestDeviceDnsAllow:
    def _allow(self, index=10010):
        return P.build_device_dns_allow(
            [MAC], "testclient", INTERNAL, ["192.168.200.50"], index)

    def test_narrow_shape(self):
        a = self._allow()
        assert a["action"] == "ALLOW"
        assert a["source"]["client_macs"] == [MAC]
        assert a["destination"]["ips"] == ["192.168.200.50"]
        assert a["destination"]["port"] == "53"
        assert a["destination"]["zone_id"] == INTERNAL

    def test_reads_as_part_of_the_device_lockdown(self):
        a = self._allow()
        assert P.is_device_dns_allow(a)
        assert P._label_from_policy(a) == "testclient"
        assert P.preset_from_policy(a) == P.INTERNET_ONLY
        assert P.arrested_macs([a]) == {MAC: "testclient"}


def _block(index):
    return P._base_policy(
        name=f"{P.NAME_PREFIX}testclient — no LAN", action="BLOCK", index=index,
        source=P.client_source([MAC], INTERNAL),
        destination=P.zone_destination(INTERNAL),
        description=P.describe("Internet only for testclient"))


def _lockdown_allow(index, net_id="net-hatest"):
    return P._base_policy(
        name="House Arrest DNS: HA-Test - allow approved resolvers (LAN)",
        action="ALLOW", index=index,
        source=P.network_source([net_id], INTERNAL),
        destination=P._dns_dest(INTERNAL, P.DNS_PORT, ["192.168.200.50"]),
        description=P.describe_dns("Allow 192.168.200.50 for HA-Test"))


class TestShadowedDnsAllows:
    # The measured indexes: test A allow 10010 / block 10013 worked; test B
    # block 10013 / allow 10014 cut DNS.
    def test_test_a_order_is_fine(self):
        pols = [_lockdown_allow(10010), _block(10013)]
        assert P.shadowed_dns_allows(pols[1], pols, ["net-hatest"]) == []

    def test_test_b_order_is_caught(self):
        pols = [_block(10013), _lockdown_allow(10014)]
        hit = P.shadowed_dns_allows(pols[0], pols, ["net-hatest"])
        assert [a["index"] for a in hit] == [10014]

    def test_other_networks_lockdown_does_not_count(self):
        pols = [_block(10013), _lockdown_allow(10014, net_id="net-guests")]
        assert P.shadowed_dns_allows(pols[0], pols, ["net-hatest"]) == []

    def test_device_dns_allow_behind_its_block_is_caught(self):
        allow = P.build_device_dns_allow([MAC], "testclient", INTERNAL,
                                         ["192.168.200.50"], 10020)
        pols = [_block(10013), allow]
        assert P.shadowed_dns_allows(pols[0], pols, []) == [allow]

    def test_disabled_allow_is_ignored(self):
        a = dict(_lockdown_allow(10014), enabled=False)
        pols = [_block(10013), a]
        assert P.shadowed_dns_allows(pols[0], pols, ["net-hatest"]) == []

    def test_only_no_lan_blocks_are_checked(self):
        internet_block = dict(_block(10013), destination=P.zone_destination(EXTERNAL))
        pols = [internet_block, _lockdown_allow(10014)]
        assert P.shadowed_dns_allows(internet_block, pols, ["net-hatest"]) == []


class TestRecreatePayload:
    def test_drops_identity_and_takes_new_index(self):
        stored = dict(_block(10013), _id="abc", site_id="s")
        out = P.recreate_payload(stored, 10030)
        assert "_id" not in out and "site_id" not in out
        assert out["index"] == 10030
        assert out["source"]["client_macs"] == [MAC]
