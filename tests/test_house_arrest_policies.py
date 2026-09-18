"""
Tests for the House Arrest policy builder.

These are pure-function tests — no controller, no database. They exist mainly
to pin down two things that are easy to break and expensive to get wrong:
the [HouseArrest] marker (which revert depends on) and the index range (which
decides whether a policy evaluates before the predefined allow-all).
"""
import pytest

from tools.house_arrest import policies as P


pytestmark = pytest.mark.unit


CLIENT_ZONE = "67b4e429bb647c4c8b1759fe"
EXTERNAL_ZONE = "67b4e429bb647c4c8b175aaa"
MAC = "ba:66:5c:5c:2b:36"


class TestNormalizeMac:
    def test_lowercases_and_accepts_dashes(self):
        assert P.normalize_mac("BA-66-5C-5C-2B-36") == MAC

    def test_strips_whitespace(self):
        assert P.normalize_mac("  BA:66:5C:5C:2B:36 ") == MAC

    @pytest.mark.parametrize("bad", ["", "not-a-mac", "ba:66:5c:5c:2b", "zz:66:5c:5c:2b:36"])
    def test_rejects_junk(self, bad):
        with pytest.raises(ValueError):
            P.normalize_mac(bad)


class TestLocallyAdministered:
    def test_detects_laa_bit(self):
        # ba = 1011_1010, bit 0x02 set
        assert P.is_locally_administered("ba:66:5c:5c:2b:36") is True

    def test_vendor_mac_is_not_laa(self):
        # 0c = 0000_1100, bit 0x02 clear — a real burned-in address
        assert P.is_locally_administered("0c:43:f9:29:df:d4") is False

    def test_junk_is_not_laa_rather_than_raising(self):
        assert P.is_locally_administered("nonsense") is False


class TestMarker:
    def test_describe_tags_the_description(self):
        assert P.describe("Full lockdown for Cam").startswith(P.MARKER)

    def test_our_policy_is_recognized(self):
        pol = {"predefined": False, "description": P.describe("x")}
        assert P.is_house_arrest(pol) is True

    def test_predefined_is_never_ours_even_if_marked(self):
        """A predefined policy must never be deletable, whatever it says."""
        pol = {"predefined": True, "description": P.describe("x")}
        assert P.is_house_arrest(pol) is False

    def test_unmarked_custom_policy_is_not_ours(self):
        pol = {"predefined": False, "description": "hand-made rule"}
        assert P.is_house_arrest(pol) is False

    def test_missing_description_is_not_ours(self):
        assert P.is_house_arrest({"predefined": False}) is False

    def test_find_ours_filters(self):
        pols = [
            {"predefined": True, "description": "Allow All Traffic"},
            {"predefined": False, "description": "hand-made"},
            {"predefined": False, "description": P.describe("Cam")},
        ]
        assert len(P.find_ours(pols)) == 1


class TestIndexes:
    def test_starts_at_base(self):
        assert P.next_free_index([], 1) == [P.BASE_INDEX]

    def test_skips_used(self):
        existing = [{"index": 10000}, {"index": 10001}]
        assert P.next_free_index(existing, 2) == [10002, 10003]

    def test_ignores_predefined_high_index(self):
        existing = [{"index": P.PREDEFINED_ALLOW_ALL_INDEX}]
        assert P.next_free_index(existing, 1) == [P.BASE_INDEX]

    def test_always_below_predefined_allow_all(self):
        got = P.next_free_index([], 5)
        assert all(i < P.PREDEFINED_ALLOW_ALL_INDEX for i in got)

    def test_zero_count(self):
        assert P.next_free_index([], 0) == []


class TestSourceAndDestination:
    def test_client_source_uses_mac_array(self):
        src = P.client_source([MAC], CLIENT_ZONE)
        assert src["matching_target"] == "CLIENT"
        assert src["client_macs"] == [MAC]

    def test_client_source_takes_several_macs(self):
        src = P.client_source([MAC, "0c:43:f9:29:df:d4"], CLIENT_ZONE)
        assert len(src["client_macs"]) == 2

    def test_client_source_requires_a_mac(self):
        with pytest.raises(ValueError):
            P.client_source([], CLIENT_ZONE)

    def test_client_source_requires_zone(self):
        with pytest.raises(ValueError):
            P.client_source([MAC], "")

    def test_ip_destination_shape(self):
        dest = P.ip_destination(["192.168.107.133"], CLIENT_ZONE, port="8123")
        assert dest["matching_target"] == "IP"
        assert dest["matching_target_type"] == "SPECIFIC"
        assert dest["ips"] == ["192.168.107.133"]
        assert dest["port"] == "8123"
        assert dest["port_matching_type"] == "SPECIFIC"

    def test_ip_destination_without_port_matches_any(self):
        dest = P.ip_destination(["192.168.107.133"], CLIENT_ZONE)
        assert dest["port_matching_type"] == "ANY"
        assert "port" not in dest


class TestPresets:
    @pytest.mark.parametrize("preset", P.PRESETS)
    def test_every_preset_builds(self, preset):
        idx = P.next_free_index([], P.policy_count(preset))
        pols = P.build_lockdown(
            preset, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE, idx
        )
        assert len(pols) == P.policy_count(preset)

    @pytest.mark.parametrize("preset", P.PRESETS)
    def test_every_policy_is_marked_and_custom(self, preset):
        idx = P.next_free_index([], P.policy_count(preset))
        pols = P.build_lockdown(
            preset, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE, idx
        )
        for p in pols:
            assert P.is_house_arrest(p), "revert would not find this policy"
            assert p["predefined"] is False

    @pytest.mark.parametrize("preset", P.PRESETS)
    def test_every_policy_beats_the_allow_all(self, preset):
        idx = P.next_free_index([], P.policy_count(preset))
        pols = P.build_lockdown(
            preset, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE, idx
        )
        for p in pols:
            assert P.BASE_INDEX <= p["index"] < P.PREDEFINED_ALLOW_ALL_INDEX

    def test_internet_only_leaves_wan_open(self):
        pols = P.build_lockdown(
            P.INTERNET_ONLY, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE,
            P.next_free_index([], 1),
        )
        assert len(pols) == 1
        assert pols[0]["destination"]["zone_id"] == CLIENT_ZONE

    def test_lan_only_blocks_wan(self):
        pols = P.build_lockdown(
            P.LAN_ONLY, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE,
            P.next_free_index([], 1),
        )
        assert len(pols) == 1
        assert pols[0]["destination"]["zone_id"] == EXTERNAL_ZONE

    def test_full_lockdown_blocks_both(self):
        pols = P.build_lockdown(
            P.FULL_LOCKDOWN, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE,
            P.next_free_index([], 2),
        )
        zones = {p["destination"]["zone_id"] for p in pols}
        assert zones == {CLIENT_ZONE, EXTERNAL_ZONE}
        assert all(p["action"] == "BLOCK" for p in pols)

    def test_unknown_preset_rejected(self):
        with pytest.raises(ValueError):
            P.build_lockdown("delete_everything", [MAC], "Cam",
                             CLIENT_ZONE, EXTERNAL_ZONE, [10000])

    def test_too_few_indexes_rejected(self):
        with pytest.raises(ValueError):
            P.build_lockdown(P.FULL_LOCKDOWN, [MAC], "Cam",
                             CLIENT_ZONE, EXTERNAL_ZONE, [10000])


class TestExceptions:
    def test_outbound_exception_allows_and_responds(self):
        pol = P.build_exception(
            [MAC], "Cam", CLIENT_ZONE, ["192.168.107.133"], CLIENT_ZONE,
            index=10005, port="8123", note="Home Assistant",
        )
        assert pol["action"] == "ALLOW"
        assert pol["create_allow_respond"] is True
        assert P.is_house_arrest(pol)

    def test_inbound_exception_targets_device_by_ip(self):
        """Inbound has to be IP-matched — the API has no CLIENT destination."""
        pol = P.build_inbound_exception(
            ["192.168.107.133"], "Cam", CLIENT_ZONE, CLIENT_ZONE,
            index=10006, port="443",
        )
        assert pol["destination"]["matching_target"] == "IP"
        assert pol["source"]["matching_target"] == "ANY"
        assert pol["create_allow_respond"] is True


class TestPrecedence:
    """
    The controller assigns the stored policy index itself — indexes sent as
    10004/10005 came back as 10000/10003 against a live console. So an ALLOW
    the user already had can evaluate before our BLOCK, and the tool has to
    say so rather than assume its rules win.
    """

    def _ours(self, index):
        return {
            "_id": "ours1", "action": "BLOCK", "index": index,
            "predefined": False, "description": P.describe("Full lockdown for Pi"),
        }

    def test_allow_at_lower_index_is_flagged(self):
        ours = [self._ours(10003)]
        allpol = ours + [{
            "_id": "theirs", "action": "ALLOW", "index": 10000,
            "predefined": False, "name": "Madelena to n8n",
        }]
        warnings = P.check_precedence(ours, allpol)
        assert len(warnings) == 1
        assert warnings[0]["name"] == "Madelena to n8n"
        assert warnings[0]["blocks_at"] == 10003

    def test_same_index_counts_as_preceding(self):
        """A tie is ambiguous ordering, which is not a guarantee of enforcement."""
        ours = [self._ours(10000)]
        allpol = ours + [{"_id": "t", "action": "ALLOW", "index": 10000, "predefined": False}]
        assert len(P.check_precedence(ours, allpol)) == 1

    def test_allow_after_our_block_is_fine(self):
        ours = [self._ours(10000)]
        allpol = ours + [{"_id": "t", "action": "ALLOW", "index": 10005, "predefined": False}]
        assert P.check_precedence(ours, allpol) == []

    def test_predefined_allow_all_is_not_flagged(self):
        """It sits at the bottom by design; flagging it would be noise."""
        ours = [self._ours(10000)]
        allpol = ours + [{
            "_id": "pd", "action": "ALLOW",
            "index": P.PREDEFINED_ALLOW_ALL_INDEX, "predefined": True,
        }]
        assert P.check_precedence(ours, allpol) == []

    def test_disabled_allow_is_not_flagged(self):
        ours = [self._ours(10003)]
        allpol = ours + [{
            "_id": "t", "action": "ALLOW", "index": 10000,
            "predefined": False, "enabled": False,
        }]
        assert P.check_precedence(ours, allpol) == []

    def test_our_own_policies_never_flag_each_other(self):
        ours = [self._ours(10000), {
            "_id": "ours2", "action": "ALLOW", "index": 10000,
            "predefined": False, "description": P.describe("Exception for Pi"),
        }]
        assert P.check_precedence(ours, ours) == []

    def test_no_blocks_means_nothing_to_warn_about(self):
        assert P.check_precedence([], [{"action": "ALLOW", "index": 1}]) == []


class TestCaveats:
    """
    Measured against a real device: under Full lockdown, DNS still resolved
    through a same-VLAN resolver and the gateway stayed reachable. Presets
    that claim to cut internet access must carry those caveats.
    """

    @pytest.mark.parametrize("preset", [P.FULL_LOCKDOWN, P.LAN_ONLY, P.QUARANTINE])
    def test_internet_blocking_presets_carry_caveats(self, preset):
        """
        Asserts the behaviour, not a count — the caveat list grows as more
        escape hatches are measured, and a hardcoded number would fail for
        being more honest rather than less.
        """
        caveats = P.caveats_for(preset)
        assert caveats
        joined = " ".join(caveats).lower()
        assert "dns" in joined, "the measured DNS hole must be disclosed"
        assert "already open" in joined, "conntrack behaviour must be disclosed"

    def test_internet_only_makes_no_such_claim(self):
        assert P.caveats_for(P.INTERNET_ONLY) == []

    def test_catalog_exposes_them(self):
        entry = next(p for p in P.preset_catalog() if p["value"] == P.FULL_LOCKDOWN)
        assert entry["caveats"]
        assert entry["requires_network"] is False


class TestQuarantineTruthfulness:
    def test_quarantine_never_claims_to_block_peers(self):
        """
        Moving a device to another VLAN changes which peers it has; it does
        not cut peer traffic. Claiming "blocked" here would be a lie.
        """
        assert P.PRESET_EFFECTS[P.QUARANTINE]["peers"] == "moved"

    def test_no_preset_claims_to_block_peers(self):
        for preset in P.PRESETS:
            assert P.PRESET_EFFECTS[preset]["peers"] != "block"

    def test_quarantine_requires_a_target_network(self):
        assert P.requires_network(P.QUARANTINE) is True
        assert P.requires_network(P.FULL_LOCKDOWN) is False

    def test_quarantine_is_recognised_but_no_longer_offered(self):
        """
        Removed from the offered presets 2026-09-17: the per-client VLAN
        override was measured half-applying on a wired client (a DHCP lease on
        the target VLAN with no working L2 — ARP to the gateway and to
        same-VLAN peers failed), while the controller reported contradictory
        locations. A quarantine the platform cannot report coherently cannot
        be verified, so the tool no longer offers it.

        Recognition must survive the removal: release still has to identify a
        pre-removal quarantine policy and clear its VLAN override, or the
        device is left stranded in the quarantine VLAN.
        """
        assert P.QUARANTINE not in P.PRESETS
        assert P.QUARANTINE not in [p["value"] for p in P.preset_catalog()]
        # Release-side recognition stays intact.
        assert P.PRESET_LABELS[P.QUARANTINE] == "Quarantine + VLAN move"
        assert P.requires_network(P.QUARANTINE) is True


class TestPresetFromPolicy:
    def test_round_trips_through_the_description(self):
        pols = P.build_lockdown(
            P.FULL_LOCKDOWN, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE,
            P.next_free_index([], 2),
        )
        assert P.preset_from_policy(pols[0]) == P.FULL_LOCKDOWN

    def test_legacy_quarantine_description_is_still_recognised(self):
        """
        Quarantine can no longer be built or applied, but a policy created
        before its removal still carries the old label — and release depends on
        recovering the key from it to clear the device's VLAN override.
        """
        legacy = {"description": P.describe(
            P.PRESET_LABELS[P.QUARANTINE] + " for Cam")}
        assert P.preset_from_policy(legacy) == P.QUARANTINE

    def test_foreign_policy_yields_nothing(self):
        assert P.preset_from_policy({"description": "hand-made"}) is None


class TestNetworkIsolation:
    """
    Network isolation uses UniFi's own per-network flags rather than parallel
    firewall policies. Two properties matter:

      * it must never guess at a previous value — it only ever flips a flag
        that is not already where the preset wants it;
      * leftover policies from the previous implementation must still be
        recognisable, so they can be cleaned up.
    """

    OPEN = {"network_isolation_enabled": False, "internet_access_enabled": True}
    ISOLATED = {"network_isolation_enabled": True, "internet_access_enabled": True}
    LOCKED = {"network_isolation_enabled": True, "internet_access_enabled": False}

    def test_isolate_sets_only_the_isolation_flag(self):
        assert P.network_flags_for(P.NET_ISOLATE_NETWORKS) == {
            "network_isolation_enabled": True
        }

    def test_no_internet_sets_only_the_internet_flag(self):
        assert P.network_flags_for(P.NET_NO_INTERNET) == {
            "internet_access_enabled": False
        }

    def test_full_isolation_sets_both(self):
        assert P.network_flags_for(P.NET_FULL) == {
            "network_isolation_enabled": True,
            "internet_access_enabled": False,
        }

    def test_open_network_needs_every_flag_changed(self):
        assert P.network_changes_needed(self.OPEN, P.NET_FULL) == {
            "network_isolation_enabled": True,
            "internet_access_enabled": False,
        }

    def test_already_isolated_needs_nothing(self):
        """Re-isolating must be a no-op, not a redundant write."""
        assert P.network_changes_needed(self.ISOLATED, P.NET_ISOLATE_NETWORKS) == {}

    def test_partially_set_network_changes_only_the_gap(self):
        assert P.network_changes_needed(self.ISOLATED, P.NET_FULL) == {
            "internet_access_enabled": False
        }

    def test_missing_field_is_treated_as_off(self):
        """An absent flag means not isolated, not unknown."""
        assert P.network_changes_needed({}, P.NET_ISOLATE_NETWORKS) == {
            "network_isolation_enabled": True
        }

    def test_release_restores_reachability_and_internet(self):
        assert P.network_flags_to_release() == {
            "network_isolation_enabled": False,
            "internet_access_enabled": True,
        }

    def test_unknown_preset_rejected(self):
        with pytest.raises(ValueError):
            P.network_flags_for("nuke")

    def test_legacy_policies_are_still_recognisable(self):
        """Leftovers from the old implementation must remain cleanable."""
        legacy = {
            "predefined": False,
            "description": P.describe_network("Full isolation for IDIoT"),
            "name": "House Arrest: IDIoT network - isolated",
        }
        assert P.is_house_arrest(legacy)
        assert P.is_network_policy(legacy)
        assert P.network_label_from_policy(legacy) == "IDIoT"

    def test_device_policies_are_not_network_policies(self):
        pols = P.build_lockdown(
            P.FULL_LOCKDOWN, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE,
            P.next_free_index([], 2),
        )
        assert all(not P.is_network_policy(p) for p in pols)

    def test_every_network_preset_discloses_the_peer_caveat(self):
        for preset in P.NETWORK_PRESETS:
            joined = " ".join(P.caveats_for_network(preset)).lower()
            assert "talk to each other" in joined


class TestIsolationMatrix:
    def _nets(self):
        return [
            {"_id": "n1", "name": "Default", "vlan": None, "purpose": "corporate",
             "ip_subnet": "192.168.200.1/24", "dhcpd_dns_1": "192.168.200.50",
             "network_isolation_enabled": None, "mdns_enabled": True},
            {"_id": "n2", "name": "IoT", "vlan": 107, "purpose": "corporate",
             "ip_subnet": "192.168.107.1/24", "dhcpd_dns_1": "192.168.200.50",
             "network_isolation_enabled": True, "mdns_enabled": False},
            {"_id": "w1", "name": "WAN", "purpose": "wan"},
        ]

    def _zones(self):
        return [{"_id": "z1", "name": "Internal", "network_ids": ["n1", "n2"]}]

    def test_wans_are_excluded(self):
        m = P.build_isolation_matrix(self._nets(), self._zones())
        assert [r["name"] for r in m["rows"]] == ["IoT", "Default"]

    def test_resolver_on_own_subnet_is_flagged(self):
        """The measured hole: a same-subnet resolver cannot be filtered."""
        m = P.build_isolation_matrix(self._nets(), self._zones())
        default = next(r for r in m["rows"] if r["name"] == "Default")
        assert default["cells"]["dns"]["state"] == "warn"

    def test_resolver_on_another_network_is_not_flagged(self):
        m = P.build_isolation_matrix(self._nets(), self._zones())
        iot = next(r for r in m["rows"] if r["name"] == "IoT")
        assert iot["cells"]["dns"]["state"] == "neutral"

    def test_shared_zone_is_flagged(self):
        m = P.build_isolation_matrix(self._nets(), self._zones())
        assert all(r["cells"]["zone"]["state"] == "warn" for r in m["rows"])

    def test_unset_isolation_reads_as_off_not_unknown(self):
        m = P.build_isolation_matrix(self._nets(), self._zones())
        default = next(r for r in m["rows"] if r["name"] == "Default")
        assert default["cells"]["isolation"]["label"] == "Off"

    def test_every_cell_has_an_explanation(self):
        m = P.build_isolation_matrix(self._nets(), self._zones())
        for r in m["rows"]:
            for col in m["columns"]:
                assert r["cells"][col["key"]]["detail"], f"{r['name']}/{col['key']}"

    def test_subnet_membership(self):
        assert P._ip_in_subnet("192.168.200.50", "192.168.200.1/24") is True
        assert P._ip_in_subnet("192.168.107.5", "192.168.200.1/24") is False
        assert P._ip_in_subnet("garbage", "192.168.200.1/24") is False
        assert P._ip_in_subnet("192.168.200.50", None) is False


class TestInboundAccess:
    """
    A BLOCK sourced from the device also drops the replies to connections you
    started, which silently costs you access to it. UniFi's own isolation uses
    create_allow_respond for this, but the API rejects that on a policy we
    create when both sides are in the same zone
    (FirewallPolicyCreateRespondTrafficPolicyNotAllowed), which is exactly the
    "no LAN" case. Connection-state scoping is the mechanism that works.
    """

    def _build(self, allow_inbound):
        return P.build_lockdown(
            P.FULL_LOCKDOWN, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE,
            P.next_free_index([], 2), allow_inbound=allow_inbound,
        )

    def test_default_blocks_only_what_the_device_initiates(self):
        for pol in P.build_lockdown(
            P.FULL_LOCKDOWN, [MAC], "Cam", CLIENT_ZONE, EXTERNAL_ZONE,
            P.next_free_index([], 2),
        ):
            assert pol["connection_state_type"] == "CUSTOM"
            assert pol["connection_states"] == ["NEW", "INVALID"]

    def test_absolute_isolation_blocks_every_state(self):
        for pol in self._build(False):
            assert pol["connection_state_type"] == "ALL"
            assert pol["connection_states"] == []

    def test_never_sets_respond_traffic_on_a_block(self):
        """The API rejects it intra-zone, so we must not emit it."""
        for allow in (True, False):
            for pol in self._build(allow):
                assert pol["create_allow_respond"] is False

    def test_invalid_is_paired_with_new(self):
        """Without INVALID, unmatched packets would escape the block."""
        assert "INVALID" in P.connection_state(True)["connection_states"]

    def test_established_is_never_blocked_when_inbound_allowed(self):
        states = P.connection_state(True)["connection_states"]
        assert "ESTABLISHED" not in states and "RELATED" not in states

    @pytest.mark.parametrize("preset", P.PRESETS)
    def test_every_preset_honours_the_choice(self, preset):
        idx = P.next_free_index([], P.policy_count(preset))
        on = P.build_lockdown(preset, [MAC], "Cam", CLIENT_ZONE,
                              EXTERNAL_ZONE, idx, allow_inbound=True)
        off = P.build_lockdown(preset, [MAC], "Cam", CLIENT_ZONE,
                               EXTERNAL_ZONE, idx, allow_inbound=False)
        assert all(p["connection_state_type"] == "CUSTOM" for p in on)
        assert all(p["connection_state_type"] == "ALL" for p in off)

    def test_absolute_isolation_still_blocks_outbound(self):
        on, off = self._build(True), self._build(False)
        assert [p["action"] for p in on] == [p["action"] for p in off]
        assert ([p["destination"]["zone_id"] for p in on]
                == [p["destination"]["zone_id"] for p in off])

    def test_inbound_is_not_a_preset_property(self):
        for preset in P.PRESETS:
            assert "inbound" not in P.PRESET_EFFECTS[preset]

    def test_path_labels_cover_the_inbound_row(self):
        assert "inbound" in P.PATH_LABELS


class TestDnsLockdown:
    """
    The allow rule must evaluate before the blocks. If it does not, the chosen
    networks lose DNS entirely — a very visible outage — so ordering is
    checked after the fact rather than assumed.
    """

    NETS = ["netA"]
    RESOLVERS = ["192.168.200.50", "192.168.200.51"]

    def _build(self, block_dot=False):
        # All test resolvers are LAN-side, so they go in lan_resolvers with an
        # empty wan_resolvers. dns_policy_count()'s defaults (LAN allow, no WAN
        # allow) match: two blocks + one allow (+ two more for DoT).
        return P.build_dns_lockdown(
            self.NETS, "IDIoT", self.RESOLVERS, [],
            CLIENT_ZONE, EXTERNAL_ZONE,
            P.next_free_index([], P.dns_policy_count(block_dot)),
            block_dot=block_dot,
        )

    def test_allow_is_created_first(self):
        assert self._build()[0]["action"] == "ALLOW"

    def test_allow_precedes_every_block(self):
        assert P.dns_order_is_safe(self._build()) is True

    def test_order_check_catches_a_bad_outcome(self):
        """If the controller reorders, this must fail rather than pass."""
        pols = self._build()
        pols[0]["index"] = 99999          # allow pushed below the blocks
        assert P.dns_order_is_safe(pols) is False

    def test_order_check_requires_both_kinds(self):
        assert P.dns_order_is_safe([]) is False
        assert P.dns_order_is_safe([{"action": "ALLOW", "index": 1}]) is False

    def test_blocks_cover_lan_and_internet(self):
        zones = {p["destination"]["zone_id"] for p in self._build()
                 if p["action"] == "BLOCK"}
        assert zones == {CLIENT_ZONE, EXTERNAL_ZONE}

    def test_allow_targets_only_the_approved_resolvers(self):
        allow = self._build()[0]
        assert allow["destination"]["ips"] == self.RESOLVERS
        assert allow["destination"]["port"] == "53"

    def test_dot_is_optional_and_adds_two_rules(self):
        assert len(self._build(False)) == 3
        assert len(self._build(True)) == 5
        ports = {p["destination"]["port"] for p in self._build(True)}
        assert ports == {"53", "853"}

    def test_every_rule_is_marked_and_identifiable(self):
        for pol in self._build(True):
            assert P.is_house_arrest(pol)
            assert P.is_dns_policy(pol)
            assert not P.is_network_policy(pol)

    def test_label_round_trips(self):
        assert P.dns_label_from_policy(self._build()[1]) == "IDIoT"

    def test_requires_networks_and_resolvers(self):
        with pytest.raises(ValueError):
            P.build_dns_lockdown([], "x", self.RESOLVERS, [],
                                 CLIENT_ZONE, EXTERNAL_ZONE, [1, 2, 3])
        with pytest.raises(ValueError):
            P.build_dns_lockdown(self.NETS, "x", [], [],
                                 CLIENT_ZONE, EXTERNAL_ZONE, [1, 2, 3])

    def test_too_few_indexes_rejected(self):
        with pytest.raises(ValueError):
            P.build_dns_lockdown(self.NETS, "x", self.RESOLVERS, [],
                                 CLIENT_ZONE, EXTERNAL_ZONE, [1])

    def test_doh_limitation_is_disclosed(self):
        assert any("HTTPS" in c for c in P.DNS_CAVEATS)

    def test_same_network_resolver_limitation_is_disclosed(self):
        assert any("OWN network" in c for c in P.DNS_CAVEATS)


class TestZoneResolution:
    """
    Zones are found by `zone_key`, not display name — a renamed "Internal"
    keeps zone_key "internal" (measured 2026-09-17). Name matching survives
    only as a fallback for firmware without zone_key.
    """

    ZONES = [
        {"_id": "z-int", "name": "Homebase", "zone_key": "internal",
         "network_ids": ["n1", "n2"]},
        {"_id": "z-ext", "name": "Outside", "zone_key": "external",
         "network_ids": ["wan1"]},
        {"_id": "z-gw", "name": "Gateway", "zone_key": "gateway",
         "network_ids": []},
        {"_id": "z-vpn", "name": "Vpn", "zone_key": "vpn",
         "network_ids": ["n-vpn"]},
        {"_id": "z-custom", "name": "Servers", "network_ids": ["n3"]},
    ]

    def test_renamed_default_zones_still_found(self):
        assert P.find_zone_id(self.ZONES, "internal") == "z-int"
        assert P.find_zone_id(self.ZONES, "external") == "z-ext"

    def test_name_fallback_without_zone_key(self):
        legacy = [{"_id": "a", "name": "Internal"}, {"_id": "b", "name": "External"}]
        assert P.find_zone_id(legacy, "internal") == "a"
        assert P.find_zone_id(legacy, "external") == "b"

    def test_missing_zone_is_none_not_a_guess(self):
        assert P.find_zone_id([{"_id": "a", "name": "Whatever"}], "internal") is None

    def test_network_zone_prefers_firewall_zone_id(self):
        net = {"_id": "n9", "firewall_zone_id": "z-custom"}
        assert P.zone_of_network(net, self.ZONES) == "z-custom"

    def test_network_zone_falls_back_to_membership(self):
        assert P.zone_of_network({"_id": "n3"}, self.ZONES) == "z-custom"

    def test_unlinked_network_is_none(self):
        assert P.zone_of_network({"_id": "n-unknown"}, self.ZONES) is None
        assert P.zone_of_network({}, self.ZONES) is None

    def test_other_lan_zones_excludes_external_gateway_empty_and_self(self):
        others = P.other_lan_zones(self.ZONES, "z-int")
        assert {z["_id"] for z in others} == {"z-vpn", "z-custom"}

    def test_zone_name_never_raises(self):
        assert P.zone_name(self.ZONES, "z-int") == "Homebase"
        assert P.zone_name(self.ZONES, "nope") == "unknown zone"
        assert P.zone_name(None, None) == "unknown zone"


class TestZoneAwareResolverClassification:
    """
    A resolver is allowed in the zone pair it is reached through. One sitting
    on a LAN network in a DIFFERENT zone than the locked networks is outside
    every pair these rules write — it must come back as foreign, not as a LAN
    resolver, or the allow lands in a pair where it does nothing.
    """

    ZONES = [
        {"_id": "z-int", "name": "Internal", "zone_key": "internal",
         "network_ids": ["n1"]},
        {"_id": "z-srv", "name": "Servers", "zone_key": None,
         "network_ids": ["n2"]},
    ]
    NETWORKS = [
        {"_id": "n1", "name": "Default", "ip_subnet": "192.168.1.1/24",
         "firewall_zone_id": "z-int"},
        {"_id": "n2", "name": "SrvNet", "ip_subnet": "10.10.0.1/24",
         "firewall_zone_id": "z-srv"},
        {"_id": "wan", "name": "WAN", "purpose": "wan",
         "ip_subnet": "203.0.113.1/30"},
    ]

    def test_same_zone_resolver_is_lan(self):
        lan, wan, foreign = P.classify_resolvers(
            ["192.168.1.53"], self.NETWORKS, self.ZONES, "z-int")
        assert (lan, wan, foreign) == (["192.168.1.53"], [], [])

    def test_public_resolver_is_wan(self):
        lan, wan, foreign = P.classify_resolvers(
            ["1.1.1.1"], self.NETWORKS, self.ZONES, "z-int")
        assert (lan, wan, foreign) == ([], ["1.1.1.1"], [])

    def test_other_zone_resolver_is_foreign(self):
        lan, wan, foreign = P.classify_resolvers(
            ["10.10.0.53"], self.NETWORKS, self.ZONES, "z-int")
        assert lan == [] and wan == []
        assert foreign == [{"ip": "10.10.0.53", "network": "SrvNet",
                            "zone_id": "z-srv"}]

    def test_without_zone_context_behaves_like_before(self):
        lan, wan, foreign = P.classify_resolvers(
            ["10.10.0.53", "1.1.1.1"], self.NETWORKS)
        assert lan == ["10.10.0.53"]
        assert wan == ["1.1.1.1"]
        assert foreign == []

    def test_foreign_only_selection_still_builds_blocks(self):
        pols = P.build_dns_lockdown(
            ["n1"], "Default", [], [], "z-int", "z-ext",
            P.next_free_index([], P.dns_policy_count(False, False, False)),
            foreign_resolvers=[{"ip": "10.10.0.53", "network": "SrvNet",
                                "zone_id": "z-srv"}],
        )
        assert [p["action"] for p in pols] == ["BLOCK", "BLOCK"]

    def test_no_resolvers_at_all_still_refused(self):
        with pytest.raises(ValueError):
            P.build_dns_lockdown(["n1"], "x", [], [], "z-int", "z-ext", [1, 2])

    def test_blocks_only_set_is_safe_when_no_allow_expected(self):
        blocks = [
            {"action": "BLOCK", "index": 10000,
             "source": {"zone_id": "z-int"}, "destination": {"zone_id": "z-int"}},
            {"action": "BLOCK", "index": 10000,
             "source": {"zone_id": "z-int"}, "destination": {"zone_id": "z-ext"}},
        ]
        assert P.dns_order_is_safe(blocks, expect_allow=False) is True
        assert P.dns_order_is_safe(blocks) is False  # default still strict


class TestDeviceZoneAttribution:
    """MAC -> known-client -> last_connection_network_id -> firewall zone."""

    from tools.house_arrest.routers.arrest import _device_zone
    _device_zone = staticmethod(_device_zone)

    ZONES = [
        {"_id": "z-int", "name": "Internal", "zone_key": "internal",
         "network_ids": ["n1"]},
        {"_id": "z-srv", "name": "Servers", "network_ids": ["n2"]},
    ]
    NETWORKS = [
        {"_id": "n1", "name": "Default", "firewall_zone_id": "z-int"},
        {"_id": "n2", "name": "SrvNet", "firewall_zone_id": "z-srv"},
    ]
    KNOWN = [
        {"mac": "aa:aa:aa:aa:aa:01", "last_connection_network_id": "n1"},
        {"mac": "aa:aa:aa:aa:aa:02", "last_connection_network_id": "n2"},
        {"mac": "aa:aa:aa:aa:aa:03"},
    ]

    def _run(self, macs):
        caveats = []
        zone, err = self._device_zone(
            macs, self.KNOWN, self.NETWORKS, self.ZONES, "z-int", caveats)
        return zone, err, caveats

    def test_internal_device_scopes_to_internal_no_caveat(self):
        zone, err, caveats = self._run(["aa:aa:aa:aa:aa:01"])
        assert (zone, err, caveats) == ("z-int", None, [])

    def test_custom_zone_device_scopes_to_its_zone_with_caveat(self):
        zone, err, caveats = self._run(["AA:AA:AA:AA:AA:02"])
        assert zone == "z-srv" and err is None
        assert any("Servers" in c for c in caveats)

    def test_unattributable_device_falls_back_to_internal(self):
        zone, err, caveats = self._run(["aa:aa:aa:aa:aa:03"])
        assert (zone, err, caveats) == ("z-int", None, [])

    def test_unknown_mac_falls_back_to_internal(self):
        zone, err, caveats = self._run(["ff:ff:ff:ff:ff:ff"])
        assert (zone, err, caveats) == ("z-int", None, [])

    def test_mixed_zone_selection_is_refused(self):
        zone, err, caveats = self._run(
            ["aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02"])
        assert zone is None
        assert "different firewall zones" in err

class TestMdnsScope:
    """The site-wide mDNS scope list, as the matrix toggle edits it."""

    NETWORKS = [
        {"_id": "n1", "name": "Default"},
        {"_id": "n2", "name": "IoT"},
        {"_id": "wan", "name": "WAN", "purpose": "wan"},
    ]

    def test_some_returns_the_stored_list(self):
        cfg = {"mdns_enabled_for": "some",
               "mdns_enabled_for_network_ids": ["n1", "n2"]}
        assert P.mdns_effective_ids(cfg, self.NETWORKS) == ["n1", "n2"]

    def test_all_expands_to_every_lan_network(self):
        cfg = {"mdns_enabled_for": "all"}
        assert P.mdns_effective_ids(cfg, self.NETWORKS) == ["n1", "n2"]

    def test_none_and_missing_read_as_empty(self):
        assert P.mdns_effective_ids({"mdns_enabled_for": "none"}, self.NETWORKS) == []
        assert P.mdns_effective_ids(None, self.NETWORKS) == []
        assert P.mdns_effective_ids({}, self.NETWORKS) == []


class TestDisabledPolicyDetection:
    """
    A rule toggled off in the UniFi UI enforces nothing and must never be
    reported green. Happened for real: a paused DNS rule showed "Enforcing"
    for a day while troubleshooting (2026-09-17/18).
    """

    KNOWN = {"aa:bb:cc:dd:ee:01": "Cam"}

    def _pol(self, enabled, mac="aa:bb:cc:dd:ee:01"):
        return {
            "_id": "p1",
            "name": "House Arrest: Cam — no internet",
            "description": P.describe("Full lockdown for Cam"),
            "enabled": enabled,
            "source": {"matching_target": "CLIENT_MACS", "client_macs": [mac]},
        }

    def test_disabled_policy_is_flagged(self):
        rows = P.check_breakage([self._pol(False)], self.KNOWN)
        assert rows[0]["status"] == P.DISABLED

    def test_enabled_policy_stays_ok(self):
        rows = P.check_breakage([self._pol(True)], self.KNOWN)
        assert rows[0]["status"] == P.OK

    def test_missing_enabled_field_treated_as_enabled(self):
        pol = self._pol(True)
        del pol["enabled"]
        rows = P.check_breakage([pol], self.KNOWN)
        assert rows[0]["status"] == P.OK

    def test_disabled_outranks_rotation(self):
        # Disabled AND the MAC is gone: "re-enable it" comes first.
        rows = P.check_breakage([self._pol(False, mac="aa:bb:cc:dd:ee:99")],
                                self.KNOWN)
        assert rows[0]["status"] == P.DISABLED
