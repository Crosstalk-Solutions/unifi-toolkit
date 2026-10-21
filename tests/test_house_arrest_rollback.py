"""
Tests for House Arrest's lockdown rollback (#155).

A lockdown that fails partway through is undone by _roll_back_lockdown().
It must never leave a neighbour-block BLOCK without its ALLOW, because a
lone BLOCK cuts the device off from the gateway, DHCP included.
"""
from tools.house_arrest import policies as P
from tools.house_arrest.routers.arrest import _roll_back_lockdown


class FakeClient:
    """Records delete order; ids in `fail` refuse to delete."""

    def __init__(self, fail=()):
        self.fail = set(fail)
        self.calls = []

    async def delete_acl_rule(self, rid):
        self.calls.append(rid)
        return rid not in self.fail

    async def delete_firewall_policy(self, pid):
        self.calls.append(pid)
        return pid not in self.fail


def _acl(rid, action):
    return {"_id": rid, "name": f"HA {rid}", "action": action}


# Two networks: one ALLOW/BLOCK pair each, in creation (payload) order.
ACLS = [_acl("allow1", "ALLOW"), _acl("block1", "BLOCK"),
        _acl("allow2", "ALLOW"), _acl("block2", "BLOCK")]
POLICIES = [{"_id": "fw1", "name": "[HouseArrest] Quarantine for tv"}]


class TestAclDeleteOrder:
    def test_blocks_come_before_allows(self):
        order = [r["_id"] for r in P.acl_delete_order(ACLS)]
        assert order == ["block1", "block2", "allow1", "allow2"]


class TestRollBackLockdown:
    async def test_clean_rollback_deletes_blocks_first(self):
        client = FakeClient()
        left = await _roll_back_lockdown(client, POLICIES, ACLS)
        assert left == []
        assert client.calls == ["block1", "block2", "allow1", "allow2", "fw1"]

    async def test_failed_block_delete_stops_and_keeps_firewall_half(self):
        client = FakeClient(fail={"block1"})
        left = await _roll_back_lockdown(client, POLICIES, ACLS)
        # Nothing after the failed BLOCK is touched, so its ALLOW survives
        # and the lockdown stays visible for Release to clean up.
        assert client.calls == ["block1"]
        assert set(left) == {"HA allow1", "HA block1", "HA allow2", "HA block2",
                             "[HouseArrest] Quarantine for tv"}

    async def test_failed_allow_delete_is_reported_and_rollback_continues(self):
        client = FakeClient(fail={"allow2"})
        left = await _roll_back_lockdown(client, POLICIES, ACLS)
        assert left == ["HA allow2"]
        assert "fw1" in client.calls

    async def test_firewall_only_rollback(self):
        client = FakeClient(fail={"fw1"})
        left = await _roll_back_lockdown(client, POLICIES, [])
        assert left == ["[HouseArrest] Quarantine for tv"]
