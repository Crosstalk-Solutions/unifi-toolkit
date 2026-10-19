"""Saved DNS servers: the cards at the top of House Arrest's DNS tab."""
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from shared.database import get_db_session
from shared.models.base import Base
from tools.house_arrest import policies as P
from tools.house_arrest.routers import arrest

NETWORKS = [
    {"_id": "def", "name": "Default", "purpose": "corporate", "ip_subnet": "192.168.4.1/24",
     "dhcpd_dns_enabled": True, "dhcpd_dns_1": "192.168.4.79", "dhcpd_dns_2": "192.168.4.50"},
    {"_id": "iot", "name": "IoT", "purpose": "corporate", "vlan": "5", "ip_subnet": "192.168.5.1/24",
     "dhcpd_dns_enabled": True, "dhcpd_dns_1": "192.168.4.79", "dhcpd_dns_2": "192.168.5.1"},
    {"_id": "wan", "name": "WAN", "purpose": "wan", "ip_subnet": "203.0.113.2/30"},
]


def _lockdown_policies():
    return P.build_dns_lockdown(
        ["def"], "Default", ["192.168.4.79"], [], "z-int", "z-ext",
        P.next_free_index([], P.dns_policy_count(False, True, False, True)),
        upstream_resolvers=["192.168.4.79"],
    )


class TestFacts:
    def test_server_on_a_lan(self):
        f = P.dns_server_facts("192.168.4.79", NETWORKS, _lockdown_policies())
        assert f["network_id"] == "def" and f["network_name"] == "Default"
        assert f["on_internet"] is False and f["is_gateway"] is False
        assert f["dhcp_networks"] == ["Default", "IoT"]
        assert f["lockdowns"] == ["Default"]
        assert f["upstream_lockdowns"] == ["Default"]

    def test_server_on_the_internet(self):
        f = P.dns_server_facts("1.1.1.1", NETWORKS, [])
        assert f["on_internet"] is True and f["network_id"] is None
        assert f["dhcp_networks"] == [] and f["lockdowns"] == []

    def test_vlan_string_is_normalised(self):
        assert P.dns_server_facts("192.168.5.9", NETWORKS, [])["vlan"] == 5

    def test_gateway_address_is_flagged(self):
        assert P.dns_server_facts("192.168.5.1", NETWORKS, [])["is_gateway"] is True


class TestSuggestions:
    def test_suggests_dhcp_servers_not_yet_saved_and_skips_the_gateway(self):
        s = P.dhcp_suggestions(NETWORKS, ["192.168.4.50"])
        assert s == [{"ip": "192.168.4.79", "dhcp_networks": ["Default", "IoT"]}]

    def test_disabled_override_suggests_nothing(self):
        nets = [dict(NETWORKS[0], dhcpd_dns_enabled=False)]
        assert P.dhcp_suggestions(nets, []) == []


class TestAdminUrl:
    def test_defaults(self):
        assert P.default_admin_url("pihole", "10.0.0.2") == "http://10.0.0.2/admin"
        assert P.default_admin_url("adguard", "10.0.0.2") == "http://10.0.0.2/"
        assert P.default_admin_url("generic", "10.0.0.2") == ""

    def test_custom_port_is_kept(self):
        assert P.check_admin_url(" http://10.0.0.2:8080/admin ") == "http://10.0.0.2:8080/admin"

    @pytest.mark.parametrize("bad", ["javascript:alert(1)", "ftp://x/", "10.0.0.2/admin", "http://"])
    def test_refuses_anything_but_http(self, bad):
        with pytest.raises(ValueError):
            P.check_admin_url(bad)


# ---- API ----

@pytest.fixture
def client():
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool,
                                 connect_args={"check_same_thread": False})
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def session():
        async with factory() as s:
            yield s

    app = FastAPI()
    app.include_router(arrest.router)
    app.dependency_overrides[get_db_session] = session

    view = {"value": (NETWORKS, [], None)}

    async def fake_view():
        return view["value"]

    async def create():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    with TestClient(app) as c:
        c.portal.call(create)
        with patch.object(arrest, "_controller_dns_view", fake_view):
            c.view = view
            yield c


def test_add_list_edit_remove(client):
    r = client.post("/api/dns-servers", json={"ip": "192.168.4.79", "kind": "pihole"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "Pi-hole 192.168.4.79"
    assert body["admin_url"] == "http://192.168.4.79/admin"

    listed = client.get("/api/dns-servers").json()
    assert [s["ip"] for s in listed["servers"]] == ["192.168.4.79"]
    assert listed["servers"][0]["network_name"] == "Default"
    assert [s["ip"] for s in listed["suggestions"]] == ["192.168.4.50"]

    sid = body["id"]
    r = client.put(f"/api/dns-servers/{sid}", json={
        "ip": "192.168.4.79", "name": "Pi-hole 1", "kind": "pihole",
        "admin_url": "http://192.168.4.79:8080/admin"})
    assert r.json()["admin_url"] == "http://192.168.4.79:8080/admin"

    assert client.delete(f"/api/dns-servers/{sid}").json() == {"deleted": True}
    assert client.get("/api/dns-servers").json()["servers"] == []


def test_duplicate_ip_refused(client):
    client.post("/api/dns-servers", json={"ip": "1.1.1.1"})
    r = client.post("/api/dns-servers", json={"ip": "1.1.1.1"})
    assert r.status_code == 409


def test_bad_ip_and_bad_link_refused(client):
    assert client.post("/api/dns-servers", json={"ip": "192.168.4.79 192.168.4.50"}).status_code == 400
    r = client.post("/api/dns-servers", json={"ip": "10.0.0.2", "kind": "pihole",
                                              "admin_url": "javascript:alert(1)"})
    assert r.status_code == 400


def test_generic_kind_has_no_admin_link(client):
    r = client.post("/api/dns-servers", json={"ip": "9.9.9.9", "kind": "generic",
                                              "admin_url": "http://9.9.9.9/"})
    assert r.json()["admin_url"] == ""


def test_remove_refused_while_a_lockdown_uses_it(client):
    sid = client.post("/api/dns-servers", json={"ip": "192.168.4.79"}).json()["id"]
    client.view["value"] = (NETWORKS, _lockdown_policies(), None)
    r = client.delete(f"/api/dns-servers/{sid}")
    assert r.status_code == 409
    assert "Default" in r.json()["detail"]
    # Changing its address is refused too; renaming is fine.
    r = client.put(f"/api/dns-servers/{sid}", json={"ip": "192.168.4.80"})
    assert r.status_code == 409
    r = client.put(f"/api/dns-servers/{sid}", json={"ip": "192.168.4.79", "name": "Pi-hole 1"})
    assert r.status_code == 200


def test_unreadable_controller_still_lists_and_allows_remove(client):
    sid = client.post("/api/dns-servers", json={"ip": "192.168.4.79"}).json()["id"]
    client.view["value"] = ([], [], "Controller unreachable")
    listed = client.get("/api/dns-servers").json()
    assert listed["error"] == "Controller unreachable"
    assert listed["servers"][0]["network_name"] is None
    assert listed["servers"][0]["on_internet"] is None
    assert client.delete(f"/api/dns-servers/{sid}").json() == {"deleted": True}


class TestDnsLockable:
    @pytest.mark.parametrize("purpose,ok", [
        ("corporate", True), ("guest", True), ("site-vpn", False),
        ("remote-user-vpn", False), ("vpn-client", False), ("vlan-only", False),
        ("wan", False), (None, False),
    ])
    def test_only_lan_and_guest(self, purpose, ok):
        assert P.dns_lockable({"purpose": purpose}) is ok
