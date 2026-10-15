"""Tests for is_wifi_device() AP detection (#150)."""
from shared.unifi_client import is_wifi_device

RADIOS = [{"name": "wifi0", "radio": "na"}]


def test_standalone_ap():
    assert is_wifi_device({"type": "uap", "model": "U7PRO"})


def test_express_in_ap_mode():
    assert is_wifi_device({"type": "udm", "model": "UX", "device_mode_override": "mesh"})


def test_gateway_with_built_in_radios():
    # UDR 5G Max (#149/#150), UDR7, Express as gateway
    assert is_wifi_device({"type": "udm", "model": "UDMA6B9", "radio_table": RADIOS})
    assert is_wifi_device({"type": "udm", "model": "UDMA67A", "radio_table": RADIOS})
    assert is_wifi_device({"type": "ux", "model": "UX", "radio_table": RADIOS})


def test_wired_only_gateway_is_not_an_ap():
    assert not is_wifi_device({"type": "udm", "model": "UDMPRO"})
    assert not is_wifi_device({"type": "udm", "model": "UCGMAX", "radio_table": []})


def test_switches_and_other_gateways_are_not_aps():
    assert not is_wifi_device({"type": "usw", "model": "USL24P", "radio_table": RADIOS})
    assert not is_wifi_device({"type": "uxg", "model": "UXG"})
    assert not is_wifi_device({"type": "ugw", "model": "UGW3"})
