"""
Tests for webhook URL validation, including the WEBHOOK_ALLOW_PRIVATE_IPS opt-in.
"""
from unittest.mock import patch

from shared.url_validator import is_ip_blocked, validate_webhook_url


def _with_flag(value: bool):
    return patch("shared.url_validator._private_targets_allowed", return_value=value)


class TestDefaultBehavior:
    def test_public_url_allowed(self):
        with _with_flag(False):
            ok, err = validate_webhook_url("https://hooks.slack.com/services/T00/B00/xxx")
        assert ok, err

    def test_private_ip_blocked_with_hint(self):
        with _with_flag(False):
            ok, err = validate_webhook_url("http://192.168.1.50:8123/api/webhook/abc")
        assert not ok
        assert "WEBHOOK_ALLOW_PRIVATE_IPS" in err

    def test_localhost_blocked_with_hint(self):
        with _with_flag(False):
            ok, err = validate_webhook_url("http://localhost:8123/hook")
        assert not ok
        assert "WEBHOOK_ALLOW_PRIVATE_IPS" in err

    def test_metadata_ip_blocked_without_hint(self):
        with _with_flag(False):
            ok, err = validate_webhook_url("http://169.254.169.254/latest/meta-data/")
        assert not ok
        assert "WEBHOOK_ALLOW_PRIVATE_IPS" not in err


class TestPrivateAllowed:
    def test_rfc1918_allowed(self):
        with _with_flag(True):
            for url in (
                "http://192.168.1.50:8123/api/webhook/abc",
                "http://10.0.0.5/notify",
                "http://172.16.0.10:5678/webhook/wh1",
            ):
                ok, err = validate_webhook_url(url)
                assert ok, f"{url}: {err}"

    def test_localhost_and_loopback_allowed(self):
        with _with_flag(True):
            assert validate_webhook_url("http://localhost:8123/hook")[0]
            assert validate_webhook_url("http://127.0.0.1:8080/hook")[0]

    def test_tailscale_range_allowed(self):
        with _with_flag(True):
            ok, err = validate_webhook_url("http://100.101.102.103/notify")
            assert ok, err

    def test_metadata_ip_still_blocked(self):
        with _with_flag(True):
            assert not validate_webhook_url("http://169.254.169.254/latest/meta-data/")[0]

    def test_metadata_hostname_still_blocked(self):
        with _with_flag(True):
            assert not validate_webhook_url("http://metadata.google.internal/computeMetadata/v1/")[0]

    def test_link_local_and_multicast_still_blocked(self):
        with _with_flag(True):
            assert is_ip_blocked("169.254.10.10", allow_private=True)
            assert is_ip_blocked("224.0.0.1", allow_private=True)
            assert is_ip_blocked("fe80::1", allow_private=True)


class TestIsIpBlocked:
    def test_private_ranges_respect_flag(self):
        for ip in ("10.1.2.3", "172.20.0.1", "192.168.0.1", "127.0.0.1", "100.64.0.1", "fd00::1", "::1"):
            assert is_ip_blocked(ip, allow_private=False), ip
            assert not is_ip_blocked(ip, allow_private=True), ip

    def test_public_ip_never_blocked(self):
        assert not is_ip_blocked("8.8.8.8", allow_private=False)

    def test_invalid_ip_not_blocked(self):
        assert not is_ip_blocked("not-an-ip", allow_private=False)
