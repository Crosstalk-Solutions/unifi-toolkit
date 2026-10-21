"""
get_ips_events() must treat an empty v2 answer as an answer (#140).

Falling back on an empty list hit the removed legacy stat/ips/event endpoint
and logged an HTTP 404 on every quiet poll.
"""
from unittest.mock import AsyncMock, Mock, patch

import pytest

from shared.unifi_client import TrafficFlowsUnavailable, UniFiClient


pytestmark = pytest.mark.unit


def _client():
    c = UniFiClient.__new__(UniFiClient)
    c._session = object()
    c.host = "https://unifi"
    c.site = "default"
    return c


async def test_empty_v2_answer_does_not_fall_back():
    c = _client()
    c._session = Mock()
    with patch.object(c, "get_traffic_flows", AsyncMock(return_value=[])):
        assert await c.get_ips_events() == []
    c._session.post.assert_not_called()


async def test_failed_v2_request_falls_back_to_legacy():
    c = _client()
    c._session = Mock()
    c._session.post.side_effect = RuntimeError("legacy called")
    with patch.object(
        c, "get_traffic_flows",
        AsyncMock(side_effect=TrafficFlowsUnavailable("HTTP 500")),
    ):
        assert await c.get_ips_events() == []
    c._session.post.assert_called_once()


class _Resp:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def text(self):
        return ""


async def test_refused_credentials_raise_instead_of_empty():
    # A revoked API key must not read as "no events" (#146): the scheduler
    # needs the exception to drop the session and record why.
    from shared.unifi_client import ConsoleAuthRefused
    c = _client()
    c._session = Mock()
    c._session.post.return_value = _Resp(401)
    with patch.object(
        c, "get_traffic_flows",
        AsyncMock(side_effect=TrafficFlowsUnavailable("HTTP 401")),
    ):
        with pytest.raises(ConsoleAuthRefused):
            await c.get_ips_events()


async def test_removed_legacy_endpoint_still_reads_as_empty():
    c = _client()
    c._session = Mock()
    c._session.post.return_value = _Resp(404)
    with patch.object(
        c, "get_traffic_flows",
        AsyncMock(side_effect=TrafficFlowsUnavailable("HTTP 500")),
    ):
        assert await c.get_ips_events() == []
