"""
connection_problem() tells pages why the toolkit can't reach the console,
without the page connecting itself. Threat Watch shows it (#146).
"""
from unittest.mock import AsyncMock, Mock, patch

import pytest

from shared import unifi_session as S


pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset():
    S._shared_client = None
    S._last_connect_error = None
    yield
    S._shared_client = None
    S._last_connect_error = None


def test_no_attempt_yet_is_not_a_problem():
    assert S.connection_problem() is None


def test_failed_attempt_is_reported():
    S._last_connect_error = "The console refused the API key (HTTP 401)."
    assert "API key" in S.connection_problem()


def test_live_session_hides_an_old_error():
    live = Mock()
    live._session = Mock(closed=False)
    S._shared_client = live
    S._last_connect_error = "stale"
    assert S.connection_problem() is None


async def test_saving_new_settings_clears_the_error():
    S._last_connect_error = "The console refused the API key (HTTP 401)."
    await S.invalidate_shared_client()
    assert S.connection_problem() is None


async def test_api_key_refusal_sets_plain_reason():
    from shared.unifi_client import UniFiClient
    c = UniFiClient("https://unifi", api_key="k")
    resp = Mock(status=401)
    cm = AsyncMock()
    cm.__aenter__.return_value = resp
    c._session = Mock()
    c._session.get.return_value = cm
    with patch.object(c, "disconnect", AsyncMock()):
        assert await c._connect_unifi_os_api_key() is False
    assert "refused the API key (HTTP 401)" in c.last_error
