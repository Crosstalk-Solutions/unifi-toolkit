"""Tests for the Wi-Fi Stalker WebSocket route (#147)."""
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from tools.wifi_stalker.main import create_app


def test_ws_accepts_and_answers_ping_in_local_mode():
    with patch.dict(os.environ, {"DEPLOYMENT_TYPE": "local"}):
        client = TestClient(create_app())
        with client.websocket_connect("/ws") as ws:
            ws.send_text("ping")
            assert ws.receive_text() == '{"type":"pong"}'


def test_ws_rejects_unauthenticated_in_production_mode():
    with patch.dict(os.environ, {"DEPLOYMENT_TYPE": "production"}):
        client = TestClient(create_app())
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws") as ws:
                ws.receive_text()
