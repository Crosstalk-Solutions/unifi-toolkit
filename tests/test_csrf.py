"""Tests for the CSRF check in AuthMiddleware (#145)."""
import os
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routers.auth import AuthMiddleware


def _app():
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.post("/stalker/api/devices/{device_id}/block")
    async def block(device_id: int):
        return {"blocked": device_id}

    @app.get("/stalker/api/devices")
    async def devices():
        return []

    return app


@pytest.fixture
def local_client():
    with patch.dict(os.environ, {"DEPLOYMENT_TYPE": "local"}):
        yield TestClient(_app())


class TestCsrfLocalMode:
    """Local mode has no login, so the CSRF header is the only guard."""

    def test_bodyless_post_without_header_rejected(self, local_client):
        resp = local_client.post(
            "/stalker/api/devices/1/block",
            headers={"Origin": "https://evil.example", "Content-Type": "text/plain"},
        )
        assert resp.status_code == 403

    def test_post_with_header_allowed(self, local_client):
        resp = local_client.post(
            "/stalker/api/devices/1/block",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"blocked": 1}

    def test_get_needs_no_header(self, local_client):
        assert local_client.get("/stalker/api/devices").status_code == 200


class TestCsrfProductionMode:
    def test_unauthenticated_post_still_401(self):
        with patch.dict(os.environ, {"DEPLOYMENT_TYPE": "production"}):
            client = TestClient(_app())
            resp = client.post(
                "/stalker/api/devices/1/block",
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            assert resp.status_code == 401
