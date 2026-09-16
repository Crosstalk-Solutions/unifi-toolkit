"""
House Arrest FastAPI application factory
"""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import logging

from tools.house_arrest import __version__
from tools.house_arrest import policies as P
from tools.house_arrest.routers import arrest
from tools.house_arrest.models import SystemStatus
from shared.unifi_session import get_shared_client

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    """
    Create and configure the House Arrest sub-application

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title="House Arrest",
        version=__version__,
        description="Device lockdown via UniFi zone-based firewall policies"
    )

    app.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="arrest_static"
    )

    app.include_router(arrest.router)

    @app.get("/")
    async def dashboard(request: Request):
        """Serve the House Arrest dashboard"""
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "version": __version__,
                "presets": P.preset_catalog(),
                "path_labels": P.PATH_LABELS,
            }
        )

    @app.get("/api/status", response_model=SystemStatus, tags=["status"])
    async def get_status():
        """Lightweight status for the dashboard header."""
        client = await get_shared_client()
        if client is None:
            return SystemStatus(version=__version__, connected=False)

        try:
            all_policies = await client.get_firewall_policies()
            known = await client.get_known_clients()
        except Exception as e:
            logger.error(f"House Arrest status failed: {e}")
            return SystemStatus(version=__version__, connected=False)

        ours = P.find_ours(all_policies)
        known_macs = {
            (c.get("mac") or "").lower(): c.get("name") or c.get("hostname") or ""
            for c in known or []
        }
        health = P.check_breakage(ours, known_macs)

        return SystemStatus(
            version=__version__,
            connected=True,
            arrests_active=len(ours),
            policies_broken=len([h for h in health if h["status"] != P.OK]),
        )

    return app
