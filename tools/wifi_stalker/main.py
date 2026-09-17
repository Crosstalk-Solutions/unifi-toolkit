"""
Wi-Fi Stalker FastAPI application factory
"""
from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from tools.wifi_stalker import __version__
from tools.wifi_stalker.routers import devices, config, webhooks
from tools.wifi_stalker.database import TrackedDevice
from tools.wifi_stalker.models import SystemStatus
from tools.wifi_stalker.scheduler import get_last_refresh
from shared.database import get_db_session
from shared.config import get_settings

# Get the directory containing this file
BASE_DIR = Path(__file__).parent

# Set up templates and static files
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    """
    Create and configure the Wi-Fi Stalker sub-application

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title="Wi-Fi Stalker",
        version=__version__,
        description="Track specific Wi-Fi client devices through UniFi infrastructure"
    )

    # Mount static files
    app.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="static"
    )

    # Include API routers
    app.include_router(devices.router)
    app.include_router(config.router)
    app.include_router(webhooks.router)

    # Dashboard route
    @app.get("/")
    async def dashboard(request: Request):
        """Serve the Wi-Fi Stalker dashboard"""
        return templates.TemplateResponse(
            request,
            "index.html",
            {"version": __version__}
        )

    # Status endpoint
    @app.get("/api/status", response_model=SystemStatus, tags=["status"])
    async def get_status(
        db: AsyncSession = Depends(get_db_session)
    ):
        """
        Get system status including last refresh time and device counts
        """
        settings = get_settings()

        # Get tracked device counts
        result = await db.execute(select(TrackedDevice))
        tracked_devices = result.scalars().all()

        tracked_count = len(tracked_devices)
        connected_count = sum(1 for d in tracked_devices if d.is_connected)

        return SystemStatus(
            last_refresh=get_last_refresh(),
            tracked_devices=tracked_count,
            connected_devices=connected_count,
            refresh_interval_seconds=settings.stalker_refresh_interval
        )

    return app
