"""
UI Toolkit - Unified FastAPI Application

This is the main application that mounts all available tools as sub-applications.
"""
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from shared.database import get_database
from shared.config import get_settings
from shared.websocket_manager import get_ws_manager
from tools.wifi_stalker.main import create_app as create_stalker_app
from tools.wifi_stalker.scheduler import start_scheduler, stop_scheduler
from tools.threat_watch.main import create_app as create_threat_watch_app
from tools.threat_watch.scheduler import start_scheduler as start_threat_scheduler, stop_scheduler as stop_threat_scheduler

# Import authentication router and middleware
from app.routers.auth import router as auth_router, AuthMiddleware, is_auth_enabled
from app.routers.config import router as config_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Template directory for main dashboard
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager - handles startup and shutdown events
    """
    # Startup
    logger.info("Starting UI Toolkit...")
    settings = get_settings()
    logger.info(f"Log level: {settings.log_level}")

    # Log deployment mode
    deployment_type = os.getenv("DEPLOYMENT_TYPE", "local")
    if deployment_type == "production":
        logger.info("Running in PRODUCTION mode - authentication enabled")
    else:
        logger.info("Running in LOCAL mode - authentication disabled")

    # Initialize database
    logger.info("Initializing database...")
    db = get_database()
    await db.init_db()
    logger.info("Database initialized")

    # Start Wi-Fi Stalker scheduler
    logger.info("Starting Wi-Fi Stalker scheduler...")
    await start_scheduler()
    logger.info("Wi-Fi Stalker scheduler started")

    # Start Threat Watch scheduler
    logger.info("Starting Threat Watch scheduler...")
    await start_threat_scheduler()
    logger.info("Threat Watch scheduler started")

    logger.info("UI Toolkit started successfully")

    yield

    # Shutdown
    logger.info("Shutting down UI Toolkit...")

    # Stop Threat Watch scheduler
    logger.info("Stopping Threat Watch scheduler...")
    await stop_threat_scheduler()
    logger.info("Threat Watch scheduler stopped")

    # Stop Wi-Fi Stalker scheduler
    logger.info("Stopping Wi-Fi Stalker scheduler...")
    await stop_scheduler()
    logger.info("Wi-Fi Stalker scheduler stopped")

    logger.info("UI Toolkit shut down complete")


# Create main application
app = FastAPI(
    title="UI Toolkit",
    description="Comprehensive toolkit for UniFi network management and monitoring",
    version="1.4.0",
    lifespan=lifespan
)

# Add authentication middleware (must be added before routes)
app.add_middleware(AuthMiddleware)

# Include authentication router
app.include_router(auth_router)

# Include configuration router
app.include_router(config_router)

# Mount Wi-Fi Stalker sub-application
stalker_app = create_stalker_app()
app.mount("/stalker", stalker_app)

# Mount Threat Watch sub-application
threat_watch_app = create_threat_watch_app()
app.mount("/threats", threat_watch_app)

# Mount main app static files (for dashboard)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """
    Main dashboard - shows available tools
    """
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "auth_enabled": is_auth_enabled()
        }
    )


@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring
    """
    from tools.wifi_stalker import __version__ as stalker_version
    from tools.threat_watch import __version__ as threat_watch_version

    return {
        "status": "healthy",
        "version": "1.4.0",
        "tools": {
            "wifi_stalker": stalker_version,
            "threat_watch": threat_watch_version
        }
    }


@app.get("/api/system-status")
async def get_system_status():
    """
    Get system status including gateway info, health, and stats
    """
    from shared.unifi_client import UniFiClient
    from shared.crypto import decrypt_password, decrypt_api_key
    from shared.models.unifi_config import UniFiConfig

    db = get_database()

    try:
        # Get UniFi config from database
        async for session in db.get_session():
            from sqlalchemy import select
            result = await session.execute(select(UniFiConfig))
            config = result.scalar_one_or_none()
            break  # Only need one iteration

        if not config:
            return {
                "configured": False,
                "error": "UniFi controller not configured"
            }

        # Decrypt credentials
        password = None
        api_key = None
        if config.password_encrypted:
            password = decrypt_password(config.password_encrypted)
        if config.api_key_encrypted:
            api_key = decrypt_api_key(config.api_key_encrypted)

        # Create client and get system info
        client = UniFiClient(
            host=config.controller_url,
            username=config.username,
            password=password,
            api_key=api_key,
            site=config.site_id,
            verify_ssl=config.verify_ssl
        )

        try:
            connected = await client.connect()
            if not connected:
                return {
                    "configured": True,
                    "connected": False,
                    "error": "Failed to connect to UniFi controller"
                }

            # Get system info and health
            system_info = await client.get_system_info()
            health = await client.get_health()

            return {
                "configured": True,
                "connected": True,
                "system": system_info,
                "health": health
            }

        finally:
            await client.disconnect()

    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return {
            "configured": True,
            "connected": False,
            "error": str(e)
        }


@app.post("/api/speedtest")
async def trigger_speedtest():
    """
    Trigger a speedtest on the UniFi gateway
    """
    from shared.unifi_client import UniFiClient
    from shared.crypto import decrypt_password, decrypt_api_key
    from shared.models.unifi_config import UniFiConfig

    db = get_database()

    try:
        # Get UniFi config from database
        async for session in db.get_session():
            from sqlalchemy import select
            result = await session.execute(select(UniFiConfig))
            config = result.scalar_one_or_none()
            break

        if not config:
            return {"success": False, "error": "UniFi controller not configured"}

        # Decrypt credentials
        password = None
        api_key = None
        if config.password_encrypted:
            password = decrypt_password(config.password_encrypted)
        if config.api_key_encrypted:
            api_key = decrypt_api_key(config.api_key_encrypted)

        # Create client and trigger speedtest
        client = UniFiClient(
            host=config.controller_url,
            username=config.username,
            password=password,
            api_key=api_key,
            site=config.site_id,
            verify_ssl=config.verify_ssl
        )

        try:
            connected = await client.connect()
            if not connected:
                return {"success": False, "error": "Failed to connect to UniFi controller"}

            result = await client.run_speedtest()
            return result

        finally:
            await client.disconnect()

    except Exception as e:
        logger.error(f"Failed to trigger speedtest: {e}")
        return {"success": False, "error": str(e)}


@app.websocket("/ws")
async def websocket_endpoint(websocket):
    """
    WebSocket endpoint for real-time updates
    """
    ws_manager = get_ws_manager()
    await ws_manager.connect(websocket)
    try:
        while True:
            # Wait for messages from client (e.g., ping)
            data = await websocket.receive_text()

            if data == "ping":
                # Respond with pong
                await websocket.send_json({"type": "pong"})
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await ws_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()

    # Set log level based on settings
    log_level = settings.log_level.lower()

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level=log_level
    )
