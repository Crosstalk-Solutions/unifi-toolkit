"""
UI Toolkit - Unified FastAPI Application

This is the main application that mounts all available tools as sub-applications.
"""
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from shared.database import get_database
from shared.config import get_settings
from shared.websocket_manager import get_ws_manager
from shared.unifi_session import close_shared_client
from tools.wifi_stalker.main import create_app as create_stalker_app
from tools.wifi_stalker.scheduler import start_scheduler, stop_scheduler
from tools.threat_watch.main import create_app as create_threat_watch_app
from tools.threat_watch.scheduler import start_scheduler as start_threat_scheduler, stop_scheduler as stop_threat_scheduler
from tools.network_pulse.main import create_app as create_pulse_app
from tools.network_pulse.scheduler import start_scheduler as start_pulse_scheduler, stop_scheduler as stop_pulse_scheduler

# Import authentication router and middleware
from app.routers.auth import router as auth_router, AuthMiddleware, is_auth_enabled, verify_session
from app.routers.config import router as config_router

# Configure logging - respect LOG_LEVEL from environment
log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_str, logging.INFO)
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Template directory for main dashboard
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def run_migrations():
    """
    Run Alembic migrations safely at startup.

    Handles common schema sync issues where the database schema is ahead of
    the migration history (e.g., after manual schema changes or version jumps).
    """
    try:
        from alembic.config import Config
        from alembic import command

        alembic_cfg = Config("alembic.ini")

        # Try to run migrations normally
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations completed successfully")

    except Exception as e:
        error_msg = str(e).lower()

        # Check for common schema sync issues
        schema_sync_errors = [
            "already exists",
            "duplicate column",
            "table already exists",
            "unique constraint failed",
        ]

        is_schema_sync_issue = any(err in error_msg for err in schema_sync_errors)

        if is_schema_sync_issue:
            logger.warning(f"Migration detected schema sync issue: {e}")
            logger.info("Database schema appears to be ahead of migration history.")
            logger.info("Attempting to synchronize migration history...")

            try:
                from alembic.config import Config
                from alembic import command

                alembic_cfg = Config("alembic.ini")
                command.stamp(alembic_cfg, "head")
                logger.info("Migration history synchronized with current schema")
            except Exception as stamp_error:
                logger.error(f"Failed to synchronize migration history: {stamp_error}")
                logger.error("Manual intervention may be required.")
                logger.error("Try running: alembic stamp head")
        else:
            # Unknown error - log it clearly
            logger.error(f"Migration failed with unexpected error: {e}")
            logger.error("The application will continue, but some features may not work correctly.")
            logger.error("Check the database schema and migration history.")


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

    # Note: Migrations are now run in run.py BEFORE uvicorn starts
    # This avoids async/sync issues that caused hangs on Synology NAS

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

    # Start Network Pulse scheduler
    logger.info("Starting Network Pulse scheduler...")
    await start_pulse_scheduler()
    logger.info("Network Pulse scheduler started")

    logger.info("UI Toolkit started successfully")

    yield

    # Shutdown
    logger.info("Shutting down UI Toolkit...")

    # Close shared UniFi session
    await close_shared_client()

    # Stop Network Pulse scheduler
    logger.info("Stopping Network Pulse scheduler...")
    await stop_pulse_scheduler()
    logger.info("Network Pulse scheduler stopped")

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
    version="1.9.20",
    lifespan=lifespan
)

# Security headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

app.add_middleware(SecurityHeadersMiddleware)

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

# Mount Network Pulse sub-application
pulse_app = create_pulse_app()
app.mount("/pulse", pulse_app)

# Mount main app static files (for dashboard)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """
    Main dashboard - shows available tools
    """
    from app import __version__ as app_version
    from tools.wifi_stalker import __version__ as stalker_version
    from tools.threat_watch import __version__ as threat_watch_version
    from tools.network_pulse import __version__ as pulse_version

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "auth_enabled": is_auth_enabled(),
            "app_version": app_version,
            "stalker_version": stalker_version,
            "threat_watch_version": threat_watch_version,
            "pulse_version": pulse_version
        }
    )


@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring
    """
    from app import __version__ as app_version
    from tools.wifi_stalker import __version__ as stalker_version
    from tools.threat_watch import __version__ as threat_watch_version
    from tools.network_pulse import __version__ as pulse_version

    return {
        "status": "healthy",
        "version": app_version,
        "tools": {
            "wifi_stalker": stalker_version,
            "threat_watch": threat_watch_version,
            "network_pulse": pulse_version
        }
    }


@app.get("/api/debug-info")
async def get_debug_info():
    """
    Get non-sensitive debug information for issue reporting.

    Returns system info that helps with troubleshooting without
    exposing sensitive data like IPs, credentials, or hostnames.
    """
    import sys
    from pathlib import Path
    from app import __version__ as app_version
    from tools.wifi_stalker import __version__ as stalker_version
    from tools.threat_watch import __version__ as threat_watch_version
    from tools.network_pulse import __version__ as pulse_version
    from shared import cache

    settings = get_settings()

    # Detect if running in Docker
    is_docker = Path("/.dockerenv").exists()

    # Get cached gateway info (if available)
    gateway_info = cache.get_gateway_info()
    ips_settings = cache.get_ips_settings()

    # Build response with non-sensitive info only
    debug_info = {
        "app_version": app_version,
        "tool_versions": {
            "wifi_stalker": stalker_version,
            "threat_watch": threat_watch_version,
            "network_pulse": pulse_version
        },
        "deployment": {
            "type": settings.deployment_type,
            "docker": is_docker,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        },
        "gateway": {
            "model": gateway_info.get("gateway_model") if gateway_info else None,
            "name": gateway_info.get("gateway_name") if gateway_info else None,
            "supports_ids_ips": gateway_info.get("supports_ids_ips") if gateway_info else None,
            "is_unifi_os": gateway_info.get("is_unifi_os") if gateway_info else None,
            "ips_mode": ips_settings.get("ips_mode") if ips_settings else None
        }
    }

    return debug_info


@app.get("/api/update-check")
async def check_for_update():
    """Check if a newer version is available on GitHub."""
    import aiohttp
    from app import __version__ as app_version
    from shared import cache

    cached = cache.get_update_check()
    if cached is not None:
        return cached

    result = {
        "update_available": False,
        "current_version": app_version
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.github.com/repos/Crosstalk-Solutions/unifi-toolkit/releases/latest",
                headers={"Accept": "application/vnd.github.v3+json", "User-Agent": "UniFi-Toolkit"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    tag = data.get("tag_name", "")
                    latest = tag.lstrip("v")
                    result["latest_version"] = latest
                    result["release_url"] = data.get("html_url", "")

                    try:
                        current_parts = tuple(int(x) for x in app_version.split("."))
                        latest_parts = tuple(int(x) for x in latest.split("."))
                        result["update_available"] = latest_parts > current_parts
                    except (ValueError, AttributeError):
                        pass
                else:
                    result["error"] = f"GitHub API returned {resp.status}"
    except Exception as e:
        logger.warning(f"Update check failed: {e}")
        result["error"] = "Unable to check for updates"

    cache.set_update_check(result)
    return result


@app.get("/api/system-status")
async def get_system_status():
    """
    Get system status including gateway info, health, stats, and IPS settings.
    Also caches gateway info and IPS settings for use by other endpoints.
    """
    from shared.unifi_client import UniFiClient
    from shared.crypto import decrypt_password, decrypt_api_key
    from shared.models.unifi_config import UniFiConfig
    from shared import cache

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
        # is_unifi_os is auto-detected during connection
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
                cache.invalidate_all()
                return {
                    "configured": True,
                    "connected": False,
                    "error": "Failed to connect to UniFi controller"
                }

            # Get system info and health
            system_info = await client.get_system_info()
            health = await client.get_health()

            # Also get gateway info and IPS settings for caching
            # (these will be reused by gateway-check endpoint)
            gateway_info = await client.get_gateway_info()
            ips_settings = None

            # Only fetch IPS settings if we have a gateway that supports it
            # and we're on UniFi OS (legacy controllers don't expose IPS API)
            if gateway_info.get("has_gateway") and gateway_info.get("supports_ids_ips") and client.is_unifi_os:
                ips_settings = await client.get_ips_settings()

            # Cache the results
            cache.set_gateway_info({
                **gateway_info,
                "is_unifi_os": client.is_unifi_os
            })
            if ips_settings:
                cache.set_ips_settings(ips_settings)

            return {
                "configured": True,
                "connected": True,
                "system": system_info,
                "health": health,
                "gateway": gateway_info,
                "ips_settings": ips_settings
            }

        finally:
            await client.disconnect()

    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        cache.invalidate_all()
        return {
            "configured": True,
            "connected": False,
            "error": str(e)
        }


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time updates.

    In production mode, requires valid session authentication via cookie.
    """
    # Check authentication in production mode
    if is_auth_enabled():
        # Get session token from cookies
        session_token = websocket.cookies.get("session_token")
        if not session_token or not verify_session(session_token):
            # Reject unauthenticated WebSocket connections
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            logger.warning("WebSocket connection rejected: not authenticated")
            return

    ws_manager = get_ws_manager()
    await ws_manager.connect(websocket)
    try:
        while True:
            # Wait for messages from client (e.g., ping)
            data = await websocket.receive_text()

            if data == "ping":
                # Respond with pong
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass  # Normal disconnect
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        ws_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    settings = get_settings()

    # Set log level based on settings
    log_level = settings.log_level.lower()

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.app_port,
        reload=False,
        log_level=log_level
    )
