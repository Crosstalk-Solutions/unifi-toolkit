"""
Network Pulse FastAPI application factory
"""
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
import logging

from tools.network_pulse import __version__
from tools.network_pulse.routers import stats
from tools.network_pulse.models import SystemStatus
from tools.network_pulse.scheduler import get_last_refresh, get_last_error, get_cached_data
from shared.websocket_manager import get_ws_manager
from app.routers.auth import is_auth_enabled, verify_session

logger = logging.getLogger(__name__)

# Get the directory containing this file
BASE_DIR = Path(__file__).parent

# Set up templates and static files
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    """
    Create and configure the Network Pulse sub-application

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title="Network Pulse",
        version=__version__,
        description="Real-time network monitoring dashboard for UniFi"
    )

    # Mount static files
    app.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="pulse_static"
    )

    # Include API routers
    app.include_router(stats.router)

    # Dashboard route
    @app.get("/")
    async def dashboard(request: Request):
        """Serve the Network Pulse dashboard"""
        return templates.TemplateResponse(
            request,
            "index.html",
            {"version": __version__}
        )

    # AP detail page route
    @app.get("/ap/{ap_mac}")
    async def ap_detail_page(request: Request, ap_mac: str):
        """Serve the AP detail page"""
        return templates.TemplateResponse(
            request,
            "ap_detail.html",
            {"ap_mac": ap_mac, "version": __version__}
        )

    # Status endpoint
    @app.get("/api/status", response_model=SystemStatus, tags=["status"])
    async def get_status():
        """Get system status including last refresh time and connection status"""
        cached = get_cached_data()
        return SystemStatus(
            last_refresh=get_last_refresh(),
            is_connected=cached is not None,
            error=get_last_error()
        )

    # WebSocket endpoint for real-time updates
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """
        WebSocket endpoint for real-time dashboard updates.

        In production mode, requires valid session authentication via cookie.
        """
        # Check authentication in production mode
        if is_auth_enabled():
            session_token = websocket.cookies.get("session_token")
            if not session_token or not verify_session(session_token):
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                logger.warning("Network Pulse WebSocket rejected: not authenticated")
                return

        ws_manager = get_ws_manager()
        await ws_manager.connect(websocket)

        try:
            while True:
                # Wait for messages from client (ping/pong)
                data = await websocket.receive_text()
                # Echo back for ping/pong
                if data == '{"type":"ping"}':
                    await websocket.send_text('{"type":"pong"}')
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            ws_manager.disconnect(websocket)

    return app
