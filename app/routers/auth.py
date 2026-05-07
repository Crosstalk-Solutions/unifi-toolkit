"""
Authentication router for UI Toolkit

Handles login/logout and session management for production deployments.
Authentication is only enforced when DEPLOYMENT_TYPE=production.
"""

import os
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional
import bcrypt

from fastapi import APIRouter, Request, Form, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from pathlib import Path

logger = logging.getLogger(__name__)

router = APIRouter()

# Template directory
BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# In-memory session store (simple, works for single-user)
# Sessions are lost on restart, which is acceptable for single-user deployment
_sessions: dict = {}

# Rate limiting for login attempts
_login_attempts: dict = {}  # {ip: [(timestamp, success), ...]}
RATE_LIMIT_WINDOW = 300  # 5 minutes
RATE_LIMIT_MAX_ATTEMPTS = 5


def is_auth_enabled() -> bool:
    """Check if authentication is enabled (production mode)"""
    return os.getenv("DEPLOYMENT_TYPE", "local").lower() == "production"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify password against bcrypt hash"""
    try:
        return bcrypt.checkpw(plain_password.encode(), password_hash.encode())
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def create_session(username: str) -> str:
    """Create a new session token"""
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "username": username,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(days=7)
    }
    logger.info(f"Session created for user: {username}")
    return token


def verify_session(token: str) -> Optional[dict]:
    """Verify session token is valid and not expired"""
    session = _sessions.get(token)
    if not session:
        return None

    if datetime.utcnow() > session["expires_at"]:
        # Session expired, remove it
        del _sessions[token]
        logger.info("Expired session removed")
        return None

    return session


def get_session_from_request(request: Request) -> Optional[dict]:
    """Get session from request cookies"""
    token = request.cookies.get("session_token")
    if not token:
        return None
    return verify_session(token)


def check_rate_limit(ip: str) -> tuple[bool, int]:
    """
    Check if IP is rate limited for login attempts.
    Returns (is_allowed, seconds_remaining)
    """
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW)

    # Clean up old attempts
    if ip in _login_attempts:
        _login_attempts[ip] = [
            (ts, success) for ts, success in _login_attempts[ip]
            if ts > window_start
        ]

    attempts = _login_attempts.get(ip, [])
    failed_attempts = [(ts, success) for ts, success in attempts if not success]

    if len(failed_attempts) >= RATE_LIMIT_MAX_ATTEMPTS:
        # Find oldest attempt in window to calculate remaining time
        oldest = min(ts for ts, _ in failed_attempts)
        seconds_remaining = int((oldest + timedelta(seconds=RATE_LIMIT_WINDOW) - now).total_seconds())
        return False, max(0, seconds_remaining)

    return True, 0


def record_login_attempt(ip: str, success: bool):
    """Record a login attempt for rate limiting"""
    now = datetime.utcnow()
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    _login_attempts[ip].append((now, success))

    # Keep only recent attempts
    window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW)
    _login_attempts[ip] = [
        (ts, s) for ts, s in _login_attempts[ip]
        if ts > window_start
    ]


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Show login page"""
    # If not in production mode, redirect to dashboard
    if not is_auth_enabled():
        return RedirectResponse(url="/", status_code=303)

    # If already logged in, redirect to dashboard
    session = get_session_from_request(request)
    if session:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": None,
            "rate_limited": False,
            "wait_seconds": 0
        }
    )


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """Process login form"""
    # If not in production mode, redirect to dashboard
    if not is_auth_enabled():
        return RedirectResponse(url="/", status_code=303)

    # Get client IP for rate limiting
    client_ip = request.client.host if request.client else "unknown"

    # Check rate limit
    is_allowed, wait_seconds = check_rate_limit(client_ip)
    if not is_allowed:
        logger.warning(f"Rate limited login attempt from {client_ip}")
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": None,
                "rate_limited": True,
                "wait_seconds": wait_seconds
            },
            status_code=429
        )

    # Get expected credentials from environment
    expected_username = os.getenv("AUTH_USERNAME", "admin")
    expected_password_hash = os.getenv("AUTH_PASSWORD_HASH", "")

    # Verify credentials
    if username != expected_username or not verify_password(password, expected_password_hash):
        record_login_attempt(client_ip, success=False)
        logger.warning(f"Failed login attempt for user '{username}' from {client_ip}")

        # Check if now rate limited
        is_allowed, wait_seconds = check_rate_limit(client_ip)

        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": "Invalid username or password",
                "rate_limited": not is_allowed,
                "wait_seconds": wait_seconds
            },
            status_code=401
        )

    # Successful login
    record_login_attempt(client_ip, success=True)
    logger.info(f"Successful login for user '{username}' from {client_ip}")

    # Create session
    token = create_session(username)

    # Redirect to dashboard with session cookie
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=True,  # HTTPS only in production
        samesite="lax",
        max_age=7 * 24 * 60 * 60  # 7 days
    )

    return response


@router.get("/logout")
async def logout(request: Request):
    """Logout and clear session"""
    token = request.cookies.get("session_token")

    if token and token in _sessions:
        username = _sessions[token].get("username", "unknown")
        del _sessions[token]
        logger.info(f"User '{username}' logged out")

    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session_token")

    return response


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce authentication and CSRF protection when in production mode.

    Authentication:
    - Allows unauthenticated access to /login, /static, and /health endpoints.

    CSRF Protection:
    - Requires 'X-Requested-With' header for state-changing API requests (POST, PUT, DELETE, PATCH)
    - This prevents cross-site request forgery since browsers don't send custom headers
      in simple cross-origin requests without CORS preflight
    """

    # Methods that require CSRF protection
    CSRF_PROTECTED_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    # API paths that need CSRF protection (when using protected methods)
    API_PREFIXES = ["/api/", "/stalker/api/", "/threats/api/", "/pulse/api/"]

    # Paths exempt from CSRF (login form uses traditional form submission)
    CSRF_EXEMPT_PATHS = ["/login"]

    async def dispatch(self, request: Request, call_next):
        # Skip all checks if not in production mode
        if not is_auth_enabled():
            return await call_next(request)

        # Allow these paths without authentication
        public_paths = [
            "/login",
            "/static",
            "/health",
            "/favicon.ico"
        ]

        path = request.url.path
        method = request.method

        # Check if path is public
        is_public = any(
            path == p or path.startswith(f"{p}/") or path.startswith(f"{p}?")
            for p in public_paths
        )

        if is_public:
            return await call_next(request)

        # Check for valid session
        session = get_session_from_request(request)

        if not session:
            # Not authenticated, redirect to login
            # For API requests, return 401 instead of redirect
            if any(path.startswith(prefix) for prefix in self.API_PREFIXES):
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Not authenticated"}
                )

            return RedirectResponse(url="/login", status_code=303)

        # CSRF Protection for state-changing requests
        if method in self.CSRF_PROTECTED_METHODS:
            is_api_request = any(path.startswith(prefix) for prefix in self.API_PREFIXES)
            is_csrf_exempt = any(path.startswith(exempt) for exempt in self.CSRF_EXEMPT_PATHS)

            if is_api_request and not is_csrf_exempt:
                # Require X-Requested-With header for API state-changing requests
                requested_with = request.headers.get("X-Requested-With")
                if requested_with != "XMLHttpRequest":
                    from fastapi.responses import JSONResponse
                    logger.warning(f"CSRF check failed for {method} {path} - missing X-Requested-With header")
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "CSRF validation failed. Include 'X-Requested-With: XMLHttpRequest' header."}
                    )

        # Authenticated and CSRF valid, continue
        return await call_next(request)


def get_current_user(request: Request) -> dict:
    """
    Dependency to get current user.
    Returns user info for authenticated requests, or mock user for local mode.
    """
    if not is_auth_enabled():
        return {"username": "local", "local_mode": True}

    session = get_session_from_request(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return {
        "username": session["username"],
        "local_mode": False
    }
