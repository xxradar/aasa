"""Auth routes: login, register, OAuth, logout."""

from __future__ import annotations
import logging
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse, JSONResponse

from config import settings
from .database import get_db
from .models import UserLogin, UserCreate, TokenResponse
from .jwt import create_access_token

logger = logging.getLogger(__name__)
auth_log = logging.getLogger("auth.events")
auth_router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    """Get client IP, respecting X-Forwarded-For behind a proxy."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _set_token_cookie(response: Response, token: str):
    """Set the JWT as an HttpOnly cookie."""
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.jwt_expire_minutes * 60,
        secure=False,  # Set True in production with HTTPS
    )


# ── Email / Password ────────────────────────────────────────────────

@auth_router.post("/register")
async def register(data: UserCreate, request: Request):
    """Register a new local account."""
    db = get_db()
    if db.get_by_email(data.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user = db.create_local(data.email, data.password, data.name)
    token = create_access_token(user.id, user.email)

    auth_log.info("REGISTER provider=local email=%s ip=%s", user.email, _client_ip(request))

    response = JSONResponse(content={
        "access_token": token,
        "token_type": "bearer",
        "user": user.model_dump(),
    })
    _set_token_cookie(response, token)
    return response


@auth_router.post("/login")
async def login(data: UserLogin, request: Request):
    """Login with email and password."""
    db = get_db()
    user = db.verify_password(data.email, data.password)
    if not user:
        auth_log.warning("LOGIN_FAILED provider=local email=%s ip=%s", data.email, _client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(user.id, user.email)

    auth_log.info("LOGIN provider=local email=%s ip=%s", user.email, _client_ip(request))

    response = JSONResponse(content={
        "access_token": token,
        "token_type": "bearer",
        "user": user.model_dump(),
    })
    _set_token_cookie(response, token)
    return response


@auth_router.post("/logout")
async def logout(request: Request):
    """Clear the auth cookie."""
    from .dependencies import get_current_user
    user = get_current_user(request)
    if user:
        auth_log.info("LOGOUT email=%s ip=%s", user.email, _client_ip(request))
    response = JSONResponse(content={"status": "logged_out"})
    response.delete_cookie("access_token")
    return response


@auth_router.get("/me")
async def me(request: Request):
    """Get the current authenticated user."""
    from .dependencies import get_current_user
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user.model_dump()


# ── GitHub OAuth ────────────────────────────────────────────────────

@auth_router.get("/github")
async def github_login(request: Request):
    """Redirect to GitHub OAuth."""
    if not settings.github_client_id:
        raise HTTPException(status_code=501, detail="GitHub OAuth not configured")

    # Build callback URL from the request
    base = str(request.base_url).rstrip("/")
    callback = f"{base}/auth/github/callback"

    params = urlencode({
        "client_id": settings.github_client_id,
        "redirect_uri": callback,
        "scope": "user:email",
    })
    return RedirectResponse(f"https://github.com/login/oauth/authorize?{params}")


@auth_router.get("/github/callback")
async def github_callback(request: Request, code: str = None, error: str = None):
    """Handle GitHub OAuth callback."""
    if error or not code:
        return RedirectResponse("/login?error=github_denied")

    base = str(request.base_url).rstrip("/")
    callback = f"{base}/auth/github/callback"

    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": callback,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            return RedirectResponse("/login?error=github_token_failed")

        # Get user info
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        gh_user = user_resp.json()

        # Get primary email if not public
        email = gh_user.get("email")
        if not email:
            emails_resp = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            for e in emails_resp.json():
                if e.get("primary"):
                    email = e["email"]
                    break

    if not email:
        return RedirectResponse("/login?error=github_no_email")

    db = get_db()
    user = db.create_or_update_oauth(
        provider="github",
        provider_id=str(gh_user["id"]),
        email=email,
        name=gh_user.get("name") or gh_user.get("login"),
        avatar_url=gh_user.get("avatar_url"),
    )

    auth_log.info("LOGIN provider=github email=%s ip=%s", email, _client_ip(request))

    jwt_token = create_access_token(user.id, user.email)
    response = RedirectResponse("/")
    _set_token_cookie(response, jwt_token)
    return response


# ── Google OAuth ────────────────────────────────────────────────────

@auth_router.get("/google")
async def google_login(request: Request):
    """Redirect to Google OAuth."""
    if not settings.google_client_id:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")

    base = str(request.base_url).rstrip("/")
    callback = f"{base}/auth/google/callback"

    params = urlencode({
        "client_id": settings.google_client_id,
        "redirect_uri": callback,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
    })
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@auth_router.get("/google/callback")
async def google_callback(request: Request, code: str = None, error: str = None):
    """Handle Google OAuth callback."""
    if error or not code:
        return RedirectResponse("/login?error=google_denied")

    base = str(request.base_url).rstrip("/")
    callback = f"{base}/auth/google/callback"

    async with httpx.AsyncClient() as client:
        # Exchange code for tokens
        token_resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "code": code,
                "redirect_uri": callback,
                "grant_type": "authorization_code",
            },
        )
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            return RedirectResponse("/login?error=google_token_failed")

        # Get user info
        user_resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        g_user = user_resp.json()

    email = g_user.get("email")
    if not email:
        return RedirectResponse("/login?error=google_no_email")

    db = get_db()
    user = db.create_or_update_oauth(
        provider="google",
        provider_id=str(g_user["id"]),
        email=email,
        name=g_user.get("name"),
        avatar_url=g_user.get("picture"),
    )

    auth_log.info("LOGIN provider=google email=%s ip=%s", email, _client_ip(request))

    jwt_token = create_access_token(user.id, user.email)
    response = RedirectResponse("/")
    _set_token_cookie(response, jwt_token)
    return response


# ── Provider availability ───────────────────────────────────────────

@auth_router.get("/providers")
async def list_providers():
    """List which auth providers are configured."""
    return {
        "local": True,
        "github": bool(settings.github_client_id and settings.github_client_secret),
        "google": bool(settings.google_client_id and settings.google_client_secret),
    }
