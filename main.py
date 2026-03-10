"""FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from api import router
from auth import auth_router, init_db, get_current_user


logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


# ── Auth middleware ──────────────────────────────────────────────────

# Paths that don't require authentication
AUTH_EXEMPT = {
    "/login",
    "/auth/login",
    "/auth/register",
    "/auth/providers",
    "/auth/github",
    "/auth/github/callback",
    "/auth/google",
    "/auth/google/callback",
    "/api/v1/health",
    "/docs",
    "/openapi.json",
}

AUTH_EXEMPT_PREFIXES = (
    "/static/",
)


class AuthMiddleware(BaseHTTPMiddleware):
    """Redirect unauthenticated users to /login for all protected routes."""

    async def dispatch(self, request: Request, call_next):
        if not settings.auth_enabled:
            return await call_next(request)

        path = request.url.path

        # Allow exempt paths
        if path in AUTH_EXEMPT or path.startswith(AUTH_EXEMPT_PREFIXES):
            return await call_next(request)

        # Check JWT cookie
        user = get_current_user(request)
        if not user:
            # API requests get 401, browser requests get redirected
            if path.startswith("/api/"):
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Not authenticated"},
                )
            return RedirectResponse("/login")

        # Attach user to request state for downstream use
        request.state.user = user
        return await call_next(request)


# ── Lifespan ─────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize auth database
    if settings.auth_enabled:
        init_db(settings.auth_db_path)
        logging.getLogger(__name__).info("Authentication enabled")
    else:
        logging.getLogger(__name__).info("Authentication DISABLED")

    logging.getLogger(__name__).info(
        f"AASA v{settings.app_version} starting on {settings.host}:{settings.port}"
    )
    yield


# ── App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Scan websites for AI agent attack surface vulnerabilities including "
        "indirect prompt injection, hidden instructions, tool-call injection, "
        "data exfiltration patterns, and agentic signal files. "
        "Uses both static rule-based analysis and LLM-as-judge deep inspection."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
)

# Auth middleware must come before CORS
app.add_middleware(AuthMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth routes (no /api/v1 prefix — top-level /auth/*)
app.include_router(auth_router)

# API routes
app.include_router(router, prefix="/api/v1")

# Serve static files (web UI)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/login", include_in_schema=False)
async def login_page(request: Request):
    """Serve the login page. If already authenticated, redirect to /."""
    if settings.auth_enabled:
        user = get_current_user(request)
        if user:
            return RedirectResponse("/")
    return FileResponse("static/login.html")


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse("static/index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
