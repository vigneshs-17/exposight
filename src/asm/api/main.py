"""Main FastAPI application entrypoint for Exposight."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from asm.api.deps import get_current_auth_settings
from asm.api.routes import public_router, router
from asm.api.routes_orgs import router as orgs_router
from asm.api.routes_ui import build_csp_header, ui_router
from asm.config import enforce_production_config, is_production

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: validate auth configuration at startup."""
    enforce_production_config(check_auth=True)
    settings = get_current_auth_settings()
    if settings.supabase_publishable_key.startswith("sb_secret_"):
        raise RuntimeError(
            "CRITICAL SECURITY MISCONFIGURATION: SUPABASE_PUBLISHABLE_KEY "
            "contains a secret service key ('sb_secret_...'). "
            "Only the public publishable/anon key may be configured."
        )
    if not settings.is_configured:
        logger.warning(
            "SUPABASE_URL is not set! Authentication is not configured. "
            "All protected endpoints will return 503 'authentication not configured'."
        )
    yield


def docs_urls(production: bool) -> dict[str, str | None]:
    """Return FastAPI docs settings; production hides /docs, /redoc and /openapi.json."""
    if production:
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}


app = FastAPI(
    title="Exposight API",
    description="Attack Surface Management REST API - Reconnaissance & Surface Monitoring",
    version="0.2.0",
    lifespan=lifespan,
    **docs_urls(is_production()),
)


@app.middleware("http")
async def add_security_headers_middleware(request: Request, call_next):
    """Enforce strict CSP on HTML pages and nosniff/no-store on every other response."""
    response = await call_next(request)
    path = request.url.path
    if (
        path == "/"
        or path.startswith("/app")
        or path.startswith("/ui")
        or path.startswith("/static")
    ):
        settings = get_current_auth_settings()
        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = build_csp_header(settings.supabase_url)
        if "X-Content-Type-Options" not in response.headers:
            response.headers["X-Content-Type-Options"] = "nosniff"
        if "Referrer-Policy" not in response.headers:
            response.headers["Referrer-Policy"] = "no-referrer"
        if path.startswith("/ui"):
            response.headers["Cache-Control"] = "no-store"
    else:
        # JSON API, /health and docs: never MIME-sniffed, never cached (tenant data).
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Cache-Control", "no-store")
    return response


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.include_router(ui_router)
app.include_router(public_router)
app.include_router(router)
app.include_router(orgs_router)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Ensure unhandled internal server errors never leak stack traces to clients."""
    logger.exception("Unhandled server exception processing request: %s", request.url)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error. Please consult system logs."},
    )
