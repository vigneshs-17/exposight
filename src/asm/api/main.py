"""Main FastAPI application entrypoint for Exposight."""

import logging
import math
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from asm.api.deps import get_current_auth_settings
from asm.api.routes import public_router, router
from asm.api.routes_orgs import invites_router, me_router
from asm.api.routes_orgs import router as orgs_router
from asm.api.routes_ui import build_csp_header, templates_env, ui_router
from asm.config import enforce_production_config, is_production
from asm.logredact import install_log_redaction
from asm.ratelimit import UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP, limiter

# Mask emails and secrets in every log line, uvicorn's access log included.
install_log_redaction()

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


# Paths never rate limited: static assets (many per page) and the container healthcheck.
RATE_LIMIT_EXEMPT_PREFIXES = ("/static/", "/health")


def _too_many_requests(retry_after: float) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Too many requests"},
        headers={"Retry-After": str(max(1, math.ceil(retry_after)))},
    )


@app.middleware("http")
async def unauthenticated_rate_limit_middleware(request: Request, call_next):
    """Limit every request without a verified identity per client IP (IC-1, D-IC2).

    No Authorization header: charged before the handler runs. With a header, the
    handler runs first: get_active_user marks a verified identity (limited per user
    instead) and get_current_user marks a rejected token it already charged. A request
    that is neither (a public route given any header) is charged afterwards and its
    response replaced with 429 when the limit is used up; only side-effect-free public
    routes can reach that point.
    """
    path = request.url.path
    if path.startswith(RATE_LIMIT_EXEMPT_PREFIXES):
        return await call_next(request)
    ip_key = f"ip:{request.client.host if request.client else 'unknown'}"
    if "authorization" not in request.headers:
        retry_after = limiter.hit(ip_key, UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP)
        if retry_after is not None:
            return _too_many_requests(retry_after)
        return await call_next(request)

    response = await call_next(request)
    if getattr(request.state, "identity_verified", False) or getattr(
        request.state, "ip_rate_charged", False
    ):
        return response
    retry_after = limiter.hit(ip_key, UNAUTHENTICATED_REQUESTS_PER_MINUTE_PER_IP)
    if retry_after is not None:
        return _too_many_requests(retry_after)
    return response


PAGE_PATH_PREFIXES = ("/app", "/ui", "/static")
# No page uses these browser features; deny them to the page and any frame (IC-1, F5).
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=()"

# First path segment of every JSON API, HTMX partial, static or docs route. Requests under
# these never get an HTML error page, whatever their Accept header says (C-UI-4).
NON_PAGE_SEGMENTS = frozenset(
    {"orgs", "invites", "me", "health", "ui", "static", "docs", "redoc", "openapi.json"}
)

ERROR_PAGES = {
    403: ("Access denied", "You do not have access to this page."),
    404: ("Page not found", "This page does not exist."),
    500: ("Something went wrong", "The server could not complete this request. Try again later."),
}


def apply_response_security_headers(path: str, response: Response) -> None:
    """Set the security headers for a response to `path`. The one place they are defined:
    used by the middleware and by the 500 handler, which runs outside every middleware."""
    headers = response.headers
    if path == "/" or path.startswith(PAGE_PATH_PREFIXES):
        if "Content-Security-Policy" not in headers:
            headers["Content-Security-Policy"] = build_csp_header(
                get_current_auth_settings().supabase_url
            )
        if path.startswith("/ui"):
            headers["Cache-Control"] = "no-store"
    else:
        # JSON API, /health, docs and 404s: never cached (tenant data), never framed.
        # Framing-only CSP so the dev Swagger UI still loads its assets.
        headers.setdefault("Cache-Control", "no-store")
        headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
    if response.status_code >= 400:
        headers.setdefault("Cache-Control", "no-store")  # error responses are never cached
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
    # Clickjacking: legacy header for browsers without CSP frame-ancestors (H-Hdr-1).
    headers["X-Frame-Options"] = "DENY"


@app.middleware("http")
async def add_security_headers_middleware(request: Request, call_next):
    """Enforce strict CSP on HTML pages and nosniff/no-store on every other response."""
    response = await call_next(request)
    apply_response_security_headers(request.url.path, response)
    return response


def is_page_request(request: Request) -> bool:
    """A browser navigation to a page: asks for HTML and is not an API/partial/asset path."""
    segment = request.url.path.split("/")[1]
    return "text/html" in request.headers.get("accept", "") and segment not in NON_PAGE_SEGMENTS


def render_error_page(request: Request, status_code: int) -> HTMLResponse:
    """Themed error page. Never echoes the path, the exception or other request data."""
    title, message = ERROR_PAGES[status_code]
    html = templates_env.get_template("error.html").render(
        status_code=status_code, title=title, message=message
    )
    response = HTMLResponse(html, status_code=status_code)
    try:
        supabase_url = get_current_auth_settings().supabase_url
    except Exception:  # an error page must render even when settings are the problem
        supabase_url = ""
    response.headers["Content-Security-Policy"] = build_csp_header(supabase_url)
    response.headers["Cache-Control"] = "no-store"
    apply_response_security_headers(request.url.path, response)
    return response


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.include_router(ui_router)
app.include_router(public_router)
app.include_router(router)
app.include_router(orgs_router)
app.include_router(invites_router)
app.include_router(me_router)


@app.exception_handler(StarletteHTTPException)
async def page_aware_http_exception_handler(request: Request, exc: StarletteHTTPException):
    """HTML error page for browser page requests (403/404); FastAPI's JSON otherwise."""
    if exc.status_code in ERROR_PAGES and is_page_request(request):
        return render_error_page(request, exc.status_code)
    return await http_exception_handler(request, exc)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> Response:
    """Ensure unhandled internal server errors never leak stack traces to clients.

    Runs in Starlette's outermost ServerErrorMiddleware, outside add_security_headers_middleware,
    so it sets the security headers itself (before C-UI-4 a 500 carried none)."""
    logger.exception("Unhandled server exception processing request: %s", request.url)
    if is_page_request(request):
        return render_error_page(request, status.HTTP_500_INTERNAL_SERVER_ERROR)
    response = JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error. Please consult system logs."},
    )
    apply_response_security_headers(request.url.path, response)
    return response
