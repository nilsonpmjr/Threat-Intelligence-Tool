import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import aiohttp
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from db import db_manager
from config import settings
from logging_config import setup_logging, get_logger
from limiters import limiter
from extensions import get_configured_plugin_roots, load_extensions_registry
from operational_status import set_scheduler_runtime_provider
from threat_ingestion_runtime import start_threat_ingestion_worker
from worker import scan_safe_targets_job, start_watchlist_worker, start_recon_scheduler

from routers import auth, users, analyze, stats, admin, mfa, sessions, api_keys, batch, recon, watchlist, feed, shift_handoff, platform_credentials

# SOC Copilot router is opt-in: it only mounts when the operator has
# provisioned SOCC_INTERNAL_SECRET (i.e. the extension is installed).
# Keeps "socc invisível até instalar" (PRD §Proposed Solution) — the
# backend boots fine without the extension.
try:
    from routers import socc as socc_router  # noqa: F401
except Exception:  # pragma: no cover - import guard only
    socc_router = None

# Generic extensions platform (Fase 4). Always-on; the catalog is
# whatever lives in backend/extensions/ at boot.
from routers import extensions as extensions_router
import credential_manager
from shift_handoff_migration import migrate_shift_handoff_incidents
from scripts.seed_dev_users import seed_dev_users
import app_state
from app_state import check_initialization

try:
    from routers import hunting
except (ModuleNotFoundError, ImportError):
    hunting = None

try:
    from routers import exposure
except (ModuleNotFoundError, ImportError):
    exposure = None

from bson import ObjectId
from fastapi.encoders import ENCODERS_BY_TYPE

ENCODERS_BY_TYPE[ObjectId] = str

logger = get_logger("WebAPI")
setup_logging(level=settings.log_level)

scheduler = AsyncIOScheduler()
set_scheduler_runtime_provider(
    lambda: {
        "running": bool(getattr(scheduler, "running", False)),
        "scheduled_jobs": len(scheduler.get_jobs()) if hasattr(scheduler, "get_jobs") else 0,
    }
)
API_CANONICAL_PREFIX = "/api"
API_LEGACY_PREFIX = "/api/v1"
API_V1_SUNSET = "Wed, 30 Sep 2026 00:00:00 GMT"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db_manager.connect_db()

    # Create MongoDB indexes for query performance
    if db_manager.db is not None:
        db = db_manager.db
        try:
            await db.scans.create_index([("timestamp", -1)])
            await db.scans.create_index([("verdict", 1)])
            await db.scans.create_index([("analyst", 1), ("timestamp", -1)])
            await db.scans.create_index([("target", 1), ("timestamp", -1)])
            await db.analysis_runtime.create_index(
                [("expires_at", 1)],
                expireAfterSeconds=0,
                name="analysis_runtime_ttl",
            )
            await db.users.create_index(
                [("normalized_email", 1)],
                unique=True,
                sparse=True,
                name="users_normalized_email_unique",
            )
            # TTL index to auto-purge expired refresh tokens (7d + 1h grace)
            await db.refresh_tokens.create_index(
                [("expires_at", 1)],
                expireAfterSeconds=3600,
            )
            await db.refresh_tokens.create_index(
                [("token_hash", 1)],
                unique=True,
                sparse=True,
                name="refresh_tokens_token_hash",
            )
            # Audit log indexes for query performance
            await db.audit_log.create_index([("timestamp", -1)])
            await db.audit_log.create_index([("user", 1), ("timestamp", -1)])
            await db.audit_log.create_index([("action", 1)])
            # TTL: auto-delete audit entries older than 90 days
            await db.audit_log.create_index(
                [("timestamp", 1)],
                expireAfterSeconds=90 * 24 * 3600,
                name="audit_log_ttl",
            )
            # TTL: auto-expire password reset tokens (MongoDB removes at expires_at)
            await db.password_reset_tokens.create_index(
                [("expires_at", 1)],
                expireAfterSeconds=0,
                name="reset_tokens_ttl",
            )
            await db.password_reset_tokens.create_index(
                [("username", 1)],
                name="reset_tokens_username",
            )
            # TTL: auto-expire completed batch jobs
            await db.batch_jobs.create_index(
                [("created_at", 1)],
                expireAfterSeconds=settings.batch_job_ttl_hours * 3600,
                name="batch_jobs_ttl",
            )
            await db.batch_jobs.create_index(
                [("analyst", 1), ("created_at", -1)],
                name="batch_jobs_analyst",
            )
            # Recon Engine indexes
            await db.recon_jobs.create_index(
                [("created_at", 1)],
                expireAfterSeconds=24 * 3600,
                name="recon_jobs_ttl",
            )
            await db.recon_jobs.create_index(
                [("analyst", 1), ("created_at", -1)],
                name="recon_jobs_analyst",
            )
            await db.recon_jobs.create_index(
                [("target", 1), ("created_at", -1)],
                name="recon_jobs_target",
            )
            await db.recon_results.create_index(
                [("scanned_at", 1)],
                expireAfterSeconds=settings.recon_cache_ttl_hours * 3600,
                name="recon_results_ttl",
            )
            await db.recon_results.create_index(
                [("cache_key", 1)],
                unique=True,
                name="recon_results_cache_key",
            )
            # Recon scheduled scans indexes
            await db.recon_scheduled.create_index(
                [("run_at", 1)],
                name="recon_scheduled_run_at",
            )
            await db.recon_scheduled.create_index(
                [("analyst", 1), ("status", 1)],
                name="recon_scheduled_analyst_status",
            )
            await db.recon_scheduled.create_index(
                [("created_at", 1)],
                expireAfterSeconds=8 * 24 * 3600,
                name="recon_scheduled_ttl",
            )
            # Watchlist indexes
            await db.watchlist.create_index(
                [("user", 1), ("target", 1)],
                unique=True,
                name="watchlist_user_target",
            )
            await db.watchlist.create_index(
                [("user", 1), ("created_at", -1)],
                name="watchlist_user_created",
            )
            await db.watchlist_history.create_index(
                [("user", 1), ("watchlist_item_id", 1), ("scanned_at", -1)],
                name="watchlist_history_user_item_scanned",
            )
            await db.threat_items.create_index(
                [("source_id", 1), ("external_id", 1)],
                unique=True,
                name="threat_items_source_external_id",
            )
            await db.threat_items.create_index(
                [("published_at", -1)],
                name="threat_items_published_at",
            )
            await db.threat_sync_status.create_index(
                [("source_id", 1)],
                unique=True,
                name="threat_sync_status_source_id",
            )
            await db.threat_sync_history.create_index(
                [("source_id", 1), ("recorded_at", -1)],
                name="threat_sync_history_source_recorded",
            )
            await db.operational_status_history.create_index(
                [("recorded_at", -1)],
                name="operational_status_history_recorded",
            )
            await db.extension_catalog_state.create_index(
                [("key", 1)],
                unique=True,
                name="extension_catalog_state_key",
            )
            await db.exposure_monitored_assets.create_index(
                [("customer_key", 1), ("asset_type", 1), ("value", 1)],
                unique=True,
                name="exposure_monitored_assets_customer_asset",
            )
            await db.exposure_monitored_assets.create_index(
                [("customer_key", 1), ("recurrence.mode", 1), ("is_active", 1)],
                name="exposure_monitored_assets_customer_recurrence",
            )
            await db.exposure_asset_groups.create_index(
                [("customer_key", 1), ("name", 1)],
                name="exposure_asset_groups_customer_name",
            )
            await db.exposure_findings.create_index(
                [("customer_key", 1), ("monitored_asset_id", 1), ("timestamp", -1)],
                name="exposure_findings_customer_asset_timestamp",
            )
            await db.exposure_findings.create_index(
                [("customer_key", 1), ("severity", 1), ("timestamp", -1)],
                name="exposure_findings_customer_severity_timestamp",
            )
            await db.exposure_incidents.create_index(
                [("customer_key", 1), ("status", 1), ("updated_at", -1)],
                name="exposure_incidents_customer_status_updated",
            )
            await db.hunting_results.create_index(
                [("analyst", 1), ("timestamp", -1)],
                name="hunting_results_analyst_timestamp",
            )
            await db.hunting_results.create_index(
                [("search_id", 1)],
                name="hunting_results_search_id",
            )
            await db.hunting_saved_searches.create_index(
                [("analyst", 1), ("created_at", -1)],
                name="hunting_saved_searches_analyst_created",
            )
            await db.hunting_case_notes.create_index(
                [("analyst", 1), ("search_id", 1), ("created_at", -1)],
                name="hunting_case_notes_analyst_search_created",
            )
            # Service quota indexes (daily API call tracking)
            await db.service_quota.create_index(
                [("service", 1), ("date", 1), ("user", 1)],
                unique=True,
                name="service_quota_unique",
            )
            await db.service_quota.create_index(
                [("created_at", 1)],
                expireAfterSeconds=2 * 24 * 3600,
                name="service_quota_ttl",
            )
            # Shift handoff indexes
            await db.shift_handoffs.create_index(
                [("expires_at", 1)],
                expireAfterSeconds=0,
                name="shift_handoffs_ttl",
            )
            await db.shift_handoffs.create_index(
                [("shift_date", -1)],
                name="shift_handoffs_date",
            )
            await db.shift_handoffs.create_index(
                [("created_by", 1), ("shift_date", -1)],
                name="shift_handoffs_author_date",
            )
            await db.shift_handoff_incidents.create_index(
                [("status", 1), ("created_at", -1)],
                name="shift_handoff_incidents_status_created",
            )
            await db.shift_handoff_incidents.create_index(
                [("handoff_id", 1), ("created_at", -1)],
                name="shift_handoff_incidents_handoff_created",
            )
            logger.info("MongoDB indexes created/verified.")

            await check_initialization(db)

            if settings.dev_seed_users and settings.environment == "development":
                if not settings.dev_admin_password:
                    logger.warning("[DEV SEED] DEV_SEED_USERS=true but DEV_ADMIN_PASSWORD is empty — skipping seed.")
                else:
                    await seed_dev_users(db, settings.dev_admin_password, settings.dev_tech_password)
                    await check_initialization(db)  # re-check after seed

            try:
                await credential_manager.seed_builtin_platforms()
                await credential_manager.bootstrap_from_env()
                await credential_manager.hydrate_os_environ()
                logger.info("Platform credentials registry initialized.")
            except Exception as exc:
                logger.warning(f"Platform credentials bootstrap failed: {exc}")

            migration_result = await migrate_shift_handoff_incidents(db)
            if migration_result["created_incidents"] > 0 or migration_result["migrated_handoffs"] > 0:
                logger.info("Shift handoff incident migration executed: %s", migration_result)

            # Clean up legacy refresh_tokens without session_id (created before session tracking)
            result = await db.refresh_tokens.delete_many({"session_id": {"$exists": False}})
            if result.deleted_count:
                logger.info(f"Cleaned up {result.deleted_count} legacy refresh token(s) without session_id.")
        except Exception as e:
            logger.warning(f"Could not create indexes: {e}")

    # Refuse to boot with an unsafe production configuration.
    settings.validate_production()
    app.state.extensions_registry = load_extensions_registry(
        plugin_roots=get_configured_plugin_roots(),
        current_core_version=settings.core_version,
    )
    logger.info("Extensions registry loaded.")

    scheduler.add_job(
        scan_safe_targets_job,
        trigger="interval",
        hours=24,
        id="scan_safe_targets_daily",
        next_run_time=datetime.now(timezone.utc),
    )
    scheduler.start()
    logger.info("Background Worker (APScheduler) started.")

    # Global aiohttp session — shared across all AsyncThreatIntelClient instances
    # to avoid creating a new connection pool per request.
    http_connector = aiohttp.TCPConnector(
        limit=int(os.environ.get("HTTP_CLIENT_MAX_CONNECTIONS", "100")),
        limit_per_host=int(os.environ.get("HTTP_CLIENT_MAX_PER_HOST", "10")),
    )
    app.state.http_session = aiohttp.ClientSession(
        connector=http_connector,
        timeout=aiohttp.ClientTimeout(total=10),
    )

    # Keep long-lived worker tasks visible to readiness checks.
    import asyncio as _aio
    background_tasks = {
        "watchlist_worker": _aio.create_task(start_watchlist_worker()),
        "recon_scheduler": _aio.create_task(start_recon_scheduler()),
        "threat_ingestion_worker": _aio.create_task(start_threat_ingestion_worker()),
    }
    app.state.background_tasks = background_tasks
    logger.info("Watchlist worker task created.")
    logger.info("Recon scheduler task created.")
    logger.info("Threat ingestion worker task created.")

    yield

    # Cancel long-lived tasks before closing shared resources.
    for task in getattr(app.state, "background_tasks", {}).values():
        task.cancel()
    scheduler.shutdown()
    # Close shared aiohttp session
    http_session = getattr(app.state, "http_session", None)
    if http_session and not http_session.closed:
        await http_session.close()
    await db_manager.close_db()


app = FastAPI(
    title=f"{settings.app_name} API",
    description=f"{settings.app_name} — Threat intelligence platform for SOC analysts.",
    version=settings.core_version,
    lifespan=lifespan,
)
app.state.background_tasks = {}


def _task_status(task) -> str:
    if task is None:
        return "missing"
    if task.cancelled():
        return "cancelled"
    if task.done():
        return "error" if task.exception() else "stopped"
    return "ok"


def _health_state() -> dict[str, object]:
    db_connected = db_manager.db is not None
    scheduler_running = bool(getattr(scheduler, "running", False))
    extensions_loaded = bool(
        getattr(app.state, "extensions_registry", None)
    )
    background_tasks = {
        name: _task_status(task)
        for name, task in getattr(app.state, "background_tasks", {}).items()
    }
    background_tasks_ready = bool(background_tasks) and all(
        status == "ok" for status in background_tasks.values()
    )
    ready = (
        db_connected
        and scheduler_running
        and extensions_loaded
        and background_tasks_ready
    )
    return {
        "status": "ok" if ready else "degraded",
        "app": settings.app_name,
        "version": settings.core_version,
        "environment": settings.environment,
        "services": {
            "database": "ok" if db_connected else "disconnected",
            "scheduler": "ok" if scheduler_running else "stopped",
            "extensions_registry": (
                "ok" if extensions_loaded else "not_loaded"
            ),
            "background_tasks": background_tasks,
        },
    }


@app.get("/health/live", include_in_schema=False)
@app.get(
    f"{API_CANONICAL_PREFIX}/health/live",
    include_in_schema=False,
)
async def live_health():
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.core_version,
        "environment": settings.environment,
    }


@app.get("/health/ready", include_in_schema=False)
@app.get(
    f"{API_CANONICAL_PREFIX}/health/ready",
    include_in_schema=False,
)
async def ready_health():
    if not app_state.APP_INITIALIZED:
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_initialized",
                "detail": (
                    "System not initialized. Run: "
                    "docker compose exec backend python bin/console setup:create-admin"
                ),
            },
        )
    payload = _health_state()
    status_code = 200 if payload["status"] == "ok" else 503
    return JSONResponse(status_code=status_code, content=payload)

# Rate limiter state + exception handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# GZip responses ≥ 1 KB
app.add_middleware(GZipMiddleware, minimum_size=1000)


# Security headers (OWASP recommendations)
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Initialization guard — block authenticated endpoints until setup:create-admin runs
_SETUP_EXEMPT_PATHS = {"/health", "/health/live", "/health/ready", "/api/health",
                       "/api/health/live", "/api/health/ready", "/api/auth/login",
                       "/api/v1/auth/login"}


@app.middleware("http")
async def initialization_guard(request: Request, call_next):
    if not app_state.APP_INITIALIZED and request.url.path not in _SETUP_EXEMPT_PATHS:
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "System not initialized. Run: "
                    "docker compose exec backend python bin/console setup:create-admin"
                )
            },
        )
    return await call_next(request)


# Content-size guard: reject bodies > 1 MB before they reach business logic
@app.middleware("http")
async def content_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 1_000_000:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large (max 1MB)"},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length header"},
            )
    return await call_next(request)


@app.middleware("http")
async def api_v1_deprecation_notice(request: Request, call_next):
    response = await call_next(request)

    path = request.url.path
    if path == API_LEGACY_PREFIX or path.startswith(f"{API_LEGACY_PREFIX}/"):
        successor_path = path.removeprefix(API_LEGACY_PREFIX) or ""
        response.headers["Deprecation"] = "true"
        response.headers["Sunset"] = API_V1_SUNSET
        response.headers["Link"] = f'<{API_CANONICAL_PREFIX}{successor_path}>; rel="successor-version"'
        response.headers["Warning"] = '299 - "/api/v1 is deprecated; use /api"'

    return response


# CORS — restrict to known origins; never use "*" in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Register routers ────────────────────────────────────────────────────────
_routers = [
    auth.router, users.router, analyze.router, stats.router,
    admin.router, mfa.router, sessions.router, api_keys.router,
    batch.router, recon.router, watchlist.router, feed.router,
    shift_handoff.router, platform_credentials.router,
    *([hunting.router] if hunting else []),
    *([exposure.router] if exposure else []),
    # SOC Copilot proxy — present only when the extension is installed
    # (env var SOCC_INTERNAL_SECRET non-empty).
    *(
        [socc_router.router]
        if socc_router and settings.socc_internal_secret
        else []
    ),
    # Generic extensions platform (catalog + lifecycle).
    extensions_router.router,
]
for _prefix in ("/api", "/api/v1"):
    for _router in _routers:
        app.include_router(_router, prefix=_prefix)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)  # nosec B104
