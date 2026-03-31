"""
Project Sentinel — FastAPI Application Entry Point
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator, Callable
from uuid import uuid4

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from api.routes.auth import router as auth_router
from api.routes.monitor import router as monitor_router
from config.settings import get_settings
from models.database import get_engine

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

request_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        return True


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }

        for key in ("method", "path", "status_code", "duration_ms", "client_ip"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=True)


handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonLogFormatter())
handler.addFilter(RequestIdFilter())

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.handlers = [handler]

logger = logging.getLogger("sentinel")


# ──────────────────────────────────────────────────────────────────────────────
# Lifespan
# ──────────────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logger.info("Project Sentinel initialising — Bloom size=%d, k=%d",
                settings.bloom_filter_size, settings.bloom_hash_count)
    yield
    logger.info("Project Sentinel shutting down")


# ──────────────────────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────────────────────

# Allowed origins for CORS (browser requests from frontend)
DEV_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    # LAN — Machine A (this machine — backend + frontend)
    "http://10.53.222.69:3000",
    "http://10.53.222.69:3001",
    # LAN — Machine B (receiver laptop)
    "http://10.53.222.108:3000",
    "http://10.53.222.108:3001",
]

settings = get_settings()
CORS_ORIGINS = settings.get_cors_origins(default=DEV_CORS_ORIGINS)
ALLOW_ORIGIN_REGEX = settings.cors_allow_origin_regex if settings.sentinel_env != "production" else None

app = FastAPI(
    title="Project Sentinel",
    description=(
        "Zero-Exposure Threat Detection System for military communications. "
        "Detects classified keyword leaks via SSE and Bloom Filters without "
        "ever decrypting message content."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


class EnsureCORSHeadersMiddleware(BaseHTTPMiddleware):
    """Add CORS headers to every response so errors (e.g. 500) still allow browser to read them."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        origin = request.headers.get("origin")
        if origin and origin in CORS_ORIGINS:
            response.headers.setdefault("Access-Control-Allow-Origin", origin)
        response.headers.setdefault("Access-Control-Allow-Credentials", "true")
        response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE")
        response.headers.setdefault("Access-Control-Allow-Headers", "*")
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request ID and emit structured request logs."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid4().hex
        token = request_id_ctx.set(request_id)
        started = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            logger.exception(
                "request_failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                    "client_ip": request.client.host if request.client else "unknown",
                },
            )
            request_id_ctx.reset(token)
            raise

        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request_completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "client_ip": request.client.host if request.client else "unknown",
            },
        )
        request_id_ctx.reset(token)
        return response


app.add_middleware(RequestContextMiddleware)
app.add_middleware(EnsureCORSHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=ALLOW_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(auth_router)
app.include_router(monitor_router)


# ──────────────────────────────────────────────────────────────────────────────
# Exception handler so 500s still return CORS headers
# ──────────────────────────────────────────────────────────────────────────────

from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail} if isinstance(exc.detail, str) else {"detail": exc.detail},
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ──────────────────────────────────────────────────────────────────────────────
# Health check
# ──────────────────────────────────────────────────────────────────────────────


async def _database_health() -> dict[str, object]:
    settings = get_settings()
    if settings.sentinel_offline_mode or not settings.supabase_db_url:
        return {"configured": False, "reachable": None}

    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"configured": True, "reachable": True}
    except Exception as exc:
        message = str(exc).split("\n")[0]
        logger.warning("Database health check failed: %s", message)
        return {"configured": True, "reachable": False, "error": message}


@app.get("/health", tags=["ops"])
async def health() -> JSONResponse:
    current_settings = get_settings()
    db_health = await _database_health()
    status = "OPERATIONAL"
    if db_health.get("configured") and db_health.get("reachable") is False:
        status = "DEGRADED"

    return JSONResponse(
        {
            "status": status,
            "system": "Project Sentinel",
            "environment": current_settings.sentinel_env,
            "offline_mode": current_settings.sentinel_offline_mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {"database": db_health},
        }
    )


# ──────────────────────────────────────────────────────────────────────────────
# Dev entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
