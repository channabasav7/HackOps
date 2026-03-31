"""
Project Sentinel — Auth: UUID + password login against pre-existing operators.
No signup; accounts are provisioned (military-grade channel).
"""

from __future__ import annotations

import asyncio
import math
import time
from datetime import datetime, timezone, timedelta
from typing import Annotated

import jwt
import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import OperationalError as SQLAlchemyOperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import get_settings
from models.database import get_db
from models.local_store import DEMO_OPERATORS

router = APIRouter(prefix="/api/auth", tags=["auth"])


class AuthRateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    def _prune_locked(self, key: str, now: float) -> list[float]:
        recent = [ts for ts in self._attempts.get(key, []) if now - ts < self.window_seconds]
        if recent:
            self._attempts[key] = recent
        else:
            self._attempts.pop(key, None)
        return recent

    async def is_limited(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        async with self._lock:
            attempts = self._prune_locked(key, now)
            if len(attempts) < self.max_attempts:
                return False, 0
            retry_after = max(1, math.ceil(self.window_seconds - (now - attempts[0])))
            return True, retry_after

    async def register_failure(self, key: str) -> None:
        now = time.monotonic()
        async with self._lock:
            attempts = self._prune_locked(key, now)
            attempts.append(now)
            self._attempts[key] = attempts

    async def clear(self, key: str) -> None:
        async with self._lock:
            self._attempts.pop(key, None)


_auth_rate_limiter: AuthRateLimiter | None = None


def get_auth_rate_limiter() -> AuthRateLimiter:
    global _auth_rate_limiter
    if _auth_rate_limiter is None:
        settings = get_settings()
        _auth_rate_limiter = AuthRateLimiter(
            max_attempts=settings.auth_rate_limit_max_attempts,
            window_seconds=settings.auth_rate_limit_window_seconds,
        )
    return _auth_rate_limiter


def reset_auth_rate_limiter_for_tests() -> None:
    global _auth_rate_limiter
    _auth_rate_limiter = None


def _build_rate_limit_key(request: Request, operator_uuid: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{operator_uuid.lower()}"


async def _raise_invalid_credentials(rate_limiter: AuthRateLimiter, key: str) -> None:
    await rate_limiter.register_failure(key)
    raise HTTPException(status_code=401, detail="Invalid operator UUID or password")


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response
# ─────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    uuid: str = Field(..., description="Operator UUID (pre-provisioned identifier)")
    password: str = Field(..., min_length=1, description="Operator password")


class LoginResponse(BaseModel):
    access_token: str
    role: str  # "sender" | "receiver"
    expires_in: int  # seconds


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    body: LoginRequest,
    db: Annotated[AsyncSession | None, Depends(get_db)],
) -> LoginResponse:
    """Authenticate with pre-existing operator UUID and password. No signup."""
    raw_uuid = body.uuid.strip()
    if not raw_uuid:
        raise HTTPException(status_code=400, detail="UUID is required")

    rate_limiter = get_auth_rate_limiter()
    rate_key = _build_rate_limit_key(request, raw_uuid)
    blocked, retry_after_seconds = await rate_limiter.is_limited(rate_key)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(retry_after_seconds)},
        )

    # Offline/demo fallback (no DB) so the app can run without Supabase.
    if db is None:
        op = DEMO_OPERATORS.get(raw_uuid)
        if not op or body.password != op["password"]:
            await _raise_invalid_credentials(rate_limiter, rate_key)
        role = op["role"]
    else:
        try:
            result = await db.execute(
                text(
                    "SELECT operator_uuid, password_hash, role FROM public.operators WHERE operator_uuid = :uuid"
                ),
                {"uuid": raw_uuid},
            )
            row = next(result.mappings(), None)
            if not row:
                await _raise_invalid_credentials(rate_limiter, rate_key)

            stored_hash = row["password_hash"]
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode("utf-8")
            if not bcrypt.checkpw(body.password.encode("utf-8"), stored_hash):
                await _raise_invalid_credentials(rate_limiter, rate_key)

            role = str(row["role"])
            if role not in ("sender", "receiver"):
                raise HTTPException(status_code=500, detail="Invalid role in database")
        except SQLAlchemyOperationalError:
            op = DEMO_OPERATORS.get(raw_uuid)
            if not op or body.password != op["password"]:
                await _raise_invalid_credentials(rate_limiter, rate_key)
            role = op["role"]

    await rate_limiter.clear(rate_key)

    settings = get_settings()
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": raw_uuid,
        "role": role,
        "exp": expires,
        "iat": datetime.now(timezone.utc),
    }
    token = jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return LoginResponse(
        access_token=token,
        role=role,
        expires_in=settings.jwt_expire_minutes * 60,
    )
