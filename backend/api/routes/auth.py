"""
Project Sentinel — Auth: UUID + password login against pre-existing operators.
No signup; accounts are provisioned (military-grade channel).
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Annotated

import jwt
import bcrypt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import OperationalError as SQLAlchemyOperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import get_settings
from models.database import get_db
from models.local_store import DEMO_OPERATORS

router = APIRouter(prefix="/api/auth", tags=["auth"])


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
    body: LoginRequest,
    db: Annotated[AsyncSession | None, Depends(get_db)],
) -> LoginResponse:
    """Authenticate with pre-existing operator UUID and password. No signup."""
    raw_uuid = body.uuid.strip()
    if not raw_uuid:
        raise HTTPException(status_code=400, detail="UUID is required")

    # Offline/demo fallback (no DB) so the app can run without Supabase.
    if db is None:
        op = DEMO_OPERATORS.get(raw_uuid)
        if not op or body.password != op["password"]:
            raise HTTPException(status_code=401, detail="Invalid operator UUID or password")
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
                raise HTTPException(status_code=401, detail="Invalid operator UUID or password")

            stored_hash = row["password_hash"]
            if isinstance(stored_hash, str):
                stored_hash = stored_hash.encode("utf-8")
            if not bcrypt.checkpw(body.password.encode("utf-8"), stored_hash):
                raise HTTPException(status_code=401, detail="Invalid operator UUID or password")

            role = str(row["role"])
            if role not in ("sender", "receiver"):
                raise HTTPException(status_code=500, detail="Invalid role in database")
        except SQLAlchemyOperationalError:
            op = DEMO_OPERATORS.get(raw_uuid)
            if not op or body.password != op["password"]:
                raise HTTPException(status_code=401, detail="Invalid operator UUID or password")
            role = op["role"]

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
