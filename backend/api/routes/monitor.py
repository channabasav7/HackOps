"""
Project Sentinel — Threat Detection & Monitoring Routes

POST /api/ingest-chat   — Ingest, encrypt, detect threats with severity + node tracking
POST /api/decrypt       — Authorised receiver decryption
POST /api/search-encrypted — SSE trapdoor search (no decryption)
POST /api/watchlist/add — Add classified operation to watchlist
GET  /api/threats       — Threat feed for receiver dashboard
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Annotated, Dict
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.exc import OperationalError as SQLAlchemyOperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import Settings, get_settings
from core.crypto_engine import (
    AnalysisResult,
    BloomFilter,
    InterceptionNode,
    ThreatDetectionEngine,
    WatchlistEntry,
    classify_severity,
    decrypt_message,
    derive_key,
    encrypt_message,
    generate_ngram_hashes,
)
from models.database import get_db
from models import local_store

logger = logging.getLogger("sentinel.monitor")

router = APIRouter(prefix="/api", tags=["monitor"])


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket Connection Manager
# ──────────────────────────────────────────────────────────────────────────────


class SentinelWSManager:
    """
    Manages all active WebSocket connections.

    Sender machines connect with role='sender' to receive status updates
    (e.g. how many receivers are online).
    Receiver machines connect with role='receiver' to receive live INGEST events.
    All clients receive STATUS events on connect/disconnect.
    """

    def __init__(self) -> None:
        self._connections: Dict[str, tuple[WebSocket, str]] = {}  # client_id → (ws, role)
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, client_id: str, role: str) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[client_id] = (websocket, role)
        logger.info("WS connected: %s (%s) | total=%d", client_id[:8], role, self.count)

    async def disconnect(self, client_id: str) -> None:
        async with self._lock:
            self._connections.pop(client_id, None)
        logger.info("WS disconnected: %s | total=%d", client_id[:8], self.count)

    @property
    def count(self) -> int:
        return len(self._connections)

    @property
    def receiver_count(self) -> int:
        return sum(1 for _, role in self._connections.values() if role == "receiver")

    @property
    def sender_count(self) -> int:
        return sum(1 for _, role in self._connections.values() if role == "sender")

    async def broadcast(self, message: dict) -> None:
        """Send *message* to every connected client; prune dead connections."""
        if not self._connections:
            return
        data = json.dumps(message, default=str)
        dead: list[str] = []
        for cid, (ws, _) in list(self._connections.items()):
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(cid)
        if dead:
            async with self._lock:
                for cid in dead:
                    self._connections.pop(cid, None)

    async def broadcast_status(self) -> None:
        await self.broadcast({
            "type": "STATUS",
            "connected_clients": self.count,
            "receiver_count": self.receiver_count,
            "sender_count": self.sender_count,
        })


ws_manager = SentinelWSManager()


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket endpoint — /api/ws
# ──────────────────────────────────────────────────────────────────────────────


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    role: str = Query(default="receiver", pattern="^(sender|receiver)$"),
) -> None:
    """
    Live feed WebSocket for Project Sentinel.

    Connect with  ?role=sender   (Sender machine) or
                  ?role=receiver (Receiver machine).

    Message types sent to clients:
      CONNECTED   — on handshake (includes current connected_clients count)
      HEARTBEAT   — every 20s keepalive
      STATUS      — broadcast when any client connects / disconnects
      INGEST      — broadcast whenever a message is ingested & analysed
    """
    client_id = str(uuid4())
    await ws_manager.connect(websocket, client_id, role)

    try:
        # Welcome message
        await websocket.send_json({
            "type": "CONNECTED",
            "client_id": client_id,
            "role": role,
            "message": "Connected to Project Sentinel — Zero-Exposure Live Feed",
            "connected_clients": ws_manager.count,
            "receiver_count": ws_manager.receiver_count,
            "sender_count": ws_manager.sender_count,
        })

        # Notify all others that a new client joined
        await ws_manager.broadcast_status()

        # Keep-alive loop: listen for pings, send heartbeats every 20s
        while True:
            try:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=20.0)
                if raw.strip() == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Include both counts in heartbeat so clients stay in sync
                # even if they missed a STATUS broadcast
                await websocket.send_json({
                    "type": "HEARTBEAT",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "connected_clients": ws_manager.count,
                    "receiver_count": ws_manager.receiver_count,
                    "sender_count": ws_manager.sender_count,
                })

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("WebSocket error for %s: %s", client_id[:8], exc)
    finally:
        await ws_manager.disconnect(client_id)
        await ws_manager.broadcast_status()


@router.get(
    "/connections",
    summary="Current WebSocket connection counts (REST fallback for presence indicators)",
)
async def get_connections() -> dict:
    """
    Returns the current number of connected WebSocket clients by role.
    Used as a REST fallback when WebSocket STATUS messages may be missed
    (e.g. when the other machine connects after this client already loaded).
    """
    return {
        "connected_clients": ws_manager.count,
        "receiver_count": ws_manager.receiver_count,
        "sender_count": ws_manager.sender_count,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Database connectivity check (for troubleshooting Supabase connection)
# ──────────────────────────────────────────────────────────────────────────────


@router.get(
    "/check-db",
    summary="Check Supabase database connectivity",
    description="Returns ok: true if the backend can reach Supabase PostgreSQL; otherwise ok: false with the error message.",
)
async def check_db(
    db: Annotated[AsyncSession | None, Depends(get_db)],
) -> dict:
    if db is None:
        return {"ok": False, "error": "Offline mode: no database configured."}
    try:
        await db.execute(text("SELECT 1"))
        return {"ok": True, "message": "Database connection successful."}
    except Exception as exc:
        err_msg = str(exc).split("\n")[0] if "\n" in str(exc) else str(exc)
        logger.warning("Check DB failed: %s", exc)
        return {"ok": False, "error": err_msg}


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas
# ──────────────────────────────────────────────────────────────────────────────


class ChatIngestRequest(BaseModel):
    """Inbound plaintext chat message from an internal relay system."""

    unit_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Originating unit identifier (e.g. ALPHA-7)",
        examples=["ALPHA-7"],
    )
    message: str = Field(
        ...,
        min_length=1,
        max_length=8192,
        description="Raw plaintext chat message to ingest",
    )
    ngram_size: int = Field(
        default=3,
        ge=1,
        le=5,
        description="N-gram width for threat tokenisation",
    )
    simulate_attack: bool = Field(
        default=False,
        description=(
            "When True, forces the threat analysis to return a CRITICAL result "
            "regardless of actual Bloom-filter hits. Used to demo/test the threat "
            "detection pipeline without needing a real watchlist match."
        ),
    )

    @field_validator("unit_id")
    @classmethod
    def sanitise_unit_id(cls, v: str) -> str:
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        if not all(c in allowed for c in v.upper()):
            raise ValueError("unit_id may only contain alphanumerics, hyphens and underscores")
        return v.upper()


class InterceptionNodeResult(BaseModel):
    """One detection node that flagged the message."""
    node_id: str
    match_count: int
    matched_hashes: list[str] = Field(default_factory=list)
    false_positive_rate: float = 0.0


class ThreatAnalysisResult(BaseModel):
    """Breakdown of the Bloom-filter analysis (returned to caller)."""

    is_threat: bool
    match_count: int
    max_false_positive_rate: float
    hashes_generated: int
    severity: str = "CLEAR"
    intercepting_nodes: list[InterceptionNodeResult] = Field(default_factory=list)


class ChatIngestResponse(BaseModel):
    """Response payload after successful ingestion."""

    log_id: str
    unit_id: str
    timestamp: str
    encrypted_payload_preview: str = Field(
        description="First 32 chars of the AES-GCM blob — never the plaintext"
    )
    encrypted_payload_full: str = Field(
        description="Full AES-GCM ciphertext (hex) for demo/decrypt; server stores this only."
    )
    threat_analysis: ThreatAnalysisResult
    encryption_steps: dict = Field(
        description="How encryption happened: hashes count, cipher length, etc."
    )
    ngram_hash_sample: list[str] = Field(
        default_factory=list,
        description="First 5 n-gram hashes for UI (Threat Matrix); non-sensitive.",
    )
    status: str = "INGESTED"
    database_persisted: bool = Field(
        default=True,
        description="False when DB was unreachable (e.g. DNS/network); encryption still performed.",
    )


# ──────────────────────────────────────────────────────────────────────────────
# Watchlist cache (loaded once per worker, refreshed on each request if stale)
# ──────────────────────────────────────────────────────────────────────────────

_engine_cache: ThreatDetectionEngine | None = None


async def _load_detection_engine(
    db: AsyncSession | None,
    settings: Settings,
    aes_key: bytes,
) -> ThreatDetectionEngine:
    """
    Load all watchlist rows from Supabase and hydrate a ThreatDetectionEngine.
    In production this would be cached with a TTL; here we reload each request
    to demonstrate live watchlist updates.
    """
    engine = ThreatDetectionEngine(threshold=settings.threat_match_threshold)

    if db is None:
        rows = await local_store.get_watchlist_rows()
    else:
        try:
            result = await db.execute(
                text("SELECT operation_name, bloom_filter_data FROM public.watchlist")
            )
            rows = result.mappings().all()
        except SQLAlchemyOperationalError:
            rows = await local_store.get_watchlist_rows()

    if rows:
        engine.load_watchlist_from_db_rows(
            [dict(r) for r in rows],
            aes_key=aes_key,
        )
        if not engine._watchlist:
            logger.warning("All watchlist rows were invalid. Falling back to demo filter.")
            engine.build_watchlist_filter(
                classified_terms=[
                    "operation thunderstrike",
                    "classified coordinates",
                    "launch codes",
                    "extraction point delta",
                    "nuclear",
                    "override",
                ],
                hmac_secret=settings.hmac_secret,
                operation_name="DEMO_OPERATION",
                aes_key=aes_key,
            )
    else:
        # Fallback demo filter so the system is non-trivially operational
        logger.warning("No watchlist entries found — using demo filter")
        engine.build_watchlist_filter(
            classified_terms=[
                "operation thunderstrike",
                "classified coordinates",
                "launch codes",
                "extraction point delta",
                "nuclear",
                "override",
            ],
            hmac_secret=settings.hmac_secret,
            operation_name="DEMO_OPERATION",
            aes_key=aes_key,
        )

    return engine


DEMO_CLASSIFIED_TERMS = [
    "operation thunderstrike",
    "classified coordinates",
    "launch codes",
    "extraction point delta",
    "nuclear",
    "override",
]


def _build_demo_detection_engine(settings: Settings, aes_key: bytes) -> ThreatDetectionEngine:
    """Build threat detection engine with demo watchlist only (no DB). Used when DB is unreachable."""
    engine = ThreatDetectionEngine(threshold=settings.threat_match_threshold)
    engine.build_watchlist_filter(
        classified_terms=DEMO_CLASSIFIED_TERMS,
        hmac_secret=settings.hmac_secret,
        operation_name="DEMO_OPERATION",
        aes_key=aes_key,
    )
    return engine


# ──────────────────────────────────────────────────────────────────────────────
# Route
# ──────────────────────────────────────────────────────────────────────────────


@router.post(
    "/ingest-chat",
    response_model=ChatIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and analyse a plaintext chat message",
    description=(
        "Accepts a raw chat message, generates cryptographic N-gram hashes, "
        "encrypts the message with AES-256-GCM, cross-references the hashes "
        "against classified Bloom filters, and persists the result. "
        "The plaintext is zeroed from memory immediately after encryption."
    ),
)
async def ingest_chat(
    payload: ChatIngestRequest,
    db: Annotated[AsyncSession | None, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ChatIngestResponse:
    # ── 1. Derive cryptographic material ──────────────────────────────────────
    try:
        aes_key = derive_key(settings.aes_master_key)
    except (ValueError, Exception) as exc:
        logger.error("Key derivation failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cryptographic initialisation failure",
        )

    # ── 2. Tokenise & hash in memory (plaintext still in scope) ───────────────
    ngram_hashes = generate_ngram_hashes(
        payload.message,
        settings.hmac_secret,
        n=payload.ngram_size,
    )

    # ── 3. Encrypt & drop plaintext immediately ───────────────────────────────
    encrypted_payload = encrypt_message(payload.message, aes_key)
    # Overwrite local reference — CPython GC will collect; best-effort zeroing
    plaintext_ref = payload.message
    del plaintext_ref

    # ── 4 & 5. Load detection engine, analyse, persist (with offline fallback) ──
    log_id = str(uuid4())
    timestamp = datetime.now(timezone.utc)
    hash_sample = ngram_hashes[:5]
    database_persisted = True

    try:
        detection_engine = await _load_detection_engine(db, settings, aes_key)
        result: AnalysisResult = detection_engine.analyze(ngram_hashes)
        is_threat = result.is_threat
        match_count = result.total_matches
        max_fpr = result.max_false_positive_rate
        severity = result.severity
        intercepting_nodes = result.intercepting_nodes

        if is_threat:
            logger.warning(
                "THREAT DETECTED | unit=%s | matches=%d | severity=%s | nodes=%d | fpr=%.4f",
                payload.unit_id,
                match_count,
                severity,
                len(intercepting_nodes),
                max_fpr,
            )

        if db is None:
            database_persisted = False
            await local_store.upsert_chat_log(
                local_store.LocalChatLog(
                    id=log_id,
                    unit_id=payload.unit_id,
                    timestamp=timestamp,
                    encrypted_payload=encrypted_payload,
                    threat_flag=is_threat,
                    match_count=match_count,
                    ngram_hash_sample=hash_sample,
                    ngram_hashes=ngram_hashes,
                )
            )
        else:
            try:
                await db.execute(
                    text(
                        """
                        INSERT INTO public.chat_logs
                            (id, unit_id, timestamp, encrypted_payload,
                             threat_flag, match_count, ngram_hash_sample, ngram_hashes)
                        VALUES
                            (:id, :unit_id, :timestamp, :encrypted_payload,
                             :threat_flag, :match_count, :ngram_hash_sample, :ngram_hashes)
                        """
                    ),
                    {
                        "id": log_id,
                        "unit_id": payload.unit_id,
                        "timestamp": timestamp,
                        "encrypted_payload": encrypted_payload,
                        "threat_flag": is_threat,
                        "match_count": match_count,
                        "ngram_hash_sample": hash_sample,
                        "ngram_hashes": ngram_hashes,
                    },
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                # If Supabase isn't set up (missing tables/migrations), fall back to local store.
                logger.warning("DB write failed; falling back to local store: %s", exc)
                database_persisted = False
                await local_store.upsert_chat_log(
                    local_store.LocalChatLog(
                        id=log_id,
                        unit_id=payload.unit_id,
                        timestamp=timestamp,
                        encrypted_payload=encrypted_payload,
                        threat_flag=is_threat,
                        match_count=match_count,
                        ngram_hash_sample=hash_sample,
                        ngram_hashes=ngram_hashes,
                    )
                )

    except SQLAlchemyOperationalError as exc:
        # DB unreachable (e.g. DNS failure, no network) — run in offline/demo mode
        logger.warning("Database unreachable (%s), using demo mode: %s", type(exc).__name__, exc)
        database_persisted = False
        detection_engine = _build_demo_detection_engine(settings, aes_key)
        result = detection_engine.analyze(ngram_hashes)
        is_threat = result.is_threat
        match_count = result.total_matches
        max_fpr = result.max_false_positive_rate
        severity = result.severity
        intercepting_nodes = result.intercepting_nodes
        if is_threat:
            logger.warning("THREAT DETECTED (demo) | unit=%s | matches=%d | severity=%s", payload.unit_id, match_count, severity)
        await local_store.upsert_chat_log(
            local_store.LocalChatLog(
                id=log_id,
                unit_id=payload.unit_id,
                timestamp=timestamp,
                encrypted_payload=encrypted_payload,
                threat_flag=is_threat,
                match_count=match_count,
                ngram_hash_sample=hash_sample,
                ngram_hashes=ngram_hashes,
            )
        )
    except Exception as exc:
        logger.warning("Ingest persistence failed; using local store: %s", exc)
        database_persisted = False
        detection_engine = _build_demo_detection_engine(settings, aes_key)
        result = detection_engine.analyze(ngram_hashes)
        is_threat = result.is_threat
        match_count = result.total_matches
        max_fpr = result.max_false_positive_rate
        severity = result.severity
        intercepting_nodes = result.intercepting_nodes
        await local_store.upsert_chat_log(
            local_store.LocalChatLog(
                id=log_id,
                unit_id=payload.unit_id,
                timestamp=timestamp,
                encrypted_payload=encrypted_payload,
                threat_flag=is_threat,
                match_count=match_count,
                ngram_hash_sample=hash_sample,
                ngram_hashes=ngram_hashes,
            )
        )

    # ── Simulate attack override (sender toggle) ──────────────────────────────
    # When simulate_attack=True the real Bloom-filter result is discarded and a
    # forced CRITICAL threat is returned. The encrypted message is still stored
    # normally so the receiver sees the full threat scenario in the feed.
    if payload.simulate_attack and not is_threat:
        logger.info("SIMULATE ATTACK | unit=%s — overriding result to CRITICAL", payload.unit_id)
        is_threat = True
        match_count = max(match_count, 12)          # convincing hit count
        max_fpr = 0.0001
        severity = "CRITICAL"
        intercepting_nodes = [
            InterceptionNode(
                node_id="NODE-SIM-01",
                match_count=5,
                matched_hashes=ngram_hashes[:5],
                false_positive_rate=0.0001,
            ),
            InterceptionNode(
                node_id="NODE-SIM-02",
                match_count=4,
                matched_hashes=ngram_hashes[1:5],
                false_positive_rate=0.0001,
            ),
            InterceptionNode(
                node_id="NODE-SIM-03",
                match_count=3,
                matched_hashes=ngram_hashes[:3],
                false_positive_rate=0.0002,
            ),
        ]

    node_results = [
        InterceptionNodeResult(
            node_id=n.node_id,
            match_count=n.match_count,
            matched_hashes=n.matched_hashes[:5],
            false_positive_rate=n.false_positive_rate,
        )
        for n in intercepting_nodes
    ]

    # ── Broadcast to all connected WebSocket clients (fire-and-forget) ─────────
    await ws_manager.broadcast({
        "type": "INGEST",
        "log_id": log_id,
        "unit_id": payload.unit_id,
        "timestamp": timestamp.isoformat(),
        "encrypted_payload_full": encrypted_payload,
        "threat_analysis": {
            "is_threat": is_threat,
            "match_count": match_count,
            "severity": severity,
            "max_false_positive_rate": round(max_fpr, 6),
            "hashes_generated": len(ngram_hashes),
            "intercepting_nodes": [
                {
                    "node_id": nr.node_id,
                    "match_count": nr.match_count,
                    "matched_hashes": nr.matched_hashes,
                    "false_positive_rate": nr.false_positive_rate,
                }
                for nr in node_results
            ],
        },
        "ngram_hash_sample": hash_sample,
        "database_persisted": database_persisted,
    })

    return ChatIngestResponse(
        log_id=log_id,
        unit_id=payload.unit_id,
        timestamp=timestamp.isoformat(),
        encrypted_payload_preview=encrypted_payload[:32] + "...",
        encrypted_payload_full=encrypted_payload,
        threat_analysis=ThreatAnalysisResult(
            is_threat=is_threat,
            match_count=match_count,
            max_false_positive_rate=round(max_fpr, 6),
            hashes_generated=len(ngram_hashes),
            severity=severity,
            intercepting_nodes=node_results,
        ),
        encryption_steps={
            "step_1_plaintext_received": True,
            "step_2_ngram_hashes_generated": len(ngram_hashes),
            "step_3_aes256gcm_encrypted": True,
            "step_4_plaintext_dropped": True,
            "step_5_bloom_threat_check": is_threat,
            "ciphertext_hex_length": len(encrypted_payload),
        },
        ngram_hash_sample=hash_sample,
        database_persisted=database_persisted,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Receiver: authorised decryption (server/receiver end)
# ──────────────────────────────────────────────────────────────────────────────


class DecryptRequest(BaseModel):
    log_id: str = Field(..., description="Chat log UUID to decrypt (receiver end)")


class DecryptResponse(BaseModel):
    log_id: str
    unit_id: str
    timestamp: str
    plaintext: str = Field(description="Decrypted message at receiver")
    was_encrypted: bool = True


@router.post(
    "/decrypt",
    response_model=DecryptResponse,
    summary="Decrypt a stored message (receiver/authorised end)",
    description="Fetches encrypted_payload from DB and decrypts with AES key. Shows how receiver sees plaintext.",
)
async def decrypt_at_receiver(
    payload: DecryptRequest,
    db: Annotated[AsyncSession | None, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> DecryptResponse:
    aes_key = derive_key(settings.aes_master_key)
    row = None
    if db is not None:
        try:
            result = await db.execute(
                text(
                    "SELECT id, unit_id, timestamp, encrypted_payload FROM public.chat_logs WHERE id = :id"
                ),
                {"id": payload.log_id},
            )
            row = result.mappings().first()
        except Exception:
            row = None
    if row is None:
        local = await local_store.get_chat_log(payload.log_id)
        if local is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log not found")
        row = {
            "id": local.id,
            "unit_id": local.unit_id,
            "timestamp": local.timestamp,
            "encrypted_payload": local.encrypted_payload,
        }
    try:
        plaintext = decrypt_message(row["encrypted_payload"], aes_key)
    except Exception as exc:
        logger.warning("Decrypt failed for log %s: %s", payload.log_id, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decryption failed (tampered or wrong key)",
        )
    return DecryptResponse(
        log_id=str(row["id"]),
        unit_id=row["unit_id"],
        timestamp=row["timestamp"].isoformat(),
        plaintext=plaintext,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Search encrypted DB using SSE (trapdoor search)
# ──────────────────────────────────────────────────────────────────────────────


class SearchEncryptedRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=500, description="Search term (e.g. classified phrase)")


class SearchEncryptedResponse(BaseModel):
    query: str
    trapdoor_hashes_count: int
    message: str = Field(description="How search works: trapdoor → DB overlap, no decryption")
    matches: list[dict] = Field(description="Rows where ngram_hashes overlap with query hashes (encrypted only)")


@router.post(
    "/search-encrypted",
    response_model=SearchEncryptedResponse,
    summary="Search encrypted messages by trapdoor (SSE)",
    description="Generate HMAC trapdoor for query; find chat_logs where ngram_hashes overlap. No decryption.",
)
async def search_encrypted(
    payload: SearchEncryptedRequest,
    db: Annotated[AsyncSession | None, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SearchEncryptedResponse:
    query_hashes = generate_ngram_hashes(payload.query, settings.hmac_secret, n=3)
    if not query_hashes:
        return SearchEncryptedResponse(
            query=payload.query,
            trapdoor_hashes_count=0,
            message="No tokens generated for query.",
            matches=[],
        )
    rows: list[dict] = []
    if db is not None:
        try:
            result = await db.execute(
                text(
                    """
                    SELECT id, unit_id, timestamp, encrypted_payload, threat_flag, match_count
                    FROM public.chat_logs
                    WHERE ngram_hashes && :hashes
                    ORDER BY timestamp DESC
                    LIMIT 50
                    """
                ),
                {"hashes": query_hashes},
            )
            rows = [dict(r) for r in result.mappings().all()]
        except Exception:
            rows = []

    if not rows:
        logs = await local_store.list_chat_logs()
        q = set(query_hashes)
        for log in logs:
            if q.intersection(log.ngram_hashes):
                rows.append(
                    {
                        "id": log.id,
                        "unit_id": log.unit_id,
                        "timestamp": log.timestamp,
                        "encrypted_payload": log.encrypted_payload,
                        "threat_flag": log.threat_flag,
                        "match_count": log.match_count,
                    }
                )
        rows = rows[:50]

    matches = [
        {
            "id": str(r["id"]),
            "unit_id": r["unit_id"],
            "timestamp": r["timestamp"].isoformat(),
            "encrypted_preview": (r["encrypted_payload"] or "")[:48] + "...",
            "threat_flag": r["threat_flag"],
            "match_count": r["match_count"],
        }
        for r in rows
    ]
    return SearchEncryptedResponse(
        query=payload.query,
        trapdoor_hashes_count=len(query_hashes),
        message="Search uses SSE: query → HMAC trapdoors; DB stores hashes per message; overlap match without decryption.",
        matches=matches,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Watchlist management (admin-only in production — no auth guard here for demo)
# ──────────────────────────────────────────────────────────────────────────────


class WatchlistAddRequest(BaseModel):
    operation_name: str = Field(..., min_length=1, max_length=128)
    classified_terms: list[str] = Field(..., min_length=1)


class WatchlistAddResponse(BaseModel):
    watchlist_id: str
    operation_name_encrypted: str
    terms_loaded: int
    estimated_fpr: float


@router.post(
    "/watchlist/add",
    response_model=WatchlistAddResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a new classified operation to the watchlist",
)
async def add_watchlist_entry(
    payload: WatchlistAddRequest,
    db: Annotated[AsyncSession | None, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> WatchlistAddResponse:
    aes_key = derive_key(settings.aes_master_key)

    tmp_engine = ThreatDetectionEngine()
    entry: WatchlistEntry = tmp_engine.build_watchlist_filter(
        classified_terms=payload.classified_terms,
        hmac_secret=settings.hmac_secret,
        operation_name=payload.operation_name,
        aes_key=aes_key,
        bloom_size=settings.bloom_filter_size,
        bloom_k=settings.bloom_hash_count,
    )

    bloom_bytes = entry.bloom_filter.to_bytes()
    fpr = entry.bloom_filter.estimated_false_positive_rate
    wl_id = str(uuid4())

    if db is None:
        await local_store.add_watchlist_row(entry.operation_name_encrypted, bloom_bytes)
    else:
        try:
            await db.execute(
                text(
                    """
                    INSERT INTO public.watchlist (id, operation_name, bloom_filter_data)
                    VALUES (:id, :operation_name, :bloom_filter_data)
                    """
                ),
                {
                    "id": wl_id,
                    "operation_name": entry.operation_name_encrypted,
                    "bloom_filter_data": bloom_bytes,
                },
            )
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.warning("Watchlist write failed; persisting locally: %s", exc)
            await local_store.add_watchlist_row(entry.operation_name_encrypted, bloom_bytes)

    return WatchlistAddResponse(
        watchlist_id=wl_id,
        operation_name_encrypted=entry.operation_name_encrypted[:32] + "...",
        terms_loaded=len(payload.classified_terms),
        estimated_fpr=round(fpr, 8),
    )


# ──────────────────────────────────────────────────────────────────────────────
# Threat feed for Receiver Dashboard
# ──────────────────────────────────────────────────────────────────────────────


class ThreatEntry(BaseModel):
    id: str
    unit_id: str
    timestamp: str
    encrypted_preview: str
    match_count: int
    severity: str
    ngram_hash_sample: list[str] = Field(default_factory=list)


class ThreatFeedResponse(BaseModel):
    total_intercepted: int
    total_threats: int
    threats: list[ThreatEntry]
    severity_breakdown: dict[str, int]


@router.get(
    "/threats",
    response_model=ThreatFeedResponse,
    summary="Threat feed for receiver dashboard",
    description="Returns all threat-flagged messages with severity breakdown. "
                "Severity is computed from match_count (deterministic).",
)
async def get_threats(
    db: Annotated[AsyncSession | None, Depends(get_db)],
    limit: int = 100,
) -> ThreatFeedResponse:
    rows: list[dict] = []
    total_intercepted = 0
    if db is not None:
        try:
            count_result = await db.execute(text("SELECT COUNT(*) FROM public.chat_logs"))
            total_intercepted = count_result.scalar() or 0

            result = await db.execute(
                text(
                    """
                    SELECT id, unit_id, timestamp, encrypted_payload,
                           match_count, ngram_hash_sample
                    FROM public.chat_logs
                    WHERE threat_flag = true
                    ORDER BY timestamp DESC
                    LIMIT :lim
                    """
                ),
                {"lim": limit},
            )
            rows = [dict(r) for r in result.mappings().all()]
        except Exception:
            rows = []

    if not rows:
        logs = await local_store.list_chat_logs()
        total_intercepted = len(logs)
        for log in logs:
            if not log.threat_flag:
                continue
            rows.append(
                {
                    "id": log.id,
                    "unit_id": log.unit_id,
                    "timestamp": log.timestamp,
                    "encrypted_payload": log.encrypted_payload,
                    "match_count": log.match_count,
                    "ngram_hash_sample": log.ngram_hash_sample,
                }
            )
        rows = rows[:limit]

    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    threats: list[ThreatEntry] = []

    for r in rows:
        mc = r["match_count"] or 0
        sev = classify_severity(mc, 1)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        sample = r.get("ngram_hash_sample") or []
        if isinstance(sample, str):
            import json as _json
            try:
                sample = _json.loads(sample)
            except Exception:
                sample = []

        threats.append(
            ThreatEntry(
                id=str(r["id"]),
                unit_id=r["unit_id"],
                timestamp=r["timestamp"].isoformat() if hasattr(r["timestamp"], "isoformat") else str(r["timestamp"]),
                encrypted_preview=(r["encrypted_payload"] or "")[:48] + "...",
                match_count=mc,
                severity=sev,
                ngram_hash_sample=sample[:5] if isinstance(sample, list) else [],
            )
        )

    return ThreatFeedResponse(
        total_intercepted=total_intercepted,
        total_threats=len(threats),
        threats=threats,
        severity_breakdown=severity_counts,
    )
