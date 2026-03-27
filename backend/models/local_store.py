"""
Local/offline in-memory store for Project Sentinel.

This is used when SENTINEL_OFFLINE_MODE=true, or when the database dependency
is unavailable. It enables a self-contained demo without Supabase.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime


DEMO_OPERATORS: dict[str, dict[str, str]] = {
    # Matches README demo credentials
    "550e8400-e29b-41d4-a716-446655440001": {"role": "sender", "password": "sentinel-sender-01"},
    "550e8400-e29b-41d4-a716-446655440002": {"role": "receiver", "password": "sentinel-receiver-01"},
}


@dataclass(frozen=True)
class LocalChatLog:
    id: str
    unit_id: str
    timestamp: datetime
    encrypted_payload: str
    threat_flag: bool
    match_count: int
    ngram_hash_sample: list[str]
    ngram_hashes: list[str]


_lock = asyncio.Lock()
_chat_logs: dict[str, LocalChatLog] = {}
_watchlist_rows: list[dict] = []  # {"operation_name": str, "bloom_filter_data": bytes}


async def upsert_chat_log(log: LocalChatLog) -> None:
    async with _lock:
        _chat_logs[log.id] = log


async def get_chat_log(log_id: str) -> LocalChatLog | None:
    async with _lock:
        return _chat_logs.get(log_id)


async def list_chat_logs() -> list[LocalChatLog]:
    async with _lock:
        return sorted(_chat_logs.values(), key=lambda r: r.timestamp, reverse=True)


async def add_watchlist_row(operation_name: str, bloom_filter_data: bytes) -> None:
    async with _lock:
        _watchlist_rows.append(
            {"operation_name": operation_name, "bloom_filter_data": bloom_filter_data}
        )


async def get_watchlist_rows() -> list[dict]:
    async with _lock:
        return list(_watchlist_rows)

