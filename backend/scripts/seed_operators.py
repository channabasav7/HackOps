"""
Seed pre-existing operators for Project Sentinel.
Run after applying models/operators_schema.sql.
Uses SUPABASE_DB_URL from .env (sync URL; script uses sync psycopg2 for simplicity).
"""
from __future__ import annotations

import os
import sys

# Add backend root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

import bcrypt
import psycopg

# Pre-existing operator credentials (provisioned; not user-registered)
OPERATORS = [
    {
        "operator_uuid": "550e8400-e29b-41d4-a716-446655440001",
        "password": "sentinel-sender-01",
        "role": "sender",
    },
    {
        "operator_uuid": "550e8400-e29b-41d4-a716-446655440002",
        "password": "sentinel-receiver-01",
        "role": "receiver",
    },
]


def main() -> None:
    url = os.environ.get("SUPABASE_DB_URL")
    if not url:
        print("SUPABASE_DB_URL not set in .env")
        sys.exit(1)

    conn = psycopg.connect(url)
    try:
        for op in OPERATORS:
            pw_hash = bcrypt.hashpw(
                op["password"].encode("utf-8"),
                bcrypt.gensalt(),
            ).decode("utf-8")
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.operators (operator_uuid, password_hash, role)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (operator_uuid) DO UPDATE
                    SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role
                    """,
                    (op["operator_uuid"], pw_hash, op["role"]),
                )
        conn.commit()
        print("Operators seeded successfully.")
        print("Sender   UUID: 550e8400-e29b-41d4-a716-446655440001  password: sentinel-sender-01")
        print("Receiver UUID: 550e8400-e29b-41d4-a716-446655440002  password: sentinel-receiver-01")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
