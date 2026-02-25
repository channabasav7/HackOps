# Project Sentinel

### Zero-Exposure Threat Detection System for Military Communications

> A confidential encrypted communication channel between **Sender** and **Receiver** systems. Detects classified keyword leaks using **Searchable Symmetric Encryption (SSE)** and **Bloom Filters** — without ever decrypting the underlying messages. Supports **live WebSocket** delivery across two machines.

---

## Features

| Feature | Description |
|--------|-------------|
| **Role-based access** | Separate Sender and Receiver dashboards; UUID + password login (no self-registration). |
| **Custom & demo messages** | Sender can type their own message or cycle through demo messages; both use the same encryption pipeline. |
| **Live two-machine setup** | Sender on one laptop, Receiver on another; both connect to the same backend via WebSocket + REST. |
| **Real-time presence** | Sender sees "RECEIVER ONLINE"; Receiver sees "SENDER ONLINE" (WebSocket + REST polling fallback). |
| **Threat detection** | N-gram HMAC hashes → Bloom filter probe → severity (CLEAR / LOW / MEDIUM / HIGH / CRITICAL) and **which nodes** intercepted. |
| **SSE search** | Receiver can search encrypted messages by trapdoor (no decryption). |
| **Authorised decryption** | Receiver decrypts by log ID with server-side AES key. |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PROJECT SENTINEL                                         │
│                                                                                  │
│  LAPTOP A (Sender)                    LAPTOP B (Receiver)                        │
│  ┌─────────────────────┐             ┌─────────────────────┐                     │
│  │ Next.js /sender     │             │ Next.js /receiver   │                     │
│  │ • Compose / Demo    │             │ • Live Intercept    │                     │
│  │ • Transmission log  │             │   Feed              │                     │
│  │ • Receiver online   │             │ • Threat Matrix     │                     │
│  │   indicator         │             │ • Threat Intel      │                     │
│  └──────────┬──────────┘             │ • Decrypt / SSE     │                     │
│             │                         │   Search             │                     │
│             │ POST /api/ingest-chat   │ • Sender online     │                     │
│             │ WebSocket /api/ws       │   indicator         │                     │
│             └────────────┬───────────┴──────────┬──────────┘                     │
│                           │                      │                                │
│                           ▼                      ▼                                │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                    FastAPI Backend (e.g. 10.53.222.69:8000)                  │ │
│  │  1. N-gram HMAC-SHA256 hashing  2. AES-256-GCM encrypt  3. Plaintext drop   │ │
│  │  4. Bloom filter threat check → severity + intercepting_nodes                 │ │
│  │  5. Persist ciphertext to DB    6. Broadcast INGEST via WebSocket             │ │
│  └───────────────────────────────────────┬─────────────────────────────────────┘ │
│                                          │                                        │
│                                          ▼                                        │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │  Supabase (PostgreSQL)  • chat_logs  • watchlist  • operators               │ │
│  │  Realtime (optional fallback for receiver feed)                             │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Stack

| Layer | Technology |
|-------|------------|
| Backend API | Python 3.11+, FastAPI, Uvicorn |
| Auth | JWT (PyJWT), bcrypt; custom `/api/auth/login` (UUID + password) |
| Cryptography | `cryptography` (AES-256-GCM), HMAC-SHA256 for n-gram SSE |
| Bloom Filter | `bitarray`; per-node interception + severity classification |
| Database | Supabase (PostgreSQL) — `chat_logs`, `watchlist`, `operators` |
| ORM | SQLAlchemy 2.0 async |
| Realtime | WebSocket `/api/ws` (primary); Supabase Realtime (receiver fallback) |
| Frontend | Next.js 14 App Router, React 18, TypeScript |
| Styling | Tailwind CSS, Framer Motion |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- A Supabase project

---

### 1. Supabase setup

1. In Supabase **SQL Editor**, run (in order):
   - `backend/models/schema.sql` — chat_logs, watchlist, Realtime
   - `backend/models/operators_schema.sql` — operators table
   - `backend/models/migration_ngram_hashes.sql` — ngram_hashes column for SSE search

2. Note **Project URL**, **anon key**, and **database connection string** from Project Settings → API.

3. If the backend reports "Database unreachable", see **docs/CONNECT_SUPABASE.md**.

---

### 2. Backend

```bash
cd backend

cp .env.example .env
# Edit .env:
#   SUPABASE_DB_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
#   AES_MASTER_KEY (64 hex chars), HMAC_SECRET
#   JWT_SECRET (optional; default dev value)

pip install -r requirements.txt
python scripts/seed_operators.py   # Demo sender + receiver accounts
python main.py
# → http://localhost:8000  (Swagger: /docs)
```

---

### 3. Frontend

```bash
cd frontend

cp .env.local.example .env.local
# Edit .env.local:
#   NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY
#   NEXT_PUBLIC_API_URL=http://localhost:8000

npm install
npm run dev
# → http://localhost:3000
```

---

### 4. Log in

- **Landing:** http://localhost:3000 → choose **Sender** or **Receiver**.
- **Sender:** http://localhost:3000/login/sender  
  UUID: `550e8400-e29b-41d4-a716-446655440001`  
  Password: `sentinel-sender-01`
- **Receiver:** http://localhost:3000/login/receiver  
  UUID: `550e8400-e29b-41d4-a716-446655440002`  
  Password: `sentinel-receiver-01`

See **docs/AUTH_OPERATORS.md** for full auth setup.

---

## Two-machine (sender / receiver) setup

Run the **backend on one machine** (e.g. Machine A). Both frontends point to it.

1. **On Machine A (backend host):**  
   - Run backend: `cd backend && python main.py`  
   - Run frontend: `cd frontend && npm run dev`  
   - Note Machine A’s LAN IP (e.g. `10.53.222.69`).

2. **On both machines**, set the frontend API URL to the backend:
   ```env
   NEXT_PUBLIC_API_URL=http://10.53.222.69:8000
   ```
   (Replace with your backend machine’s IP.)

3. **Machine A:** Open `http://localhost:3000` or `http://10.53.222.69:3000` → log in as **Sender**.  
4. **Machine B:** Open `http://10.53.222.69:3000` (or run Next.js on B with same `NEXT_PUBLIC_API_URL`) → log in as **Receiver**.

Backend CORS and Next.js `allowedDevOrigins` are preconfigured for common LAN IPs; adjust in `backend/main.py` and `frontend/next.config.js` if your IPs differ.

- **WebSocket:** Sender and Receiver connect to `ws://<API_HOST>:8000/api/ws?role=sender` or `?role=receiver`.
- **Presence:** "RECEIVER ONLINE" / "SENDER ONLINE" use WebSocket STATUS/HEARTBEAT plus REST polling of `GET /api/connections` every 5 seconds.

---

## Key API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Operator login (UUID + password) → JWT. |
| POST | `/api/ingest-chat` | Ingest plaintext → encrypt, Bloom check, persist, broadcast INGEST via WebSocket. |
| GET  | `/api/ws` | WebSocket; query `?role=sender` or `?role=receiver`. |
| GET  | `/api/connections` | Current WebSocket connection counts (REST fallback for presence). |
| GET  | `/api/threats` | Threat-flagged messages + severity breakdown for receiver dashboard. |
| POST | `/api/decrypt` | Decrypt by `log_id` (receiver only). |
| POST | `/api/search-encrypted` | SSE trapdoor search (no decryption). |
| POST | `/api/watchlist/add` | Add classified operation terms to watchlist. |
| GET  | `/health` | Health check. |

### Ingest request/response (summary)

**Request:** `POST /api/ingest-chat`

```json
{
  "unit_id": "ALPHA-7",
  "message": "Your plaintext or custom message here",
  "ngram_size": 3
}
```

**Response** includes:

- `log_id`, `unit_id`, `timestamp`, `encrypted_payload_preview`, `encrypted_payload_full`
- `threat_analysis`: `is_threat`, `match_count`, `max_false_positive_rate`, `hashes_generated`, **`severity`** (CLEAR | LOW | MEDIUM | HIGH | CRITICAL), **`intercepting_nodes`** (node_id, match_count, matched_hashes, false_positive_rate)
- `ngram_hash_sample`, `database_persisted`

---

## Sender dashboard

- **Encrypt & Transmit** panel:
  - **COMPOSE:** Custom Unit/Callsign + free-text message (max 2048 chars). **Encrypt & Send** uses the same pipeline as demo; Ctrl+Enter to send.
  - **DEMO:** Cycle through preset messages (classified/non-classified) and send with one click.
- After each send: interception status (THREAT INTERCEPTED / TRANSMISSION CLEAR), severity badge, **which nodes** intercepted (if any), encryption pipeline steps, ciphertext preview.
- **Transmission log:** Recent sends with status and severity.
- **Receiver online indicator:** Shows when at least one receiver is connected (WebSocket + REST poll).

---

## Receiver dashboard

- **Live Intercept Feed:** Incoming messages (from WebSocket INGEST + Supabase Realtime fallback) with severity badges.
- **Threat Matrix:** Bloom collision map for the latest entry.
- **Threat Intelligence:** Fetches `/api/threats`; severity breakdown (CRITICAL/HIGH/MEDIUM/LOW) and list of threat entries.
- **Alert panel:** Active threats with severity and match count.
- **Authorised decryption:** Decrypt by log ID.
- **SSE Encrypted Search:** Search by trapdoor (query → hashes → overlap with stored hashes).
- **Sender online indicator:** Shows when at least one sender is connected.
- **No message sending:** Receiver cannot send messages; only monitor, decrypt, and search.

---

## Threat detection (backend)

- **N-gram hashes:** Unigrams, n-grams (default n=3), character bigrams → HMAC-SHA256 with `HMAC_SECRET`.
- **Bloom filters:** One filter per watchlist entry; each probed with the message’s hashes.
- **Per-node tracking:** Each filter that matches is reported as an **intercepting node** (node_id, match_count, sample hashes, FPR).
- **Severity:** Derived from total match count and number of nodes (e.g. CLEAR, LOW, MEDIUM, HIGH, CRITICAL).
- **Zero-exposure:** Plaintext is not stored; only ciphertext and threat metadata (e.g. match_count, ngram_hash_sample) are persisted.

---

## Cryptographic design

- **AES-256-GCM:** 256-bit key, 96-bit random nonce per message; output = nonce || ciphertext+tag (hex).
- **SSE:** Same HMAC secret for n-gram hashes (separate from AES key); used for search and Bloom probe.
- **Bloom:** 10k bits, k=7 (double-hashing); serialised for PostgreSQL `bytea`.

---

## Project structure

```
AIT/
├── backend/
│   ├── api/routes/
│   │   ├── auth.py           # POST /api/auth/login (UUID + password → JWT)
│   │   └── monitor.py        # ingest, ws, connections, threats, decrypt, search, watchlist
│   ├── core/
│   │   └── crypto_engine.py  # AES-GCM, n-gram SSE, Bloom, ThreatDetectionEngine, severity
│   ├── config/settings.py
│   ├── models/
│   │   ├── schema.sql
│   │   ├── operators_schema.sql
│   │   ├── migration_ngram_hashes.sql
│   │   └── database.py
│   ├── scripts/
│   │   └── seed_operators.py
│   ├── main.py
│   └── requirements.txt
├── frontend/
│   ├── app/
│   │   ├── auth-context.tsx
│   │   ├── page.tsx              # Landing
│   │   ├── command-center.tsx    # SenderDashboard + ReceiverDashboard
│   │   ├── login/sender/page.tsx
│   │   ├── login/receiver/page.tsx
│   │   ├── sender/page.tsx
│   │   └── receiver/page.tsx
│   ├── hooks/
│   │   └── useWebSocket.ts       # Live channel + presence
│   ├── lib/
│   │   ├── supabase.ts
│   │   ├── types.ts
│   │   └── utils.ts
│   ├── next.config.js            # allowedDevOrigins for two-machine dev
│   └── package.json
└── docs/
    ├── AUTH_OPERATORS.md
    └── CONNECT_SUPABASE.md
```

---

## Environment variables

### Backend (`.env`)

| Variable | Description |
|----------|-------------|
| `SUPABASE_DB_URL` | PostgreSQL connection string |
| `SUPABASE_URL` | Project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Service role key |
| `AES_MASTER_KEY` | 64-char hex (32-byte key for AES-256-GCM) |
| `HMAC_SECRET` | Secret for n-gram HMAC (no placeholder) |
| `JWT_SECRET` | JWT signing secret (optional; dev default exists) |
| `JWT_EXPIRE_MINUTES` | Token lifetime (default 1440) |

### Frontend (`.env.local`)

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Anon key |
| `NEXT_PUBLIC_API_URL` | Backend base URL (e.g. `http://localhost:8000` or `http://10.53.222.69:8000` for two-machine) |

---

## Demo credentials (after `seed_operators.py`)

| Role     | Operator UUID                             | Password              |
|----------|-------------------------------------------|------------------------|
| Sender   | `550e8400-e29b-41d4-a716-446655440001`   | `sentinel-sender-01`   |
| Receiver | `550e8400-e29b-41d4-a716-446655440002`   | `sentinel-receiver-01` |

---

## License

Unclassified demo — use according to your organization’s policy.
