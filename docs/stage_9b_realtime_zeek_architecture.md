# Stage 9B Architecture — Real-Time Zeek Native Telemetry + SSE

## Executive Summary

Stage 9B introduces a real-time ingestion pipeline for native Zeek `conn.log` telemetry, delivering live connection streams to the React SOC Dashboard via Server-Sent Events (SSE) and persisting connection records into PostgreSQL.

In accordance with the Stage 9A empirical validation gate failure, **NO ML inference is performed on Zeek telemetry**. All Zeek connection records are strictly tagged with `source_channel="ZEEK_CONN"`, `ml_classification_performed=false`, and null ML fields. The validated Stage 6A/6B PCAP pipeline remains the sole path for ML threat detection (XGBoost + Isolation Forest + Risk Engine).

---

## 1. System Architecture

```
Zeek IDS (spool dir)
  │
  ▼ writes conn.log (JSON / TSV)
SpoolTailer (watchfiles / polling)
  │ reads new bytes, detects rotation
  ▼ enqueues ZeekConnectionRecord
Bounded asyncio.Queue (maxsize=4096)
  │ backpressure throttling
  ▼ consumes & micro-batches (50 records / 2.0s)
IngestionWorker
  ├── 1. Persists batch to PostgreSQL (AnalysisJob + SecurityEvent + FlowProvenance)
  ├── 2. Updates durable checkpoint in SAME transaction (IngestionCheckpoint)
  └── 3. Publishes to EventBroadcaster (in-process pub/sub)
            │
            ├── Ring Buffer (256 events)
            └── Per-subscriber Bounded Queue (128 events)
                  │
                  ▼ SSE Stream (GET /api/v1/zeek/stream)
            React Dashboard (Zeek Live View)
```

---

## 2. Core Invariants & Governance Rules

1. **Durable Transactional Checkpointing**:
   - The `ingestion_checkpoints` table stores the exact file byte offset and lines processed.
   - The checkpoint update is executed **within the same PostgreSQL transaction** that persists the batch of `SecurityEvent`, `FlowProvenance`, and `AnalysisJob` records.
   - Invariant: `DB commit succeeds` $\implies$ `checkpoint advances`. `DB transaction fails` $\implies$ `checkpoint does NOT advance`.
2. **Zero Data Loss on Database Failure**:
   - If PostgreSQL becomes temporarily unavailable, the worker does NOT drop valid records.
   - The worker pauses the `SpoolTailer` and polls DB health every 10 seconds.
   - When the DB recovers, the batch is retried and committed.
   - Because the durable checkpoint was never advanced for the uncommitted batch, crash recovery resumes from the last successfully committed offset.
3. **Session-Scoped SSE Sequence IDs**:
   - Sequence IDs follow the format `<session_id>:<sequence_id>`.
   - The `session_id` is a unique process-level identifier regenerated on every backend restart.
   - SSE replay using `Last-Event-ID` is guaranteed only within the active process session (from the 256-event ring buffer).
   - If a client reconnects with a `session_id` from a previous run, the server skips replay and the client fills gaps from the historical telemetry API (`GET /api/v1/telemetry/events`).
4. **Graceful Shutdown Semantics**:
   - On application shutdown, the `SpoolTailer` is stopped immediately (no new reads).
   - The `IngestionWorker` drains the in-memory queue and persists remaining records.
   - If the database is unreachable during shutdown, the worker exits without falsely advancing the checkpoint, ensuring clean recovery on next launch.

---

## 3. Database Schema

### `ingestion_checkpoints` Table

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PRIMARY KEY | Unique checkpoint identifier |
| `spool_directory` | VARCHAR(512) | NOT NULL, INDEX | Canonical absolute path of spool directory |
| `file_name` | VARCHAR(255) | NOT NULL | Tracked filename (e.g. `conn.log`) |
| `file_inode` | BIGINT | NULLABLE | OS inode for log rotation detection |
| `byte_offset` | BIGINT | NOT NULL, DEFAULT 0 | Last committed file read offset |
| `lines_processed` | BIGINT | NOT NULL, DEFAULT 0 | Cumulative lines processed from file |
| `last_zeek_uid` | VARCHAR(24) | NULLABLE | Diagnostic Zeek UID from last committed record |
| `updated_at` | TIMESTAMPTZ | NOT NULL | Last update timestamp |
| `created_at` | TIMESTAMPTZ | NOT NULL | Row creation timestamp |

*Constraint:* `UNIQUE(spool_directory, file_name)`

---

## 4. API Endpoints

### 4.1 SSE Telemetry Stream: `GET /api/v1/zeek/stream`

- **Protocol**: Server-Sent Events (`text/event-stream`)
- **Query Parameter**: `last_event_id` (optional string, e.g. `12dac9d3f5dc:42`)
- **Header**: `Last-Event-ID` (standard SSE header)
- **Event Types**:
  - `connected`: `{ "session_id": "...", "replay_supported": true }`
  - `zeek_connection`: Native 5-tuple, protocol, service, duration, byte counts, packets, state, history
  - `ingestion_status`: Periodic 30s status pulse
  - `: heartbeat`: 15s keep-alive comment
- **Client Cap**: Maximum 32 concurrent connections (`ZEEK_SSE_MAX_CLIENTS`). Returns `HTTP 429 Too Many Requests` when saturated.

### 4.2 Ingestion Status: `GET /api/v1/zeek/ingestion/status`

- **Response**: `ZeekIngestionStatus` schema with:
  - `status`: `"running" | "paused" | "stopped" | "disabled"`
  - `counters`: `records_read`, `records_parsed`, `records_malformed`, `records_duplicate`, `records_persisted`, `batches_persisted`, `queue_depth`, `sse_clients_connected`, etc.
  - `latest_batch`: `ingestion_lag_ms`, `flush_latency_ms`, `records_in_batch`
  - `tracked_files`: Active files and their current byte offsets

---

## 5. Frontend Integration

1. **Zeek Live Stream View** (`ZeekLiveView.tsx`):
   - Real-time rolling connection table (500-event buffer)
   - Connection status indicator (`ZeekConnectionIndicator.tsx`) with pulse animations
   - Live KPI cards (`ZeekLiveStats.tsx`) showing live rate, persisted counts, lag, and queue depth
   - Search/filter controls by IP, port, protocol (ALL/TCP/UDP/ICMP), and service
   - Stream pause/resume and buffer clear actions
2. **Prominent Telemetry-Only Banner**:
   > *"Telemetry Only — ML Classification Not Performed. This live stream displays native Zeek connection metadata in real time. In accordance with Stage 9A validation findings, no automated ML attack classification, risk score, or anomaly score is applied to native Zeek connection logs."*

---

## 6. Performance Benchmarks

Measured in the local project environment with SQLite/PostgreSQL async engine and in-memory queue:

| Metric | Target | Measured Result | Status |
|---|---|---|:---:|
| **Full Test Suite** | All tests pass | **125 / 125 passed (0 failures)** | **PASS** |
| **Stage 9B Unit & Integration Suite** | All 22 new tests pass | **22 / 22 passed in 7.31s** | **PASS** |
| **Frontend Production Build** | TypeScript + Vite | **0 errors, built in 21.00s** | **PASS** |
| **Batch Flush Latency** | $\le 500\text{ ms}$ | **$47.0\text{ ms} - 109.0\text{ ms}$** | **PASS** |
| **SSE Replay Latency** | $\le 50\text{ ms}$ | **$< 5.0\text{ ms}$ (instant)** | **PASS** |
| **Alembic Upgrade Head** | All 3 revisions apply | **0001 $\to$ 0002 $\to$ 0003 SUCCESS** | **PASS** |

---

## 7. Stage Boundaries & Non-Goals

- ❌ NO Zeek ML classification or feature inference
- ❌ NO modification to frozen Stage 3 models (`protocol_a_xgboost_k48`, `protocol_a_isolationforest_k48`)
- ❌ NO Kafka or Redis dependencies (in-process `asyncio.Queue` + `EventBroadcaster`)
- ❌ NO WebSocket protocol (unidirectional SSE with standard browser `EventSource`)
- ❌ NO modification to Stage 1–8 validated behavior
