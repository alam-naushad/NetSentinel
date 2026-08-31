# Security Model: Hardened Capstone Deployment

This document outlines the defensive security architecture, threat model, input validation mechanisms, and operational safeguards implemented across the platform.

---

## 1. Threat Model & Attack Surface

```
[ External Untrusted Sources ]
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│ Edge / Nginx Reverse Proxy (Port 80)                       │
│  - Client Max Body Size (50 MB)                             │
│  - Security Headers (CSP, Frame Options, MIME type)        │
└──────────────────────────┬──────────────────────────────────┘
                           │ Internal HTTP Proxy
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ FastAPI Application Gateway (Port 8000)                     │
│  - SecurityHeadersMiddleware (Conditional HSTS)             │
│  - Configurable CORS Origin Restriction                     │
│  - Process-Local Sliding-Window Rate Limiting              │
│  - Model Artifact SHA-256 Checksum Validation               │
│  - Exception Shielding (Sanitized HTTP 500 Responses)       │
└──────────────────────────┬──────────────────────────────────┘
                           │ Async Database Pool
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ PostgreSQL 16 Database (Port 5432)                          │
│  - Non-Superuser Role (soc_user)                            │
│  - Parameterized ORM Queries (SQL Injection Immunity)       │
│  - Connection Pool Timeout and Pre-Ping Protection         │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Defensive HTTP Security Headers

All HTTP responses emitted by the FastAPI backend and Nginx reverse proxy include defensive security headers:

| Header | Value | Purpose |
| :--- | :--- | :--- |
| `X-Content-Type-Options` | `nosniff` | Prevents browser MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking and framing attacks |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Protects URI query parameters from leaking to external domains |
| `Content-Security-Policy` | `default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self';` | Restricts script and asset execution to trusted local bundles |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | **Conditioned on `ENABLE_HTTPS=true`**. Omitted in local HTTP development. |

*Note: Legacy `X-XSS-Protection` is omitted in favor of modern, robust Content Security Policy directives.*

---

## 3. Rate Limiting Strategy & Boundaries

### In-Memory Sliding-Window Implementation
The platform includes an in-memory, sliding-window rate limiter on resource-intensive endpoints:
- `/api/v1/inference/*` (Single & Batch Inference): Default 60 requests/minute per client IP.
- `/api/v1/pcap/analyze` & `/api/v1/zeek/analyze` (File Uploads): Default 20 requests/minute per client IP.
- `/api/v1/zeek/stream` (SSE Live Stream): Hard client cap of 32 concurrent active listeners per process.

### Operational Boundaries:
- **Process-Local Scope**: Rate limit buckets are maintained in RAM per process instance.
- **Restart Semantics**: Rate limit counters reset upon application restart.
- **Multi-Node Limitation**: Distributed multi-node token synchronization (e.g. Redis) is out of scope for this single-node capstone system.

---

## 4. Resource Protection & Upload Safeguards

1. **PCAP Upload Limits**: Default preserved at **50 MB** (`PCAP_MAX_UPLOAD_SIZE_MB=50`). Maximum flows analyzed per capture capped at 10,000 flows (`PCAP_MAX_FLOWS=10000`). Files exceeding limits are rejected immediately with HTTP 413.
2. **Streaming Packet Extraction**: PCAP parsing uses `dpkt` chunked stream iteration rather than reading full captures into application memory.
3. **Zeek Ingestion Backpressure**: Ingestion worker queue is bounded to 4,096 items. When full, spool tailer pauses reading, allowing disk buffers to absorb traffic without memory exhaustion.

---

## 5. Model Integrity & Tamper Protection

1. **Read-Only Mount**: Model artifacts directory is mounted read-only (`:ro`) in Docker Compose.
2. **SHA-256 Checksum Validation**: On startup, the backend validates model files against hard-coded known hashes. Any missing or modified model file raises an immediate fatal exception preventing compromised inference.
3. **No Dynamic Execution**: Client-supplied model paths are strictly prohibited; inference is invoked only via canonical catalog identifiers.

---

## 6. Information Disclosure Prevention

1. **Minimal Liveness Probe** (`/health/live`): Emits only `{"status": "ok", "service": "network-anomaly-api"}` without disclosing internal versions, environment variables, or database endpoints.
2. **Guarded Readiness Probe** (`/health/ready`): Diagnostic check exposing only binary status indicators (`connected`/`disconnected`, `loaded`/`unavailable`).
3. **Sanitized Error Responses**: Internal exception tracebacks are shielded from client HTTP 500 responses while detailed forensic logs are captured internally.
