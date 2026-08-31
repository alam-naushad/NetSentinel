# Operations Runbook: Troubleshooting & Maintenance

This document provides operational runbooks for monitoring, diagnosing, and resolving incidents within the AI Network Anomaly Detection Platform.

---

## 1. System Health Monitoring

### Health & Readiness Endpoints
- **Liveness Heartbeat**:
  ```bash
  curl -s http://localhost:8000/health/live
  # Response: {"status": "ok", "service": "network-anomaly-api"}
  ```
- **Readiness Probe**:
  ```bash
  curl -s http://localhost:8000/health/ready
  # Response: {"status": "ready", "database": "connected", "models": "loaded", "environment": "production"}
  ```
- **Operational Metrics**:
  ```bash
  curl -s http://localhost:8000/api/v1/metrics
  ```

---

## 2. Common Incident Runbooks

### Incident A: Model Integrity Check Fails on Startup
- **Symptom**: Backend container exits on launch with error:
  `CRITICAL: Model integrity check FAILED for 'protocol_a_xgboost_k48'` or `Required production model artifact not found`.
- **Cause**: Frozen model artifacts in `artifacts/models/` are missing, corrupted, or not properly mounted.
- **Resolution**:
  1. Confirm `artifacts/models/` contains valid `.joblib` files on the host machine.
  2. Verify SHA-256 checksum of `protocol_a_xgboost_k48.joblib` matches `7d9b78ff493f4ab0588022aeaef35bb02fd328751f52eb02e79ae7c488f50b89`.
  3. Ensure Docker Compose volume mount `./artifacts/models:/app/artifacts/models:ro` is present.

### Incident B: Database Disconnection & Ingestion Pause
- **Symptom**: Ingestion worker logs `PostgreSQL persistence failed. Pausing ingestion worker.` Ingestion lag increases in `/api/v1/metrics`.
- **Behavior**: Spool tailer automatically pauses. Durable checkpoint does not advance, ensuring zero records are lost.
- **Resolution**:
  1. Check PostgreSQL container status: `docker compose -f docker-compose.prod.yml ps postgres`.
  2. Inspect database logs: `docker compose -f docker-compose.prod.yml logs --tail 50 postgres`.
  3. Once database connectivity recovers, the ingestion worker automatically flushes pending batches and resumes spool tailing.

### Incident C: High Ingestion Lag / Queue Depth
- **Symptom**: `/api/v1/metrics` reports `zeek_queue_depth > 1000` or `zeek_ingestion_lag_ms > 5000`.
- **Cause**: Zeek spool generation rate exceeds database batch persistence throughput.
- **Resolution**:
  1. Review `ZEEK_BATCH_SIZE` in `.env` (recommended: 50–100 records per micro-batch).
  2. Verify PostgreSQL disk I/O performance and connection pool parameters.

### Incident D: Zeek Spool Log Rotation
- **Symptom**: Zeek rotates `conn.log` to `conn.YYYY-MM-DD-HH-MM-SS.log` or truncates the file.
- **Behavior**: `SpoolTailer` detects inode change or file size shrink and automatically resets offset tracker for the new file descriptor while preserving persisted records in PostgreSQL.

---

## 3. Routine Maintenance & Log Inspection

### Structured Log Inspection
To view live structured JSON logs from the containerized backend:
```bash
docker compose -f docker-compose.prod.yml logs -f --tail 100 backend
```

### Inspecting Ingestion Checkpoints
```bash
docker compose -f docker-compose.prod.yml exec postgres \
    psql -U soc_user -d soc_telemetry -c \
    "SELECT spool_directory, file_name, byte_offset, lines_processed, updated_at FROM ingestion_checkpoints;"
```
