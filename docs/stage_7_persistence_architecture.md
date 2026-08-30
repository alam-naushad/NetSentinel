# Stage 7: Persistent Security Telemetry & Incident Management Architecture

## 1. System Overview

Stage 7 establishes a persistent security telemetry and incident-management layer backed by PostgreSQL and SQLAlchemy 2.0. It bridges real-time flow inference with durable relational storage for historical auditing, longitudinal trend analysis, and SOC alert lifecycle management.

```mermaid
flowchart TD
    A["Raw PCAP / Future Zeek Telemetry"] --> B["Stateful Flow & Feature Extraction"]
    B --> C["Frozen ML Inference (XGBoost + Isolation Forest)"]
    C --> D["Deterministic Hybrid Risk Engine"]
    D --> E["TelemetryPersistenceService"]
    E --> F[("PostgreSQL Database")]
    F --> G["FastAPI Historical / Alert Endpoints (/api/v1/telemetry, /api/v1/alerts)"]
    G --> H["React SOC Dashboard (Alerts & Telemetry Tabs)"]
```

---

## 2. Invariants & Scope Separation

### A. Frozen Stages Preserved
- **Stage 3 Models**: Completely frozen (`artifacts/models/*.joblib`). Zero retraining.
- **Stage 4 Inference**: Unaltered feature scaling, prediction, and anomaly scoring pipelines.
- **Stage 5 Dashboard**: In-memory session analytics preserved alongside persistent history.
- **Stage 6A/6B PCAP Inference**: 617-flow validation evidence and packet parsing logic unchanged.

### B. Downstream Persistence Contract
- Database persistence is strictly downstream of ML prediction and risk scoring.
- ML inference results and triage decisions are never altered by persistence failures.

### C. Explicit Failure Semantics
- When `DATABASE_REQUIRED=true`, database unavailability during application startup or request processing fails fast with an explicit error.
- When `DATABASE_REQUIRED=false`, the system operates in explicit ephemeral mode, returning ML inference results with `persisted: false` metadata.

---

## 3. Relational Schema & Entity Relationships

```mermaid
erDiagram
    ANALYSIS_JOBS ||--o{ SECURITY_EVENTS : "contains"
    SECURITY_EVENTS ||--|| FLOW_PROVENANCE : "originates_from"
    SECURITY_EVENTS ||--|| MODEL_DECISIONS : "evaluated_by"
    SECURITY_EVENTS ||--o| ALERTS : "escalates_to"
    ALERTS ||--o{ ALERT_HISTORY : "audits"
    
    ANALYSIS_JOBS {
        uuid id PK
        string source_type
        string filename
        int file_size_bytes
        string file_sha256
        int total_flows_extracted
        int total_flows_analyzed
        int anomalies_flagged
        float processing_time_ms
        string status
        timestamp created_at
    }

    SECURITY_EVENTS {
        uuid id PK
        uuid job_id FK
        timestamp event_timestamp
        string source_channel
        string predicted_family
        float class_confidence
        float normalized_anomaly_score
        boolean is_statistical_anomaly
        int risk_score
        string severity
        string triage_status
        jsonb class_probabilities
        jsonb feature_vector
        timestamp created_at
    }

    FLOW_PROVENANCE {
        uuid id PK
        uuid event_id FK
        string flow_id
        string src_ip
        string dst_ip
        int src_port
        int dst_port
        int ip_proto
        string protocol_name
        timestamp start_time
        timestamp end_time
        float duration_ms
        int total_packets
        bigint total_bytes
    }

    MODEL_DECISIONS {
        uuid id PK
        uuid event_id FK
        string supervised_model_key
        string anomaly_model_key
        float raw_decision_score
        float calibrated_threshold
        string policy_version
        text explanation
        timestamp evaluated_at
    }

    ALERTS {
        uuid id PK
        uuid event_id FK
        string alert_type
        string severity
        string disposition
        text analyst_notes
        string policy_version_applied
        timestamp created_at
        timestamp resolved_at
    }

    ALERT_HISTORY {
        uuid id PK
        uuid alert_id FK
        timestamp timestamp
        string previous_disposition
        string new_disposition
        string actor_id
        text action_note
    }
```

---

## 4. Key Architectural Features

### A. Immutable Detection Evidence
Detection evidence in `security_events`, `flow_provenance`, and `model_decisions` is strictly immutable once written. Analysts cannot modify original ML classifications, confidence scores, or feature snapshots.

### B. Configurable Alert Policy & Append-Only Audit Trail
- Security events only generate operational alerts when they meet the configurable alert policy (`ALERT_RISK_THRESHOLD`, `ALERT_CONFIDENCE_THRESHOLD`, `ALERT_ON_UNKNOWN_ANOMALY`).
- When an alert disposition changes (`OPEN` $\to$ `INVESTIGATING` $\to$ `RESOLVED` / `FALSE_POSITIVE`), the change is recorded in `alert_history` with the analyst ID, timestamp, and rationale.

### C. Primary Relational Indexing vs. Forensic JSONB Snapshots
- Primary queries, sorting, time-bounding, and subnet filtering operate on indexed relational columns (`event_timestamp`, `src_ip`, `dst_ip`, `predicted_family`, `risk_score`, `severity`, `triage_status`).
- The 48-feature vector is preserved in `feature_vector` as an immutable JSONB payload for detailed inspection without degrading index performance.

---

## 5. Docker & Migration Guide

### A. Starting Local PostgreSQL
```bash
# Start PostgreSQL 16 container via Docker Compose
docker compose up -d
```

### B. Executing Alembic Migrations
```bash
# Run schema upgrades to latest revision
alembic upgrade head
```

---

## 6. API Reference Summary

- `GET /api/v1/telemetry/events` — Query and filter historical security events with server-side pagination.
- `GET /api/v1/telemetry/events/{event_id}` — Retrieve full forensic event detail including 48-feature JSONB vector.
- `GET /api/v1/telemetry/jobs` — List historical PCAP/batch ingestion runs.
- `GET /api/v1/telemetry/jobs/{job_id}` — Inspect ingestion job summary and KPIs.
- `GET /api/v1/telemetry/stats/summary` — Aggregate security metrics over time windows (`1h`, `24h`, `7d`, `30d`, `all`).
- `GET /api/v1/alerts` — Query escalated incident alerts.
- `PATCH /api/v1/alerts/{alert_id}` — Update alert disposition with atomic audit trail appending.
- `GET /api/v1/health` — Reports API service and PostgreSQL persistence connectivity status.
