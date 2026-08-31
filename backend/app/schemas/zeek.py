"""Pydantic schemas for Zeek Native Telemetry API."""

from __future__ import annotations

import uuid
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict


class ZeekConnectionSummary(BaseModel):
    """Summary of a single native Zeek connection record."""
    model_config = ConfigDict(extra="ignore")

    zeek_uid: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    service: Optional[str] = None
    duration_sec: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None
    history: Optional[str] = None
    orig_pkts: Optional[int] = None
    resp_pkts: Optional[int] = None
    missed_bytes: Optional[int] = None


class ZeekAnalysisSummary(BaseModel):
    """Aggregate statistics and operational metrics for an ingested Zeek log."""
    model_config = ConfigDict(extra="ignore")

    filename: str
    file_size_bytes: int
    total_connections_parsed: int
    total_connections_persisted: int
    connections_skipped_malformed: int
    connections_skipped_duplicate: int
    protocol_distribution: Dict[str, int]
    service_distribution: Dict[str, int]
    conn_state_distribution: Dict[str, int]
    processing_time_ms: float
    ml_classification_performed: bool = False
    analysis_type: str = "TELEMETRY_ONLY"


class ZeekAnalysisResponse(BaseModel):
    """Response returned by POST /api/v1/zeek/analyze."""
    model_config = ConfigDict(extra="ignore")

    summary: ZeekAnalysisSummary
    connections: List[ZeekConnectionSummary]
    job_id: Optional[uuid.UUID] = None
    persisted: bool = False
    persistence_error: Optional[str] = None


# ---------------------------------------------------------------
# Stage 9B — Real-Time Ingestion & SSE Schemas
# ---------------------------------------------------------------


class ZeekTrackedFile(BaseModel):
    """Status of a single file being tailed in the spool directory."""
    file_name: str
    byte_offset: int
    lines_processed: int
    last_updated: Optional[str] = None


class ZeekIngestionCounters(BaseModel):
    """Observable counters for the ingestion pipeline."""
    records_read: int = 0
    records_parsed: int = 0
    records_malformed: int = 0
    records_duplicate: int = 0
    records_persisted: int = 0
    batches_persisted: int = 0
    batches_failed: int = 0
    persist_errors: int = 0
    queue_depth: int = 0
    queue_high_watermark: int = 0
    sse_clients_connected: int = 0
    sse_events_published: int = 0
    sse_events_dropped: int = 0


class ZeekIngestionBatchInfo(BaseModel):
    """Metrics from the latest persisted micro-batch."""
    ingestion_lag_ms: float = 0.0
    flush_latency_ms: float = 0.0
    records_in_batch: int = 0


class ZeekIngestionStatus(BaseModel):
    """Full ingestion worker status response."""
    enabled: bool
    status: str  # "running", "stopped", "paused", "disabled"
    spool_directory: str
    uptime_seconds: float = 0.0
    counters: ZeekIngestionCounters
    latest_batch: ZeekIngestionBatchInfo
    tracked_files: List[ZeekTrackedFile] = []
    sse_session_id: Optional[str] = None


class ZeekSSEEvent(BaseModel):
    """Schema documenting the SSE event payload (for API docs only)."""
    sequence_id: int
    session_id: str
    ts: float
    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    service: Optional[str] = None
    duration_sec: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None
    orig_pkts: Optional[int] = None
    resp_pkts: Optional[int] = None
    history: Optional[str] = None
    event_timestamp: str = ""
    persisted: bool = True

