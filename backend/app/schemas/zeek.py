"""Pydantic schemas for Zeek Native Telemetry API."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


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


# ---------------------------------------------------------------
# Phase 1 & 2A — Feature-Schema Completeness Scoring & Safe Routing
# ---------------------------------------------------------------


class RoutingDecision(str, Enum):
    """Deterministic routing decision for network flow evaluation."""

    ML_INFERENCE = "ML_INFERENCE"
    TELEMETRY_ONLY = "TELEMETRY_ONLY"


class TrustedSourceChannel(str, Enum):
    """Enumeration of recognized data source channels with explicit trust boundaries.

    Source compatibility is established exclusively by backend pipeline context,
    never by trusting client-submitted payload values.
    """

    PCAP_RECONSTRUCTED = "PCAP_RECONSTRUCTED"  # Verified by PcapParityValidator against CICFlowMeter
    REST_INFERENCE = "REST_INFERENCE"          # Direct authenticated API evaluation
    ZEEK_FLOWMETER = "ZEEK_FLOWMETER"          # Zeek packet-level flowmeter log (unverified semantic parity -> telemetry only)
    ZEEK_CONN = "ZEEK_CONN"                    # Native Zeek conn.log / live spool (connection-level only)
    UNTRUSTED_CLIENT = "UNTRUSTED_CLIENT"      # Arbitrary or client-tagged input (untrusted)


class FeatureCompletenessReport(BaseModel):
    """Detailed audit report of K=48 feature-schema completeness evaluation."""

    model_config = ConfigDict(extra="ignore")

    total_required_features: int = Field(default=48, description="Total canonical features required by frozen K=48 model schema")
    valid_features_count: int = Field(..., ge=0, le=48, description="Number of required features meeting presence, type, finiteness, and domain constraints")
    completeness_score: float = Field(..., ge=0.0, le=1.0, description="Completeness ratio = valid_features_count / 48")
    is_eligible_for_ml: bool = Field(..., description="Whether flow meets strict dual-gate requirements (source compatibility AND 100% completeness)")
    route: RoutingDecision = Field(..., description="Deterministic destination pipeline: ML_INFERENCE or TELEMETRY_ONLY")
    routing_reason: str = Field(..., description="Deterministic human-readable explanation of routing decision")
    missing_features: List[str] = Field(default_factory=list, description="Canonical feature names absent from the input payload")
    invalid_features: Dict[str, str] = Field(default_factory=dict, description="Feature names present but rejected (with rejection reason)")
    unexpected_features: List[str] = Field(default_factory=list, description="Extraneous features present in payload outside the canonical schema")


class FlowRoutingResponse(BaseModel):
    """Response capturing flow routing decision, completeness report, and safe ML or telemetry payload."""

    model_config = ConfigDict(extra="ignore")

    flow_id: Optional[str] = None
    source_channel: TrustedSourceChannel
    route: RoutingDecision
    is_eligible_for_ml: bool
    completeness: FeatureCompletenessReport
    ml_classification_performed: bool = False
    routing_reason: str
    telemetry_preserved: Dict[str, Any] = Field(default_factory=dict, description="Preserved network visibility and flow provenance metadata")
    feature_vector: Optional[Dict[str, float]] = Field(default=None, description="Canonical 48-feature snapshot, populated ONLY if route is ML_INFERENCE")
    is_sample_evaluation: bool = Field(default=False, description="Whether this evaluation represents a sample record from a multi-record file")
    sample_record_identifier: Optional[str] = Field(default=None, description="Identifier of the evaluated sample record (e.g. Zeek UID)")
    evaluation_scope: str = Field(default="FLOW_RECORD", description="Evaluation scope: 'SAMPLE_RECORD', 'FLOW_RECORD', or 'FILE_AGGREGATE'")


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
    completeness_report: Optional[FlowRoutingResponse] = Field(
        default=None,
        description="Feature completeness audit report evaluated on actual parsed telemetry records",
    )


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

