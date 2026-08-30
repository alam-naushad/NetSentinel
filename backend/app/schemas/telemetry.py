"""Pydantic schemas for historical security events and telemetry aggregations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Generic, List, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field

from app.schemas.decisions import DecisionPreviewResponse
from app.schemas.flows import FlowFeaturesInput
from app.schemas.pcap import PcapFlowProvenanceResponse

T = TypeVar("T")


class PageResponse(BaseModel, Generic[T]):
    """Standardized server-side paginated envelope."""
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class SecurityEventSummary(BaseModel):
    """Compact summary of a historical security event for table listings."""
    id: uuid.UUID
    event_timestamp: datetime
    source_channel: str
    ml_classification_performed: bool = True
    predicted_family: Optional[str] = None
    class_confidence: Optional[float] = None
    normalized_anomaly_score: Optional[float] = None
    is_statistical_anomaly: bool
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    triage_status: Optional[str] = None
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol_name: str
    job_id: Optional[uuid.UUID] = None
    has_alert: bool = False


class SecurityEventDetail(BaseModel):
    """Complete forensic inspection of a security event including the full 48-feature vector."""
    id: uuid.UUID
    event_timestamp: datetime
    source_channel: str
    ml_classification_performed: bool = True
    predicted_family: Optional[str] = None
    class_confidence: Optional[float] = None
    class_probabilities: Optional[dict[str, float]] = None
    normalized_anomaly_score: Optional[float] = None
    raw_decision_score: Optional[float] = None
    is_statistical_anomaly: bool
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    triage_status: Optional[str] = None
    explanation: Optional[str] = None
    supervised_model_key: Optional[str] = None
    anomaly_model_key: Optional[str] = None
    provenance: PcapFlowProvenanceResponse
    feature_vector: Optional[dict[str, float]] = None
    alert_id: Optional[uuid.UUID] = None
    job_id: Optional[uuid.UUID] = None


class AnalysisJobSummary(BaseModel):
    """Summary of a historical PCAP or batch ingestion job."""
    id: uuid.UUID
    source_type: str
    filename: str
    file_size_bytes: int
    file_sha256: Optional[str] = None
    total_flows_extracted: int
    total_flows_analyzed: int
    anomalies_flagged: int
    processing_time_ms: float
    status: str
    created_at: datetime


class TelemetrySummaryStats(BaseModel):
    """Aggregated threat metrics over a time window."""
    total_events: int
    total_attacks: int
    total_benign: int
    total_anomalies: int
    attack_distribution: dict[str, int]
    severity_distribution: dict[str, int]
    status_distribution: dict[str, int]
    time_window: str


class TimeSeriesBucket(BaseModel):
    """Bucketized event count and attack distribution for historical charts."""
    timestamp: datetime
    total_count: int
    attack_count: int
    anomaly_count: int
