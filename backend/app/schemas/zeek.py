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
