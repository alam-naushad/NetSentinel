"""Pydantic schemas for PCAP analysis API responses.

Design decisions:
- Bulk `PcapAnalysisResponse` omits per-flow 48-feature vectors to keep response size practical
  for large captures (10,000 flows × 48 features = significant JSON overhead).
- Full 48-feature inspection is available in `PcapFlowDetailResult` which the frontend
  requests per-flow via the detail modal.
- Provenance is strictly separated from model features in all response schemas.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.decisions import DecisionPreviewResponse


class PcapFlowProvenanceResponse(BaseModel):
    """Provenance metadata for a single reconstructed PCAP flow.
    Never included as model features — strictly network identity/session metadata.
    """
    flow_id: str = Field(..., description="Unique flow identifier")
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., description="Source port")
    dst_port: int = Field(..., description="Destination port")
    ip_proto: int = Field(..., description="IP protocol number (6=TCP, 17=UDP)")
    protocol_name: str = Field(..., description="Human-readable protocol name")
    start_time_iso: str = Field(..., description="Flow start time ISO 8601")
    end_time_iso: str = Field(..., description="Flow end time ISO 8601")
    duration_ms: float = Field(..., description="Flow duration in milliseconds")
    total_packets: int = Field(..., description="Total packets in flow")
    total_bytes: int = Field(..., description="Total payload bytes in flow")


class PcapFlowResult(BaseModel):
    """Per-flow analysis result in the bulk response (without full 48-feature vector)."""

    # Provenance
    provenance: PcapFlowProvenanceResponse

    # Supervised classification
    predicted_family: str = Field(..., description="Predicted attack family label")
    class_confidence: float = Field(..., ge=0, le=1, description="Top-class confidence")
    class_probabilities: dict[str, float] = Field(..., description="Full class probability distribution")

    # Anomaly detection
    raw_decision_score: float = Field(..., description="Isolation Forest raw decision_function score")
    is_statistical_anomaly: bool = Field(..., description="Flagged by calibrated alpha=0.01 threshold")
    normalized_anomaly_score: float = Field(..., ge=0, le=1, description="Display anomaly score [0,1]")

    # Hybrid risk decision
    risk_score: int = Field(..., ge=0, le=100, description="Composite risk score")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL")
    status: str = Field(..., description="Detection status: NORMAL, UNKNOWN_ANOMALY, KNOWN_ATTACK")
    explanation: str = Field(..., description="Human-readable triage explanation")


class PcapFlowDetailResult(PcapFlowResult):
    """Extended per-flow result including the full 48 reconstructed features for inspection."""
    features: dict[str, float] = Field(
        ..., description="Complete 48-feature vector reconstructed from PCAP"
    )


class PcapAnalysisSummary(BaseModel):
    """File-level summary KPIs for a PCAP analysis."""

    file_name: str = Field(..., description="Uploaded filename")
    file_size_bytes: int = Field(..., description="Uploaded file size in bytes")
    extracted_flows: int = Field(..., description="Total flows reconstructed from PCAP")
    analyzed_flows: int = Field(..., description="Flows successfully analyzed by ML models")
    skipped_flows: int = Field(
        default=0,
        description="Flows skipped due to feature validation failures",
    )
    attack_distribution: dict[str, int] = Field(
        ..., description="Count of each predicted attack family"
    )
    severity_distribution: dict[str, int] = Field(
        ..., description="Count of each severity level"
    )
    status_distribution: dict[str, int] = Field(
        ..., description="Count of each detection status"
    )
    anomalies_flagged: int = Field(
        default=0, description="Number of flows flagged as statistical anomalies"
    )
    processing_time_ms: float = Field(..., description="Total server-side processing time")
    supervised_model_key: str = Field(..., description="Supervised model used")
    anomaly_model_key: str = Field(..., description="Anomaly model used")


class PcapAnalysisResponse(BaseModel):
    """Top-level response for POST /api/v1/pcap/analyze."""

    summary: PcapAnalysisSummary
    flows: list[PcapFlowResult]
