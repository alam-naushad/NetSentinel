"""Pydantic schemas for single-flow, batch, and hybrid decision inference endpoints."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from app.schemas.decisions import DecisionPreviewResponse
from app.schemas.flows import ContextualSignals, FlowFeaturesInput


class FlowInferenceRequest(BaseModel):
    """Single network flow prediction request."""

    flow: FlowFeaturesInput
    supervised_model_key: str | None = Field(
        default=None,
        description="Optional catalog key for supervised classifier (defaults to protocol_a_xgboost_k48)",
    )
    anomaly_model_key: str | None = Field(
        default=None,
        description="Optional catalog key for statistical anomaly detector (defaults to protocol_a_isolationforest_k48)",
    )


class FlowPredictionResponse(BaseModel):
    """Single network flow prediction and statistical anomaly detection response."""

    # Supervised classification outputs
    predicted_family: str = Field(..., description="Canonical predicted attack family label")
    class_confidence: float = Field(..., ge=0, le=1, description="Confidence probability of predicted family")
    class_probabilities: dict[str, float] = Field(..., description="Full class probability distribution")

    # Statistical anomaly detection outputs (Isolation Forest)
    raw_decision_score: float = Field(..., description="Exact scikit-learn decision_function score (negative=anomalous, positive=normal)")
    is_statistical_anomaly: bool = Field(..., description="Whether flow is flagged by empirical alpha=0.01 calibrated threshold")
    calibrated_threshold: float | None = Field(default=None, description="Calibrated decision_function threshold used for anomaly determination")
    normalized_anomaly_score: float = Field(..., ge=0, le=1, description="Normalized [0, 1] anomaly score for UI display (1.0=high anomaly)")

    # Operational metrics
    inference_latency_ms: float = Field(..., description="End-to-end model execution latency in milliseconds")
    supervised_model_key: str = Field(..., description="Supervised model artifact identifier used")
    anomaly_model_key: str = Field(..., description="Statistical anomaly detector artifact identifier used")


class BatchFlowInferenceRequest(BaseModel):
    """Batch network flow inference request supporting up to 5,000 flows."""

    flows: list[FlowFeaturesInput] = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Array of network flow feature objects (maximum 5,000 flows per batch)",
    )
    supervised_model_key: str | None = Field(
        default=None,
        description="Optional catalog key for supervised classifier (defaults to protocol_a_xgboost_k48)",
    )
    anomaly_model_key: str | None = Field(
        default=None,
        description="Optional catalog key for statistical anomaly detector (defaults to protocol_a_isolationforest_k48)",
    )


class BatchFlowInferenceResponse(BaseModel):
    """Vectorized batch prediction and anomaly detection response."""

    total_flows: int
    total_latency_ms: float
    average_latency_ms: float
    summary: dict[str, int] = Field(..., description="Distribution count of predicted families and flagged anomalies")
    predictions: list[FlowPredictionResponse]


class EvaluateFlowRequest(BaseModel):
    """End-to-end flow evaluation request with contextual modifiers."""

    flow: FlowFeaturesInput
    context: ContextualSignals = Field(default_factory=ContextualSignals)
    supervised_model_key: str | None = Field(default=None)
    anomaly_model_key: str | None = Field(default=None)


class EvaluateFlowResponse(BaseModel):
    """Complete hybrid incident triage decision with underlying ML predictions and signals."""

    decision: DecisionPreviewResponse
    prediction: FlowPredictionResponse
    context_applied: ContextualSignals
