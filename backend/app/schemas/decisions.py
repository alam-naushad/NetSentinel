from pydantic import BaseModel, Field

from app.domain import DetectionStatus, Severity


class DecisionPreviewRequest(BaseModel):
    """Development-only input until the trained model artifact is available."""

    anomaly_score: float = Field(ge=0, le=1)
    predicted_class: str = Field(min_length=1, max_length=64)
    class_confidence: float = Field(ge=0, le=1)
    repeated_source_events: int = Field(default=0, ge=0, le=1000)
    targets_sensitive_service: bool = False


class DecisionPreviewResponse(BaseModel):
    status: DetectionStatus
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    explanation: str
    policy_version: str
