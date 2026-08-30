from fastapi import APIRouter

from app.schemas.decisions import DecisionPreviewRequest, DecisionPreviewResponse
from app.services.risk_engine import DecisionSignals, decide

router = APIRouter(prefix="/decisions", tags=["decisions"])


@router.post("/preview", response_model=DecisionPreviewResponse)
def preview_decision(payload: DecisionPreviewRequest) -> DecisionPreviewResponse:
    """Exercise the decision policy without presenting synthetic scores as ML output."""
    decision = decide(
        DecisionSignals(
            anomaly_score=payload.anomaly_score,
            predicted_class=payload.predicted_class,
            class_confidence=payload.class_confidence,
            repeated_source_events=payload.repeated_source_events,
            targets_sensitive_service=payload.targets_sensitive_service,
        )
    )
    return DecisionPreviewResponse(
        status=decision.status,
        severity=decision.severity,
        risk_score=decision.risk_score,
        explanation=decision.explanation,
        policy_version="foundation-v0",
    )
