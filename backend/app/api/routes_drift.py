"""Production Feature Drift Monitoring API Routes.

Provides endpoints to inspect training baseline feature distributions and evaluate
empirical drift across incoming batch flows or persisted telemetry windows.

Security & Operational Invariants:
- All evaluation endpoints are protected by session-based authentication (get_current_user).
- Rate limited via process-local sliding-window rate limiter.
- Operates strictly in read-only observation mode: does NOT trigger model inference,
  generate attack alerts, calculate risk scores, or alter existing model weights.
- Enforces canonical K=48 schema completeness and flags insufficient sample sizes (N < 100).
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import (
    AuthenticatedUser,
    check_rate_limit,
    get_current_user,
    inference_rate_limiter,
)
from app.db.repositories.event_repository import EventRepository
from app.schemas.drift import (
    BatchDriftEvaluationRequest,
    DatasetDriftSummary,
    DriftEvaluationResponse,
)
from app.services.drift_service import FeatureDriftService, get_drift_service
from app.services.preprocessor import FeatureValidationError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/drift", tags=["drift"])


@router.get("/baseline")
async def get_drift_baseline(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    drift_service: Annotated[FeatureDriftService, Depends(get_drift_service)],
) -> Dict[str, Any]:
    """Retrieve the static reference baseline metadata and distribution summaries."""
    return {
        "metadata": drift_service.baseline_metadata,
        "features": {
            k: {
                "feature_name": v["feature_name"],
                "canonical_index": v["canonical_index"],
                "mean": v["mean"],
                "std": v["std"],
                "min": v["min"],
                "max": v["max"],
                "zero_fraction": v["zero_fraction"],
                "bin_type": v["bin_type"],
                "n_bins": v["n_bins"],
            }
            for k, v in drift_service._baseline_data["features"].items()
        },
    }


@router.post("/evaluate-batch", response_model=DriftEvaluationResponse)
async def evaluate_batch_drift(
    request: Request,
    payload: BatchDriftEvaluationRequest,
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
    drift_service: Annotated[FeatureDriftService, Depends(get_drift_service)],
) -> DriftEvaluationResponse:
    """Evaluate empirical feature drift on an on-demand batch of canonical K=48 flows.

    Accepts up to 5,000 flows. Enforces schema validation and reports distribution shifts
    relative to the Protocol A training baseline.
    """
    # Rate limit check
    rate_limit_resp = await check_rate_limit(request, inference_rate_limiter)
    if rate_limit_resp is not None:
        return rate_limit_resp

    if not payload.flows:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Flow list cannot be empty for drift evaluation.",
        )

    flow_dicts = [f.model_dump() for f in payload.flows]

    try:
        return drift_service.evaluate_flows(flow_dicts)
    except FeatureValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "FeatureValidationError",
                "message": str(e),
                "missing_features": e.missing_features,
                "invalid_fields": e.invalid_fields,
            },
        ) from e
    except Exception as e:
        logger.exception("Unexpected error during batch drift evaluation: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Drift evaluation failed: {e}",
        ) from e


@router.get("/telemetry-window", response_model=DriftEvaluationResponse)
async def evaluate_telemetry_window_drift(
    request: Request,
    limit: int = Query(default=500, ge=10, le=5000, description="Number of recent flows to evaluate"),
    source_channel: str = Query(default="PCAP_BATCH", description="Source channel to evaluate (e.g. PCAP_BATCH)"),
    user: Annotated[AuthenticatedUser, Depends(get_current_user)] = None,
    db: Optional[AsyncSession] = Depends(get_db),
    drift_service: FeatureDriftService = Depends(get_drift_service),
) -> DriftEvaluationResponse:
    """Evaluate feature drift across the most recent window of persisted forensic flow vectors.

    Data Source Semantic Caveat:
    Persisted security_events records reflect user-uploaded PCAP files or test captures,
    not an unbiased continuous sample of live enterprise production traffic.
    """
    # Rate limit check
    rate_limit_resp = await check_rate_limit(request, inference_rate_limiter)
    if rate_limit_resp is not None:
        return rate_limit_resp

    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent database storage is currently unavailable (ephemeral mode active).",
        )

    repo = EventRepository(db)
    vectors = await repo.get_recent_feature_vectors(limit=limit, source_channel=source_channel)

    if not vectors:
        # Return an explicit insufficient-data response rather than failing with 500
        empty_summary = DatasetDriftSummary(
            evaluated_flow_count=0,
            evaluated_feature_count=len(drift_service.canonical_features),
            stable_feature_count=0,
            moderate_feature_count=0,
            significant_feature_count=0,
            overall_drift_status="INSUFFICIENT_DATA",
            mean_psi=0.0,
            max_psi=0.0,
            top_drifting_features=[],
            is_sample_size_sufficient=False,
            insufficient_sample_reason=(
                f"No historical feature vectors found in security_events for source_channel='{source_channel}'. "
                "Upload and analyze a PCAP capture to populate forensic flow telemetry."
            ),
            evaluation_time_ms=0.0,
            baseline_dataset=drift_service.baseline_metadata.get("source_dataset", "CICIDS2017"),
            baseline_sample_count=drift_service.baseline_metadata.get("training_sample_count", 0),
        )
        return DriftEvaluationResponse(summary=empty_summary, feature_metrics={})

    try:
        response = drift_service.evaluate_flows(vectors)
        # Append documentation caveat to insufficient_sample_reason if sample size is small
        if not response.summary.is_sample_size_sufficient:
            caveat = (
                f" Note: Persisted {source_channel} records represent analyst-uploaded capture files, "
                "not an unbiased continuous sample of production network traffic."
            )
            response.summary.insufficient_sample_reason = (response.summary.insufficient_sample_reason or "") + caveat
        return response
    except Exception as e:
        logger.exception("Error evaluating telemetry window drift: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Telemetry drift evaluation failed: {e}",
        ) from e
