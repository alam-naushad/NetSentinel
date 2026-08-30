"""Production ML inference and hybrid evaluation API endpoints."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from fastapi import APIRouter, HTTPException, status
from app.schemas.decisions import DecisionPreviewResponse
from app.schemas.inference import (
    BatchFlowInferenceRequest,
    BatchFlowInferenceResponse,
    EvaluateFlowRequest,
    EvaluateFlowResponse,
    FlowInferenceRequest,
    FlowPredictionResponse,
)
from app.services.anomaly_scorer import StatisticalAnomalyScorer
from app.services.model_registry import (
    DEFAULT_ANOMALY_MODEL_KEY,
    DEFAULT_SUPERVISED_MODEL_KEY,
    get_model_registry,
)
from app.services.predictor import SupervisedPredictor
from app.services.preprocessor import FeatureValidationError, InferencePreprocessor
from app.services.risk_engine import DecisionSignals, decide

router = APIRouter(tags=["inference"])


def _resolve_bundles(
    supervised_key: str | None,
    anomaly_key: str | None,
) -> tuple[Any, Any]:
    """Helper to resolve and validate requested model bundles from registry."""
    registry = get_model_registry()
    sup_key = (supervised_key or DEFAULT_SUPERVISED_MODEL_KEY).strip().lower()
    anom_key = (anomaly_key or DEFAULT_ANOMALY_MODEL_KEY).strip().lower()

    try:
        sup_bundle = registry.get_model(sup_key)
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Invalid supervised model key '{sup_key}': {e}",
        ) from e

    try:
        anom_bundle = registry.get_model(anom_key)
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Invalid anomaly model key '{anom_key}': {e}",
        ) from e

    return sup_bundle, anom_bundle


@router.post("/predict/flow", response_model=FlowPredictionResponse)
def predict_single_flow(payload: FlowInferenceRequest) -> FlowPredictionResponse:
    """Execute supervised classification and statistical anomaly detection on a single flow."""
    sup_bundle, anom_bundle = _resolve_bundles(
        payload.supervised_model_key,
        payload.anomaly_model_key,
    )
    flow_dict = payload.flow.to_dict()

    try:
        # Preprocess for supervised classifier
        x_raw_sup, x_scaled_sup = InferencePreprocessor.preprocess_single_flow(
            flow_dict, sup_bundle
        )
        sup_res = SupervisedPredictor.predict_single(x_raw_sup, x_scaled_sup, sup_bundle)

        # Preprocess for statistical anomaly detector
        _, x_scaled_anom = InferencePreprocessor.preprocess_single_flow(
            flow_dict, anom_bundle
        )
        anom_res = StatisticalAnomalyScorer.score_single(x_scaled_anom, anom_bundle)

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

    total_latency_ms = sup_res.inference_latency_ms + anom_res.inference_latency_ms

    return FlowPredictionResponse(
        predicted_family=sup_res.predicted_family,
        class_confidence=sup_res.class_confidence,
        class_probabilities=sup_res.class_probabilities,
        raw_decision_score=anom_res.raw_decision_score,
        is_statistical_anomaly=anom_res.is_anomaly_alpha_01,
        calibrated_threshold=anom_res.calibrated_threshold_01,
        normalized_anomaly_score=anom_res.normalized_display_score,
        inference_latency_ms=round(total_latency_ms, 4),
        supervised_model_key=sup_bundle.key,
        anomaly_model_key=anom_bundle.key,
    )


@router.post("/predict/batch", response_model=BatchFlowInferenceResponse)
def predict_batch_flows(payload: BatchFlowInferenceRequest) -> BatchFlowInferenceResponse:
    """Execute high-throughput vectorized batch prediction and anomaly detection (up to 5,000 flows)."""
    sup_bundle, anom_bundle = _resolve_bundles(
        payload.supervised_model_key,
        payload.anomaly_model_key,
    )
    flows_list = [f.to_dict() for f in payload.flows]

    t_batch_start = time.perf_counter()
    try:
        # Preprocess for supervised classifier
        x_raw_sup, x_scaled_sup = InferencePreprocessor.preprocess_batch_flows(
            flows_list, sup_bundle
        )
        pred_classes, confidences, proba_matrix, sup_lat_ms = (
            SupervisedPredictor.predict_batch(x_raw_sup, x_scaled_sup, sup_bundle)
        )

        # Preprocess for statistical anomaly detector
        _, x_scaled_anom = InferencePreprocessor.preprocess_batch_flows(
            flows_list, anom_bundle
        )
        raw_scores, is_anom_01, norm_anom_scores, anom_lat_ms = (
            StatisticalAnomalyScorer.score_batch(x_scaled_anom, anom_bundle)
        )

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

    total_batch_latency_ms = (time.perf_counter() - t_batch_start) * 1000.0
    n_flows = len(flows_list)
    avg_latency_ms = total_batch_latency_ms / max(n_flows, 1)

    # Extract calibrated threshold
    cal_thresh = (
        anom_bundle.thresholds.get(0.01) if anom_bundle.thresholds else 0.051838
    )

    predictions: list[FlowPredictionResponse] = []
    class_counter: Counter[str] = Counter()
    anom_count = 0

    for i in range(n_flows):
        p_class = pred_classes[i]
        p_conf = float(confidences[i])
        r_score = float(raw_scores[i])
        is_anom = bool(is_anom_01[i])
        norm_score = float(norm_anom_scores[i])

        class_counter[p_class] += 1
        if is_anom:
            anom_count += 1

        prob_dist = {
            sup_bundle.class_names[j]: round(float(proba_matrix[i, j]), 6)
            for j in range(len(sup_bundle.class_names))
        }

        predictions.append(
            FlowPredictionResponse(
                predicted_family=p_class,
                class_confidence=round(p_conf, 6),
                class_probabilities=prob_dist,
                raw_decision_score=round(r_score, 6),
                is_statistical_anomaly=is_anom,
                calibrated_threshold=round(cal_thresh, 6),
                normalized_anomaly_score=round(norm_score, 4),
                inference_latency_ms=round(avg_latency_ms, 4),
                supervised_model_key=sup_bundle.key,
                anomaly_model_key=anom_bundle.key,
            )
        )

    summary_dict = dict(class_counter)
    summary_dict["STATISTICAL_ANOMALIES_FLAGGED"] = anom_count

    return BatchFlowInferenceResponse(
        total_flows=n_flows,
        total_latency_ms=round(total_batch_latency_ms, 2),
        average_latency_ms=round(avg_latency_ms, 4),
        summary=summary_dict,
        predictions=predictions,
    )


@router.post("/decisions/evaluate", response_model=EvaluateFlowResponse)
def evaluate_flow_decision(payload: EvaluateFlowRequest) -> EvaluateFlowResponse:
    """Evaluate network flow with ML models and apply hybrid risk policy to produce triage decision."""
    # Obtain ML predictions
    inference_req = FlowInferenceRequest(
        flow=payload.flow,
        supervised_model_key=payload.supervised_model_key,
        anomaly_model_key=payload.anomaly_model_key,
    )
    pred_res = predict_single_flow(inference_req)

    # Feed real ML outputs into hybrid decision engine
    signals = DecisionSignals(
        anomaly_score=pred_res.normalized_anomaly_score,
        predicted_class=pred_res.predicted_family,
        class_confidence=pred_res.class_confidence,
        raw_decision_score=pred_res.raw_decision_score,
        is_statistical_anomaly=pred_res.is_statistical_anomaly,
        repeated_source_events=payload.context.repeated_source_events,
        targets_sensitive_service=payload.context.targets_sensitive_service,
    )

    decision = decide(signals)

    decision_res = DecisionPreviewResponse(
        status=decision.status,
        severity=decision.severity,
        risk_score=decision.risk_score,
        explanation=decision.explanation,
        policy_version=decision.policy_version,
    )

    return EvaluateFlowResponse(
        decision=decision_res,
        prediction=pred_res,
        context_applied=payload.context,
    )
