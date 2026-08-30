"""PCAP Analysis Orchestrator Service.

Connects the validated Stage 6A PCAP feature reconstruction pipeline to the
frozen Stage 4 ML inference services (supervised classification + statistical
anomaly detection + hybrid risk engine).

Architecture:
  PCAP bytes → FlowReconstructor → PcapFeatureAdapter → InferencePreprocessor
  → SupervisedPredictor (XGBoost K48) + StatisticalAnomalyScorer (IF K48)
  → risk_engine.decide() → structured PcapAnalysisResult

Design decisions:
  - Reuses Stage 6A parser/reconstructor/feature adapter without duplication.
  - Chunks flows into batches of ≤5,000 to respect Stage 4's batch contract.
  - Reassembles results in original flow order.
  - Provenance is strictly separated from model features throughout.
  - Stage 6A empirical compatibility: 617 authentic PCAP flows validated
    against XGBoost K48 with 99.84% prediction agreement. Isolation Forest
    is used as the production anomaly detector but was not part of the
    617-flow Stage 6A model-compatibility validation.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import BinaryIO

import numpy as np

from app.schemas.flows import FlowFeaturesInput
from app.services.anomaly_scorer import StatisticalAnomalyScorer
from app.services.model_registry import (
    ModelArtifactBundle,
    get_model_registry,
)
from app.services.pcap.feature_adapter import PcapFeatureAdapter, PcapFlowProvenance
from app.services.pcap.flow_reconstructor import FlowReconstructor
from app.services.predictor import SupervisedPredictor
from app.services.preprocessor import FeatureValidationError, InferencePreprocessor
from app.services.risk_engine import DecisionSignals, decide

logger = logging.getLogger(__name__)

# Stage 4 batch inference contract limit
STAGE4_BATCH_LIMIT = 5_000


@dataclass(frozen=True)
class AnalyzedFlow:
    """Single flow analysis result combining provenance + ML outputs + risk decision."""

    provenance: PcapFlowProvenance
    features: FlowFeaturesInput

    # Supervised classification
    predicted_family: str
    class_confidence: float
    class_probabilities: dict[str, float]

    # Anomaly detection
    raw_decision_score: float
    is_statistical_anomaly: bool
    normalized_anomaly_score: float

    # Hybrid risk decision
    risk_score: int
    severity: str
    status: str
    explanation: str


@dataclass
class PcapAnalysisResult:
    """Complete result of PCAP file analysis."""

    analyzed_flows: list[AnalyzedFlow] = field(default_factory=list)
    extracted_flow_count: int = 0
    analyzed_flow_count: int = 0
    skipped_flow_count: int = 0
    attack_distribution: dict[str, int] = field(default_factory=dict)
    severity_distribution: dict[str, int] = field(default_factory=dict)
    status_distribution: dict[str, int] = field(default_factory=dict)
    anomalies_flagged: int = 0
    processing_time_ms: float = 0.0
    supervised_model_key: str = ""
    anomaly_model_key: str = ""


class PcapAnalysisService:
    """Orchestrates PCAP file analysis through the validated Stage 6A + Stage 4 pipeline."""

    def __init__(
        self,
        flow_timeout_sec: float = 120.0,
        max_flows: int = 10_000,
    ):
        self._reconstructor = FlowReconstructor(
            flow_timeout_sec=flow_timeout_sec,
            max_flows=max_flows,
        )
        self._max_flows = max_flows

    def analyze(self, file_obj: BinaryIO) -> PcapAnalysisResult:
        """Run the complete PCAP → ML inference pipeline.

        Steps:
        1. Parse PCAP/PCAPNG and reconstruct bidirectional flows (Stage 6A)
        2. Extract canonical 48-feature vectors + provenance (Stage 6A)
        3. Batch-vectorize features through Stage 4 preprocessor (≤5,000 per chunk)
        4. Run supervised classification (XGBoost K48)
        5. Run statistical anomaly detection (Isolation Forest K48)
        6. Apply hybrid risk engine to each flow
        7. Assemble structured results
        """
        t0 = time.perf_counter()

        # Load production default models
        registry = get_model_registry()
        sup_bundle = registry.get_default_supervised_model()
        anom_bundle = registry.get_default_anomaly_model()

        # Step 1: Reconstruct flows from PCAP
        raw_flows = self._reconstructor.extract_flows(file_obj)
        extracted_count = len(raw_flows)
        logger.info("Extracted %d flows from PCAP", extracted_count)

        # Enforce flow limit
        if extracted_count > self._max_flows:
            logger.warning(
                "Extracted %d flows exceeds limit %d; truncating",
                extracted_count,
                self._max_flows,
            )
            raw_flows = raw_flows[: self._max_flows]

        # Step 2: Extract features + provenance for each flow
        features_list: list[FlowFeaturesInput] = []
        provenance_list: list[PcapFlowProvenance] = []
        skipped = 0

        for flow in raw_flows:
            try:
                features, provenance = PcapFeatureAdapter.adapt(flow)
                features_list.append(features)
                provenance_list.append(provenance)
            except Exception as e:
                logger.debug("Skipped flow due to feature extraction error: %s", e)
                skipped += 1

        if not features_list:
            return PcapAnalysisResult(
                extracted_flow_count=extracted_count,
                skipped_flow_count=skipped,
                processing_time_ms=round((time.perf_counter() - t0) * 1000, 2),
                supervised_model_key=sup_bundle.key,
                anomaly_model_key=anom_bundle.key,
            )

        # Step 3-5: Batch inference with ≤5,000 flow chunking
        analyzed_flows = self._run_batched_inference(
            features_list,
            provenance_list,
            sup_bundle,
            anom_bundle,
        )

        # Step 7: Compute summary statistics
        attack_counter: Counter[str] = Counter()
        severity_counter: Counter[str] = Counter()
        status_counter: Counter[str] = Counter()
        anomaly_count = 0

        for af in analyzed_flows:
            attack_counter[af.predicted_family] += 1
            severity_counter[af.severity] += 1
            status_counter[af.status] += 1
            if af.is_statistical_anomaly:
                anomaly_count += 1

        processing_ms = round((time.perf_counter() - t0) * 1000, 2)

        return PcapAnalysisResult(
            analyzed_flows=analyzed_flows,
            extracted_flow_count=extracted_count,
            analyzed_flow_count=len(analyzed_flows),
            skipped_flow_count=skipped,
            attack_distribution=dict(attack_counter),
            severity_distribution=dict(severity_counter),
            status_distribution=dict(status_counter),
            anomalies_flagged=anomaly_count,
            processing_time_ms=processing_ms,
            supervised_model_key=sup_bundle.key,
            anomaly_model_key=anom_bundle.key,
        )

    def _run_batched_inference(
        self,
        features_list: list[FlowFeaturesInput],
        provenance_list: list[PcapFlowProvenance],
        sup_bundle: ModelArtifactBundle,
        anom_bundle: ModelArtifactBundle,
    ) -> list[AnalyzedFlow]:
        """Run ML inference in chunks of ≤5,000 flows to respect Stage 4 batch contract."""
        total = len(features_list)
        all_results: list[AnalyzedFlow] = []

        for chunk_start in range(0, total, STAGE4_BATCH_LIMIT):
            chunk_end = min(chunk_start + STAGE4_BATCH_LIMIT, total)
            chunk_features = features_list[chunk_start:chunk_end]
            chunk_provenance = provenance_list[chunk_start:chunk_end]

            chunk_dicts = [f.model_dump() for f in chunk_features]

            try:
                # Preprocess for supervised classifier
                x_raw_sup, x_scaled_sup = InferencePreprocessor.preprocess_batch_flows(
                    chunk_dicts, sup_bundle
                )
                pred_classes, confidences, proba_matrix, _ = (
                    SupervisedPredictor.predict_batch(x_raw_sup, x_scaled_sup, sup_bundle)
                )

                # Preprocess for anomaly detector
                _, x_scaled_anom = InferencePreprocessor.preprocess_batch_flows(
                    chunk_dicts, anom_bundle
                )
                raw_scores, is_anom_flags, display_scores, _ = (
                    StatisticalAnomalyScorer.score_batch(x_scaled_anom, anom_bundle)
                )

            except FeatureValidationError as e:
                logger.error("Batch feature validation failed: %s", e)
                continue

            # Apply hybrid risk engine to each flow in the chunk
            for i in range(len(chunk_features)):
                p_class = pred_classes[i]
                p_conf = float(confidences[i])
                r_score = float(raw_scores[i])
                is_anom = bool(is_anom_flags[i])
                disp_score = float(display_scores[i])

                prob_dist = {
                    sup_bundle.class_names[j]: round(float(proba_matrix[i, j]), 6)
                    for j in range(len(sup_bundle.class_names))
                }

                # Hybrid risk decision (reuses existing engine — no duplication)
                signals = DecisionSignals(
                    anomaly_score=disp_score,
                    predicted_class=p_class,
                    class_confidence=p_conf,
                    raw_decision_score=r_score,
                    is_statistical_anomaly=is_anom,
                )
                decision = decide(signals)

                all_results.append(
                    AnalyzedFlow(
                        provenance=chunk_provenance[i],
                        features=chunk_features[i],
                        predicted_family=p_class,
                        class_confidence=round(p_conf, 6),
                        class_probabilities=prob_dist,
                        raw_decision_score=round(r_score, 6),
                        is_statistical_anomaly=is_anom,
                        normalized_anomaly_score=round(disp_score, 4),
                        risk_score=decision.risk_score,
                        severity=decision.severity.value,
                        status=decision.status.value,
                        explanation=decision.explanation,
                    )
                )

        return all_results
