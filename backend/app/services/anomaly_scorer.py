"""Statistical Anomaly Scorer Service.

Evaluates unsupervised Isolation Forest models using the exact scikit-learn
decision_function convention:
- decision_function(X) returns lower / negative values for anomalous flows
- Higher / positive values indicate normal / inlier traffic
- Threshold calibration against empirical validation benign traffic determines
  statistical anomaly status (raw_score < calibrated_threshold).
- A separate [0, 1] display normalization is provided for UI visualization,
  preserving the raw decision score without altering threshold semantics.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import numpy as np
from app.services.model_registry import ModelArtifactBundle

logger = logging.getLogger(__name__)

# Default reference range for display normalization based on Stage 3 score distribution
# In scikit-learn IsolationForest, scores typically fall between -0.40 and +0.25
DISPLAY_SCORE_MIN_REF = -0.35
DISPLAY_SCORE_MAX_REF = 0.25


@dataclass(frozen=True)
class AnomalyScoreResult:
    """Statistical anomaly scoring result for a single network flow."""

    raw_decision_score: float
    is_anomaly_alpha_01: bool
    is_anomaly_alpha_05: bool
    calibrated_threshold_01: float | None
    calibrated_threshold_05: float | None
    normalized_display_score: float
    inference_latency_ms: float
    model_key: str
    feature_set: str


class StatisticalAnomalyScorer:
    """Scores network flows using trained statistical anomaly detector artifacts."""

    @staticmethod
    def compute_display_normalization(raw_scores: np.ndarray | float) -> np.ndarray | float:
        """Calculate a separate [0, 1] display score for visualization.

        Mapping convention:
        - raw_decision_score <= -0.35 -> normalized score close to 1.0 (extreme anomaly)
        - raw_decision_score >= +0.25 -> normalized score close to 0.0 (highly normal)
        - Monotonically decreasing so that higher display score = higher anomaly.
        """
        # Linear clamp with inverted direction for intuitive 0 (normal) to 1 (anomaly) display
        norm = 1.0 - (raw_scores - DISPLAY_SCORE_MIN_REF) / (DISPLAY_SCORE_MAX_REF - DISPLAY_SCORE_MIN_REF)
        if isinstance(norm, np.ndarray):
            return np.clip(norm, 0.0, 1.0)
        return float(max(0.0, min(1.0, norm)))

    @classmethod
    def score_single(
        cls,
        x_scaled: np.ndarray,
        bundle: ModelArtifactBundle,
    ) -> AnomalyScoreResult:
        """Score a single preprocessed flow feature vector (1, n_features)."""
        t0 = time.perf_counter()
        raw_score_arr = bundle.model.decision_function(x_scaled)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        raw_score = float(raw_score_arr[0])

        # Extract calibrated thresholds from model artifact metadata
        thresh_01 = bundle.thresholds.get(0.01) if bundle.thresholds else None
        thresh_05 = bundle.thresholds.get(0.05) if bundle.thresholds else None

        # Fallback thresholds if artifact did not store them
        if thresh_01 is None:
            thresh_01 = 0.051838  # Stage 3 Protocol A K=48 default
        if thresh_05 is None:
            thresh_05 = 0.120016  # Stage 3 Protocol A K=48 default

        # In scikit-learn convention: flow is anomalous if decision_function < threshold
        is_anom_01 = raw_score < thresh_01
        is_anom_05 = raw_score < thresh_05

        display_score = float(cls.compute_display_normalization(raw_score))

        return AnomalyScoreResult(
            raw_decision_score=round(raw_score, 6),
            is_anomaly_alpha_01=is_anom_01,
            is_anomaly_alpha_05=is_anom_05,
            calibrated_threshold_01=round(thresh_01, 6),
            calibrated_threshold_05=round(thresh_05, 6),
            normalized_display_score=round(display_score, 4),
            inference_latency_ms=round(latency_ms, 4),
            model_key=bundle.key,
            feature_set=bundle.feature_set,
        )

    @classmethod
    def score_batch(
        cls,
        x_scaled: np.ndarray,
        bundle: ModelArtifactBundle,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, float]:
        """Score a batch of preprocessed flow feature vectors (N, n_features).

        Returns:
            (raw_scores, is_anomaly_01_flags, normalized_display_scores, total_latency_ms)
        """
        t0 = time.perf_counter()
        raw_scores = bundle.model.decision_function(x_scaled)
        total_latency_ms = (time.perf_counter() - t0) * 1000.0

        thresh_01 = bundle.thresholds.get(0.01, 0.051838) if bundle.thresholds else 0.051838
        is_anom_01 = raw_scores < thresh_01
        display_scores = cls.compute_display_normalization(raw_scores)

        return raw_scores, is_anom_01, display_scores, total_latency_ms
