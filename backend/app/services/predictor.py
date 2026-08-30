"""Supervised Classification Predictor Service.

Executes trained supervised model artifacts (XGBoost, Random Forest, Logistic Regression)
to extract predicted attack family, per-class probability distribution, and classification confidence.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import numpy as np
from app.services.model_registry import ModelArtifactBundle

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SupervisedPredictionResult:
    """Supervised prediction result for a single network flow."""

    predicted_family: str
    class_confidence: float
    class_probabilities: dict[str, float]
    inference_latency_ms: float
    model_key: str
    feature_set: str


class SupervisedPredictor:
    """Vectorized predictor for trained supervised classifiers."""

    @classmethod
    def predict_single(
        cls,
        x_raw: np.ndarray,
        x_scaled: np.ndarray,
        bundle: ModelArtifactBundle,
    ) -> SupervisedPredictionResult:
        """Predict class and probability distribution for a single flow (1, n_features)."""
        # Select scaled or raw input based on model's preprocessing requirement
        x_input = x_scaled if bundle.scaler is not None else x_raw

        t0 = time.perf_counter()
        proba_matrix = bundle.model.predict_proba(x_input)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        proba_row = proba_matrix[0]
        pred_idx = int(np.argmax(proba_row))
        confidence = float(proba_row[pred_idx])

        # Resolve class name from bundle's class vocabulary
        if bundle.class_names and pred_idx < len(bundle.class_names):
            pred_class = bundle.class_names[pred_idx]
        elif bundle.label_encoder is not None:
            pred_class = str(bundle.label_encoder.classes_[pred_idx])
        else:
            pred_class = str(pred_idx)

        # Build class probability distribution
        prob_dist = {
            bundle.class_names[i]: round(float(proba_row[i]), 6)
            for i in range(len(bundle.class_names))
        }

        return SupervisedPredictionResult(
            predicted_family=pred_class,
            class_confidence=round(confidence, 6),
            class_probabilities=prob_dist,
            inference_latency_ms=round(latency_ms, 4),
            model_key=bundle.key,
            feature_set=bundle.feature_set,
        )

    @classmethod
    def predict_batch(
        cls,
        x_raw: np.ndarray,
        x_scaled: np.ndarray,
        bundle: ModelArtifactBundle,
    ) -> tuple[list[str], np.ndarray, np.ndarray, float]:
        """Predict class and probability distribution for a batch of flows (N, n_features).

        Returns:
            (predicted_classes, confidence_scores, proba_matrix, total_latency_ms)
        """
        x_input = x_scaled if bundle.scaler is not None else x_raw

        t0 = time.perf_counter()
        proba_matrix = bundle.model.predict_proba(x_input)
        total_latency_ms = (time.perf_counter() - t0) * 1000.0

        pred_indices = np.argmax(proba_matrix, axis=1)
        confidences = np.max(proba_matrix, axis=1)

        predicted_classes = [
            bundle.class_names[idx] if idx < len(bundle.class_names) else str(idx)
            for idx in pred_indices
        ]

        return predicted_classes, confidences, proba_matrix, total_latency_ms
