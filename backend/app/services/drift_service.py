"""Feature Drift Calculation Service.

Computes statistically sound, interpretable feature drift metrics
(Population Stability Index and Standardized Mean Difference) comparing
incoming network flow feature distributions against the verified Protocol A
training baseline.

Core Design Invariants:
1. Reuses the canonical K=48 feature schema strictly in frozen order.
2. Never classifies drift as an attack or creates automatic alert decisions.
3. Never automatically retrains models on drifted data.
4. Uses adaptive zero-inflated binning with epsilon smoothing to guarantee
   finite, mathematically stable PSI values (zero NaN/Inf).
5. Enforces a minimum sample size constraint (N >= 100) to ensure statistical validity.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from app.schemas.drift import (
    DatasetDriftSummary,
    DriftDataQuality,
    DriftEvaluationResponse,
    FeatureDriftResult,
)
from app.services.preprocessor import FeatureValidationError

logger = logging.getLogger(__name__)

# Base path resolution: 3 levels up from backend/app/services -> project root
PROJECT_ROOT = Path(__file__).resolve().parents[3]
BASELINE_FILE = PROJECT_ROOT / "data" / "metadata" / "baseline_feature_distributions.json"
SELECTED_FEATURES_FILE = PROJECT_ROOT / "data" / "metadata" / "selected_features.json"

MINIMUM_RECOMMENDED_SAMPLE_SIZE = 100
EPSILON_SMOOTHING = 1e-4

# Operational threshold heuristics for PSI
PSI_STABLE_THRESHOLD = 0.10
PSI_SIGNIFICANT_THRESHOLD = 0.25


class FeatureDriftService:
    """Service for computing and summarizing feature distribution drift."""

    def __init__(self, baseline_path: Optional[Path] = None):
        self.baseline_path = baseline_path or BASELINE_FILE
        self._baseline_data: Optional[Dict[str, Any]] = None
        self._canonical_features: Optional[List[str]] = None
        self._load_baseline()

    def _load_baseline(self) -> None:
        """Load and validate the precomputed training baseline distributions artifact."""
        if not self.baseline_path.exists():
            raise FileNotFoundError(
                f"Feature drift baseline artifact not found at: {self.baseline_path}. "
                "Execute scripts/generate_drift_baseline.py to generate it."
            )

        def _strict_parse_constant(c: str) -> None:
            raise ValueError(f"Strict RFC 8259 JSON violation: non-standard constant in baseline: '{c}'")

        with open(self.baseline_path, "r", encoding="utf-8") as f:
            self._baseline_data = json.load(f, parse_constant=_strict_parse_constant)

        # Load canonical feature ordering
        if SELECTED_FEATURES_FILE.exists():
            with open(SELECTED_FEATURES_FILE, "r", encoding="utf-8") as f:
                self._canonical_features = json.load(f)["selected_features"]
        else:
            self._canonical_features = list(self._baseline_data["features"].keys())

        # Validate feature completeness
        baseline_features = self._baseline_data["features"]
        missing = [fn for fn in self._canonical_features if fn not in baseline_features]
        if missing:
            raise ValueError(f"Baseline artifact is missing canonical features: {missing}")

        logger.info(
            "FeatureDriftService initialized with %d features from baseline: %s (training rows: %d)",
            len(self._canonical_features),
            self._baseline_data.get("split_protocol", "unknown"),
            self._baseline_data.get("training_sample_count", 0),
        )

    @property
    def canonical_features(self) -> List[str]:
        return list(self._canonical_features)

    @property
    def baseline_metadata(self) -> Dict[str, Any]:
        return {
            "source_dataset": self._baseline_data.get("source_dataset", "Unknown"),
            "split_protocol": self._baseline_data.get("split_protocol", "Unknown"),
            "training_sample_count": self._baseline_data.get("training_sample_count", 0),
            "k_features": self._baseline_data.get("k_features", len(self._canonical_features)),
        }

    def evaluate_flows(self, flows: List[Dict[str, Any]]) -> DriftEvaluationResponse:
        """Validate input flows and evaluate feature distribution drift."""
        t_start = time.perf_counter()
        n_flows = len(flows)

        # Validate feature completeness and non-finites
        matrix = self._validate_and_extract_matrix(flows)

        return self.evaluate_matrix(matrix, t_start=t_start)

    def evaluate_matrix(
        self,
        matrix: np.ndarray,
        t_start: Optional[float] = None,
    ) -> DriftEvaluationResponse:
        """Evaluate feature distribution drift on a pre-validated (N, 48) numeric matrix."""
        if t_start is None:
            t_start = time.perf_counter()

        n_flows, n_features = matrix.shape
        if n_features != len(self._canonical_features):
            raise ValueError(
                f"Feature matrix dimension mismatch: expected {len(self._canonical_features)} "
                f"columns, got {n_features}."
            )

        is_sufficient = n_flows >= MINIMUM_RECOMMENDED_SAMPLE_SIZE
        insufficient_reason = None
        if not is_sufficient:
            insufficient_reason = (
                f"Sample size ({n_flows} flows) is below the recommended minimum threshold "
                f"({MINIMUM_RECOMMENDED_SAMPLE_SIZE} flows). Distribution metrics may have high variance."
            )

        feature_metrics: Dict[str, FeatureDriftResult] = {}
        stable_count = 0
        moderate_count = 0
        significant_count = 0
        psi_values = []

        baseline_features = self._baseline_data["features"]

        for idx, feat_name in enumerate(self._canonical_features):
            b_meta = baseline_features[feat_name]
            col_vals = matrix[:, idx]

            # Compute empirical observed moments
            finite_mask = np.isfinite(col_vals)
            finite_count = int(np.sum(finite_mask))
            zero_count = int(np.sum(np.isclose(col_vals, 0.0, atol=1e-6)))
            zero_fraction = float(zero_count / max(n_flows, 1))

            obs_mean = float(np.mean(col_vals)) if finite_count > 0 else 0.0
            obs_var = float(np.var(col_vals)) if finite_count > 0 else 0.0
            obs_std = float(np.sqrt(obs_var))

            # Compute Population Stability Index (PSI)
            inner_cutoffs = b_meta["inner_cutoffs"]
            ref_props = b_meta["reference_proportions"]
            psi = self._calculate_psi(col_vals, inner_cutoffs, ref_props)
            psi_values.append(psi)

            # Compute Standardized Mean Difference (SMD / Cohen's d)
            base_mean = float(b_meta["mean"])
            base_std = float(b_meta["std"])
            is_constant_baseline = base_std < 1e-9
            is_constant_observed = obs_std < 1e-9

            if is_constant_baseline:
                smd = None
            else:
                smd = float((obs_mean - base_mean) / base_std)

            # Categorize severity
            if psi < PSI_STABLE_THRESHOLD:
                severity = "STABLE"
                stable_count += 1
            elif psi < PSI_SIGNIFICANT_THRESHOLD:
                severity = "MODERATE"
                moderate_count += 1
            else:
                severity = "SIGNIFICANT"
                significant_count += 1

            feature_metrics[feat_name] = FeatureDriftResult(
                feature_name=feat_name,
                canonical_index=idx,
                sample_count=n_flows,
                baseline_mean=round(base_mean, 6),
                observed_mean=round(obs_mean, 6),
                baseline_std=round(base_std, 6),
                observed_std=round(obs_std, 6),
                psi=round(psi, 6),
                smd=round(smd, 6) if smd is not None else None,
                drift_severity=severity,
                data_quality=DriftDataQuality(
                    finite_count=finite_count,
                    zero_count=zero_count,
                    zero_fraction=round(zero_fraction, 6),
                    is_constant_baseline=is_constant_baseline,
                    is_constant_observed=is_constant_observed,
                    bin_type=b_meta.get("bin_type", "continuous"),
                ),
            )

        # Determine overall dataset status
        if not is_sufficient:
            overall_status = "INSUFFICIENT_DATA"
        elif significant_count > 0:
            overall_status = "SIGNIFICANT_DRIFT"
        elif moderate_count > 0:
            overall_status = "MODERATE_DRIFT"
        else:
            overall_status = "STABLE"

        # Sort top drifting features by PSI descending
        sorted_by_psi = sorted(
            feature_metrics.keys(),
            key=lambda k: feature_metrics[k].psi,
            reverse=True,
        )

        eval_time_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

        summary = DatasetDriftSummary(
            evaluated_flow_count=n_flows,
            evaluated_feature_count=len(self._canonical_features),
            stable_feature_count=stable_count,
            moderate_feature_count=moderate_count,
            significant_feature_count=significant_count,
            overall_drift_status=overall_status,
            mean_psi=round(float(np.mean(psi_values)), 6) if psi_values else 0.0,
            max_psi=round(float(np.max(psi_values)), 6) if psi_values else 0.0,
            top_drifting_features=sorted_by_psi[:10],
            is_sample_size_sufficient=is_sufficient,
            insufficient_sample_reason=insufficient_reason,
            evaluation_time_ms=eval_time_ms,
            baseline_dataset=self._baseline_data.get("source_dataset", "CICIDS2017"),
            baseline_sample_count=self._baseline_data.get("training_sample_count", 0),
        )

        return DriftEvaluationResponse(
            summary=summary,
            feature_metrics=feature_metrics,
        )

    def _calculate_psi(
        self,
        actual: np.ndarray,
        inner_cutoffs: List[float],
        ref_props: List[float],
        epsilon: float = EPSILON_SMOOTHING,
    ) -> float:
        """Calculate Population Stability Index with adaptive cutoffs and epsilon smoothing."""
        val_clean = actual[np.isfinite(actual)]
        n_clean = len(val_clean)
        if n_clean == 0:
            return 0.0

        n_bins = len(ref_props)
        if len(inner_cutoffs) == 0:
            # Single-bin edge case
            return 0.0

        bin_indices = np.digitize(val_clean, inner_cutoffs, right=False)
        counts = np.bincount(bin_indices, minlength=n_bins)

        # Slice or pad if digitize length differs
        if len(counts) > n_bins:
            counts = counts[:n_bins]
        elif len(counts) < n_bins:
            counts = np.pad(counts, (0, n_bins - len(counts)))

        actual_props = counts / n_clean
        ref_p = np.array(ref_props, dtype=np.float64)

        # Epsilon smoothing to prevent division by zero and undefined log
        act_s = (actual_props + epsilon) / (1.0 + epsilon * n_bins)
        ref_s = (ref_p + epsilon) / (1.0 + epsilon * n_bins)

        psi = np.sum((act_s - ref_s) * np.log(act_s / ref_s))
        return float(max(0.0, psi))

    def _validate_and_extract_matrix(self, flows: List[Dict[str, Any]]) -> np.ndarray:
        """Validate canonical feature completeness and convert flows to a 2D float64 matrix."""
        if not flows:
            raise FeatureValidationError("Flow list cannot be empty for drift evaluation.")

        n_flows = len(flows)
        n_features = len(self._canonical_features)
        matrix = np.empty((n_flows, n_features), dtype=np.float64)

        first_flow = flows[0]
        missing_features = [f for f in self._canonical_features if f not in first_flow]
        if missing_features:
            raise FeatureValidationError(
                f"Missing required canonical features: {missing_features}",
                missing_features=missing_features,
            )

        for row_idx, flow_dict in enumerate(flows):
            for col_idx, feat_name in enumerate(self._canonical_features):
                val = flow_dict.get(feat_name)
                if val is None:
                    raise FeatureValidationError(
                        f"Missing feature '{feat_name}' at flow index {row_idx}.",
                        missing_features=[feat_name],
                    )
                try:
                    num_val = float(val)
                except (ValueError, TypeError) as e:
                    raise FeatureValidationError(
                        f"Non-numeric value for feature '{feat_name}' at flow index {row_idx}: {val}",
                        invalid_fields={feat_name: str(val)},
                    ) from e

                if not np.isfinite(num_val):
                    raise FeatureValidationError(
                        f"Non-finite value ({num_val}) for feature '{feat_name}' at flow index {row_idx}.",
                        invalid_fields={feat_name: str(num_val)},
                    )

                matrix[row_idx, col_idx] = num_val

        return matrix


# Global singleton instance with lazy loading
_drift_service_instance: Optional[FeatureDriftService] = None


def get_drift_service() -> FeatureDriftService:
    """Retrieve or initialize the singleton FeatureDriftService."""
    global _drift_service_instance
    if _drift_service_instance is None:
        _drift_service_instance = FeatureDriftService()
    return _drift_service_instance
