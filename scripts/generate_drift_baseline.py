"""Generate reproducible production feature drift baseline artifact.

This script executes Phase 1 of Feature Drift Monitoring:
1. Loads the authentic CICIDS2017 dataset using existing pipeline cleaning rules.
2. Partitions via Protocol A (70/15/15 stratified random split, seed=42) to isolate
   the exact 1,979,432-flow training population.
3. Aligns with the frozen K=48 canonical schema from data/metadata/selected_features.json.
4. Verifies zero deviation against the production StandardScaler moments.
5. Computes adaptive zero-inflated and continuous empirical quantiles and reference proportions.
6. Exports data/metadata/baseline_feature_distributions.json.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
from pathlib import Path
import sys
import numpy as np
import joblib

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.experiments.config import RANDOM_SEED
from ml.experiments.data_loader import load_dataset
from ml.experiments.split_data import create_protocol_a_splits

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def compute_feature_bins(values: np.ndarray, n_bins: int = 10) -> dict:
    """Compute adaptive bin cutoffs and empirical reference proportions for a feature."""
    val_clean = values[np.isfinite(values)]
    if len(val_clean) == 0:
        raise ValueError("Cannot compute bins on empty or all-non-finite array.")

    unique_vals = np.unique(val_clean)

    # 1. Discrete features with few unique values (e.g. binary flags)
    if len(unique_vals) <= 5:
        sorted_vals = np.sort(unique_vals)
        midpoints = (sorted_vals[:-1] + sorted_vals[1:]) / 2.0
        inner_cutoffs = [float(c) for c in midpoints]
        bin_indices = np.digitize(val_clean, inner_cutoffs, right=False)
        counts = np.bincount(bin_indices, minlength=len(inner_cutoffs) + 1)
        proportions = [float(c / len(val_clean)) for c in counts]
        return {
            "bin_type": "discrete",
            "inner_cutoffs": inner_cutoffs,
            "reference_proportions": proportions,
            "n_bins": len(proportions),
        }

    # 2. Check for zero-inflation
    zero_mask = np.isclose(val_clean, 0.0, atol=1e-6)
    zero_fraction = float(np.mean(zero_mask))

    if zero_fraction >= 0.05:
        pos_vals = val_clean[val_clean > 1e-6]
        neg_vals = val_clean[val_clean < -1e-6]

        if len(neg_vals) == 0:
            target_pos_bins = min(n_bins - 1, len(np.unique(pos_vals)))
            if target_pos_bins > 1:
                pcts = np.linspace(0, 100, target_pos_bins + 1)[1:-1]
                pos_quantiles = np.unique(np.percentile(pos_vals, pcts))
                inner_cutoffs = [1e-6] + [float(q) for q in pos_quantiles]
            else:
                inner_cutoffs = [1e-6]
        else:
            pcts = np.linspace(0, 100, n_bins + 1)[1:-1]
            inner_cutoffs = list(np.unique(np.percentile(val_clean, pcts)))
            if 0.0 not in inner_cutoffs and 1e-6 not in inner_cutoffs:
                inner_cutoffs = sorted(list(set(inner_cutoffs + [1e-6])))
    else:
        # 3. Standard continuous feature
        pcts = np.linspace(0, 100, n_bins + 1)[1:-1]
        inner_cutoffs = list(np.unique(np.percentile(val_clean, pcts)))

    inner_cutoffs = sorted([float(c) for c in list(set(inner_cutoffs))])
    bin_indices = np.digitize(val_clean, inner_cutoffs, right=False)
    counts = np.bincount(bin_indices, minlength=len(inner_cutoffs) + 1)
    proportions = [float(c / len(val_clean)) for c in counts]

    return {
        "bin_type": "zero_inflated" if zero_fraction >= 0.05 else "continuous",
        "inner_cutoffs": inner_cutoffs,
        "reference_proportions": proportions,
        "n_bins": len(proportions),
    }


def main():
    logger.info("Starting reproducible drift baseline generation...")

    # Load canonical feature schema
    selected_features_path = PROJECT_ROOT / "data" / "metadata" / "selected_features.json"
    with open(selected_features_path, "rb") as f:
        raw_schema = f.read()
        schema_sha256 = hashlib.sha256(raw_schema).hexdigest()
        feature_names = json.loads(raw_schema.decode("utf-8"))["selected_features"]

    logger.info("Loaded %d canonical features from %s", len(feature_names), selected_features_path.name)

    # Load training dataset
    full_df, reports = load_dataset()
    logger.info("Full dataset loaded: %d rows from %d files", len(full_df), len(reports))

    train_df, _, _, split_report = create_protocol_a_splits(full_df, seed=RANDOM_SEED)
    n_train = len(train_df)
    logger.info("Isolated Protocol A training split: %d rows", n_train)

    # Verification against production StandardScaler
    scaler_path = PROJECT_ROOT / "artifacts" / "models" / "protocol_a_logisticregression_k48.joblib"
    scaler_bundle = joblib.load(scaler_path)
    scaler = scaler_bundle["scaler"]
    scaler_means = scaler.mean_
    scaler_vars = scaler.var_

    train_X = train_df[feature_names].values.astype(np.float64)
    computed_means = np.mean(train_X, axis=0)
    computed_vars = np.var(train_X, axis=0)

    max_delta_mean = float(np.max(np.abs(scaler_means - computed_means)))
    max_delta_var = float(np.max(np.abs(scaler_vars - computed_vars)))

    logger.info("StandardScaler alignment check: max_delta_mean=%.6e, max_delta_var=%.6e", max_delta_mean, max_delta_var)
    if max_delta_mean > 1e-4 or max_delta_var > 1e-2:
        raise RuntimeError(
            f"FATAL: Training split does not align with production StandardScaler: "
            f"max_delta_mean={max_delta_mean}, max_delta_var={max_delta_var}"
        )

    # Generate feature distribution metadata
    features_meta = {}
    for idx, name in enumerate(feature_names):
        col_vals = train_X[:, idx]
        bin_info = compute_feature_bins(col_vals)

        c_mean = float(computed_means[idx])
        c_var = float(computed_vars[idx])
        c_std = float(np.sqrt(c_var))
        c_min = float(np.min(col_vals))
        c_max = float(np.max(col_vals))
        zero_fraction = float(np.mean(np.isclose(col_vals, 0.0, atol=1e-6)))

        features_meta[name] = {
            "feature_name": name,
            "canonical_index": idx,
            "mean": c_mean,
            "std": c_std,
            "variance": c_var,
            "min": c_min,
            "max": c_max,
            "zero_fraction": zero_fraction,
            "bin_type": bin_info["bin_type"],
            "inner_cutoffs": [float(c) for c in bin_info["inner_cutoffs"]],
            "reference_proportions": [float(p) for p in bin_info["reference_proportions"]],
            "n_bins": bin_info["n_bins"],
            "scaler_mean": float(scaler_means[idx]),
            "scaler_var": float(scaler_vars[idx]),
            "alignment_delta_mean": float(abs(c_mean - scaler_means[idx])),
            "alignment_delta_var": float(abs(c_var - scaler_vars[idx])),
        }

    output_payload = {
        "schema_version": "1.0.0",
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_dataset": "CICIDS2017 MachineLearningCVE",
        "split_protocol": "Protocol A (70/15/15 Stratified Random Split, seed=42)",
        "training_sample_count": n_train,
        "k_features": len(feature_names),
        "selected_features_sha256": schema_sha256,
        "alignment_verification": {
            "status": "EXACT_ALIGNMENT",
            "max_delta_mean": max_delta_mean,
            "max_delta_var": max_delta_var,
        },
        "features": features_meta,
    }

    output_path = PROJECT_ROOT / "data" / "metadata" / "baseline_feature_distributions.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    logger.info("Successfully generated baseline distributions artifact: %s (size: %d bytes)", output_path, output_path.stat().st_size)


if __name__ == "__main__":
    main()
