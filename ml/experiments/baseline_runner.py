"""Stage 3 Baseline ML Experiment Orchestrator.

Orchestrates modular experiment functions for Protocol A and Protocol B.
Each completed experiment saves its metrics/artifacts immediately so that
a later failure does not invalidate previous results.

Usage
-----
    python -m ml.experiments.baseline_runner [--smoke-test] [--full]

Architecture
------------
- Protocol A: 70/15/15 stratified random split, 9-class classification
- Protocol B: Capture/day-aware split with 3 separate regimes:
    - Regime A: Known-class cross-capture generalization (BENIGN specificity)
    - Regime B: Unseen-attack open-set evaluation (NADR, escape rate)
    - Regime C: Isolation Forest cross-capture anomaly detection
- Feature sets: K=48 (primary), K=47 (destination_port ablated)
- Models: Logistic Regression, Random Forest, XGBoost, Isolation Forest
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from ml.experiments.config import MODELS_DIR, RANDOM_SEED, REPORTS_DIR
from ml.experiments.data_loader import load_dataset
from ml.experiments.metrics import (
    calibrate_isolation_forest_threshold,
    compute_isolation_forest_metrics,
    compute_known_class_generalization_metrics,
    compute_multiclass_metrics,
    compute_open_set_metrics,
    save_metrics_json,
)
from ml.experiments.model_trainers import (
    compute_xgb_sample_weights,
    evaluate_isolation_forest,
    evaluate_supervised_model,
    fit_scaler,
    get_environment_metadata,
    load_model_artifact,
    save_model_artifact,
    train_isolation_forest,
    train_logistic_regression,
    train_random_forest,
    train_xgboost,
)
from ml.experiments.split_data import create_protocol_a_splits, create_protocol_b_splits

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# Protocol B unseen attack families (present in test but absent from train)
PROTOCOL_B_UNSEEN_FAMILIES = ["WEB_ATTACK", "INFILTRATION", "BOT", "PORT_SCAN", "DDOS"]
# Protocol B known families (present in both train and test)
PROTOCOL_B_KNOWN_TRAIN_ATTACKS = ["BRUTE_FORCE", "DOS"]

# FPR targets for Isolation Forest threshold calibration
IF_FPR_TARGETS = [0.01, 0.05]


# ---------------------------------------------------------------------------
# Feature set helpers
# ---------------------------------------------------------------------------

def load_feature_sets() -> dict[str, list[str]]:
    """Load K=48 and derive K=47 (port-ablated) feature sets."""
    features_path = Path("data/metadata/selected_features.json")
    with open(features_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    k48 = meta["selected_features"]
    k47 = [f for f in k48 if f != "destination_port"]
    logger.info(f"Loaded feature sets: K={len(k48)} (primary), K={len(k47)} (port-ablated)")
    return {"K48": k48, "K47": k47}


def encode_labels(
    train_families: pd.Series,
    *other_families: pd.Series,
) -> tuple[LabelEncoder, np.ndarray, ...]:
    """Fit LabelEncoder on training families, transform all series.

    Returns (encoder, y_train_encoded, y_other1_encoded, ...)
    """
    le = LabelEncoder()
    le.fit(train_families)
    results = [le.transform(train_families)]
    for series in other_families:
        # For labels unseen during training, assign a special index
        encoded = np.array([
            le.transform([v])[0] if v in le.classes_ else -1
            for v in series
        ])
        results.append(encoded)
    return (le, *results)


# ---------------------------------------------------------------------------
# Protocol A Experiment (per model, per feature set)
# ---------------------------------------------------------------------------

def run_protocol_a_supervised(
    model_name: str,
    train_fn,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    class_names: list[str],
    feature_names: list[str],
    feature_set_name: str,
    scaler_for_lr: object | None,
    seed: int = RANDOM_SEED,
) -> dict:
    """Run a single Protocol A supervised model experiment.

    Saves model artifact and metrics immediately.
    """
    logger.info(f"=== Protocol A | {model_name} | {feature_set_name} ===")

    # Train
    model, train_meta = train_fn(X_train, y_train, seed)

    # Evaluate on test set
    y_pred, y_proba, inference_time = evaluate_supervised_model(model, X_test, y_test, class_names)

    # Compute metrics
    test_metrics = compute_multiclass_metrics(y_true=y_test, y_pred=y_pred, y_proba=y_proba, class_names=class_names)

    # Also evaluate on validation set for reference
    y_val_pred, y_val_proba, val_inference_time = evaluate_supervised_model(model, X_val, y_val, class_names)
    val_metrics = compute_multiclass_metrics(y_true=y_val, y_pred=y_val_pred, y_proba=y_val_proba, class_names=class_names)

    # Build label encoder for artifact saving
    le = LabelEncoder()
    le.classes_ = np.array(class_names)

    # Save model artifact
    artifact_path = MODELS_DIR / f"protocol_a_{model_name.lower()}_{feature_set_name.lower()}.joblib"
    artifact_size = save_model_artifact(
        model=model,
        scaler=scaler_for_lr,
        label_encoder=le,
        metadata={
            **train_meta,
            "protocol": "A",
            "feature_set": feature_set_name,
            "feature_names": feature_names,
            "n_features": len(feature_names),
            "class_names": class_names,
            "random_seed": seed,
            "environment": get_environment_metadata(),
            "class_distribution_train": {
                class_names[i]: int((y_train == i).sum())
                for i in range(len(class_names))
            },
        },
        filepath=artifact_path,
    )

    # Compile full results
    result = {
        "model_name": model_name,
        "protocol": "A",
        "feature_set": feature_set_name,
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "random_seed": seed,
        "training_metadata": train_meta,
        "test_metrics": test_metrics,
        "validation_metrics": val_metrics,
        "inference_time_seconds": round(inference_time, 6),
        "inference_samples": len(X_test),
        "inference_latency_per_sample_us": round((inference_time / len(X_test)) * 1e6, 4),
        "artifact_path": str(artifact_path),
        "artifact_size_bytes": artifact_size,
        "environment": get_environment_metadata(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # Save metrics immediately
    metrics_path = REPORTS_DIR / f"protocol_a_{model_name.lower()}_{feature_set_name.lower()}.json"
    save_metrics_json(result, metrics_path)

    return result


def run_protocol_a_isolation_forest(
    X_train_benign: np.ndarray,
    X_val: np.ndarray,
    y_val_binary: np.ndarray,
    X_test: np.ndarray,
    y_test_binary: np.ndarray,
    y_test_families: np.ndarray,
    class_names: list[str],
    feature_names: list[str],
    feature_set_name: str,
    scaler: object | None,
    seed: int = RANDOM_SEED,
) -> dict:
    """Run Protocol A Isolation Forest experiment.

    - Trained on BENIGN-only training flows
    - Calibrated on benign validation flows at FPR targets
    - Evaluated on full test set
    """
    logger.info(f"=== Protocol A | IsolationForest | {feature_set_name} ===")

    # Train on benign only
    model, train_meta = train_isolation_forest(X_train_benign, seed)

    # Score validation benign flows for calibration
    val_benign_mask = y_val_binary == 0
    val_benign_scores, _ = evaluate_isolation_forest(model, X_val[val_benign_mask])

    # Calibrate thresholds
    thresholds = calibrate_isolation_forest_threshold(val_benign_scores, IF_FPR_TARGETS)
    logger.info(f"Calibrated IF thresholds: {thresholds}")

    # Score full test set
    test_scores, inference_time = evaluate_isolation_forest(model, X_test)

    # Compute metrics at calibrated thresholds
    test_metrics = compute_isolation_forest_metrics(y_test_binary, test_scores, thresholds)

    # Per-family detection rates at each threshold
    per_family_detection = {}
    unique_families = np.unique(y_test_families)
    for fpr_key, thresh in thresholds.items():
        family_rates = {}
        for family in unique_families:
            fam_mask = y_test_families == family
            fam_scores = test_scores[fam_mask]
            fam_detected = int((fam_scores < thresh).sum())
            fam_total = int(fam_mask.sum())
            family_rates[family] = {
                "detected": fam_detected,
                "total": fam_total,
                "detection_rate": round(fam_detected / fam_total, 6) if fam_total > 0 else 0.0,
            }
        per_family_detection[str(fpr_key)] = family_rates

    # Save model artifact
    le = LabelEncoder()
    le.classes_ = np.array(class_names)
    artifact_path = MODELS_DIR / f"protocol_a_isolationforest_{feature_set_name.lower()}.joblib"
    artifact_size = save_model_artifact(
        model=model,
        scaler=scaler,
        label_encoder=le,
        metadata={
            **train_meta,
            "protocol": "A",
            "feature_set": feature_set_name,
            "feature_names": feature_names,
            "n_features": len(feature_names),
            "thresholds": thresholds,
            "random_seed": seed,
            "environment": get_environment_metadata(),
        },
        filepath=artifact_path,
    )

    result = {
        "model_name": "IsolationForest",
        "protocol": "A",
        "feature_set": feature_set_name,
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "random_seed": seed,
        "training_metadata": train_meta,
        "calibration": {
            "method": "benign_validation_quantile",
            "fpr_targets": IF_FPR_TARGETS,
            "thresholds": {str(k): round(v, 6) for k, v in thresholds.items()},
            "n_benign_validation_flows": int(val_benign_mask.sum()),
        },
        "test_metrics": test_metrics,
        "per_family_detection": per_family_detection,
        "inference_time_seconds": round(inference_time, 6),
        "inference_samples": len(X_test),
        "inference_latency_per_sample_us": round((inference_time / len(X_test)) * 1e6, 4),
        "artifact_path": str(artifact_path),
        "artifact_size_bytes": artifact_size,
        "environment": get_environment_metadata(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    metrics_path = REPORTS_DIR / f"protocol_a_isolationforest_{feature_set_name.lower()}.json"
    save_metrics_json(result, metrics_path)

    return result


# ---------------------------------------------------------------------------
# Protocol B Experiments (3 Regimes)
# ---------------------------------------------------------------------------

def run_protocol_b_experiment(
    model_name: str,
    train_fn,
    X_train: np.ndarray,
    y_train: np.ndarray,
    y_train_families: np.ndarray,
    X_test: np.ndarray,
    y_test_families: np.ndarray,
    class_names: list[str],
    feature_names: list[str],
    feature_set_name: str,
    scaler_for_lr: object | None,
    seed: int = RANDOM_SEED,
) -> dict:
    """Run Protocol B supervised model experiment across Regimes A and B.

    Regime A: Known-class cross-capture generalization (evaluate on test BENIGN)
    Regime B: Unseen-attack open-set evaluation (evaluate on unseen test attacks)

    Protocol B does NOT report ordinary 9-class accuracy/F1 for unseen families.
    """
    logger.info(f"=== Protocol B | {model_name} | {feature_set_name} ===")

    # Train (on Mon-Wed data)
    model, train_meta = train_fn(X_train, y_train, seed)

    # Predict on full test set
    le_temp = LabelEncoder()
    le_temp.classes_ = np.array(class_names)

    y_pred, y_proba, inference_time = evaluate_supervised_model(model, X_test, None, class_names)

    # --- Regime A: Known-class cross-capture generalization ---
    regime_a = compute_known_class_generalization_metrics(
        y_true_families=y_test_families,
        y_pred_indices=y_pred,
        class_names=class_names,
    )

    # --- Regime B: Unseen-attack open-set evaluation ---
    regime_b = compute_open_set_metrics(
        y_true_families=y_test_families,
        y_pred_indices=y_pred,
        y_proba=y_proba,
        class_names=class_names,
        unseen_families=PROTOCOL_B_UNSEEN_FAMILIES,
    )

    # Save model artifact
    le = LabelEncoder()
    le.classes_ = np.array(class_names)
    artifact_path = MODELS_DIR / f"protocol_b_{model_name.lower()}_{feature_set_name.lower()}.joblib"
    artifact_size = save_model_artifact(
        model=model,
        scaler=scaler_for_lr,
        label_encoder=le,
        metadata={
            **train_meta,
            "protocol": "B",
            "feature_set": feature_set_name,
            "feature_names": feature_names,
            "n_features": len(feature_names),
            "class_names": class_names,
            "random_seed": seed,
            "environment": get_environment_metadata(),
            "train_attack_families": sorted(set(y_train_families)),
            "class_distribution_train": {
                class_names[i]: int((y_train == i).sum())
                for i in range(len(class_names))
            },
        },
        filepath=artifact_path,
    )

    result = {
        "model_name": model_name,
        "protocol": "B",
        "feature_set": feature_set_name,
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "random_seed": seed,
        "training_metadata": train_meta,
        "regime_a_known_class_generalization": regime_a,
        "regime_b_unseen_attack_open_set": regime_b,
        "inference_time_seconds": round(inference_time, 6),
        "inference_samples": len(X_test),
        "artifact_path": str(artifact_path),
        "artifact_size_bytes": artifact_size,
        "environment": get_environment_metadata(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "methodological_notes": [
            "Protocol B trains on Mon-Wed, tests on Thu-Fri.",
            "Regime A evaluates BENIGN specificity (cross-day FPR).",
            "Regime B evaluates unseen attack families (NADR, escape rate).",
            "Ordinary 9-class F1 is NOT reported for unseen families.",
            f"Unseen families in test: {PROTOCOL_B_UNSEEN_FAMILIES}",
            f"Known train attack families: {PROTOCOL_B_KNOWN_TRAIN_ATTACKS}",
        ],
    }

    metrics_path = REPORTS_DIR / f"protocol_b_{model_name.lower()}_{feature_set_name.lower()}.json"
    save_metrics_json(result, metrics_path)

    return result


def run_protocol_b_isolation_forest(
    X_train_benign: np.ndarray,
    X_test: np.ndarray,
    y_test_binary: np.ndarray,
    y_test_families: np.ndarray,
    class_names: list[str],
    feature_names: list[str],
    feature_set_name: str,
    scaler: object | None,
    n_train_benign_total: int = 0,
    seed: int = RANDOM_SEED,
) -> dict:
    """Run Protocol B Regime C: IF cross-capture anomaly detection.

    - Train on Mon-Wed BENIGN only
    - Calibrate threshold using a held-out 20% of Mon-Wed benign (validation slice)
    - Evaluate on Thu-Fri benign (FPR) and Thu-Fri attacks (detection rate)
    """
    logger.info(f"=== Protocol B Regime C | IsolationForest | {feature_set_name} ===")

    # Split Mon-Wed benign into train/val for threshold calibration (80/20)
    n_benign = len(X_train_benign)
    val_size = max(int(n_benign * 0.2), 100)
    indices = np.arange(n_benign)
    rng = np.random.RandomState(seed)
    rng.shuffle(indices)
    val_indices = indices[:val_size]
    train_indices = indices[val_size:]

    X_if_train = X_train_benign[train_indices]
    X_if_val = X_train_benign[val_indices]

    # Train
    model, train_meta = train_isolation_forest(X_if_train, seed)

    # Calibrate on benign validation slice
    val_scores, _ = evaluate_isolation_forest(model, X_if_val)
    thresholds = calibrate_isolation_forest_threshold(val_scores, IF_FPR_TARGETS)
    logger.info(f"Protocol B IF thresholds: {thresholds}")

    # Score full test set
    test_scores, inference_time = evaluate_isolation_forest(model, X_test)

    # Compute metrics
    test_metrics = compute_isolation_forest_metrics(y_test_binary, test_scores, thresholds)

    # Per-family detection
    per_family_detection = {}
    unique_families = np.unique(y_test_families)
    for fpr_key, thresh in thresholds.items():
        family_rates = {}
        for family in unique_families:
            fam_mask = y_test_families == family
            fam_scores = test_scores[fam_mask]
            fam_detected = int((fam_scores < thresh).sum())
            fam_total = int(fam_mask.sum())
            family_rates[family] = {
                "detected": fam_detected,
                "total": fam_total,
                "detection_rate": round(fam_detected / fam_total, 6) if fam_total > 0 else 0.0,
            }
        per_family_detection[str(fpr_key)] = family_rates

    # Save
    le = LabelEncoder()
    le.classes_ = np.array(class_names)
    artifact_path = MODELS_DIR / f"protocol_b_isolationforest_{feature_set_name.lower()}.joblib"
    artifact_size = save_model_artifact(
        model=model,
        scaler=scaler,
        label_encoder=le,
        metadata={
            **train_meta,
            "protocol": "B_Regime_C",
            "feature_set": feature_set_name,
            "feature_names": feature_names,
            "n_features": len(feature_names),
            "thresholds": thresholds,
            "random_seed": seed,
            "calibration_benign_count": val_size,
            "environment": get_environment_metadata(),
        },
        filepath=artifact_path,
    )

    result = {
        "model_name": "IsolationForest",
        "protocol": "B_Regime_C",
        "feature_set": feature_set_name,
        "n_features": len(feature_names),
        "feature_names": feature_names,
        "random_seed": seed,
        "training_metadata": train_meta,
        "calibration": {
            "method": "benign_validation_slice (80/20 of Mon-Wed benign)",
            "fpr_targets": IF_FPR_TARGETS,
            "thresholds": {str(k): round(v, 6) for k, v in thresholds.items()},
            "n_benign_train": len(X_if_train),
            "n_benign_val": val_size,
        },
        "test_metrics": test_metrics,
        "per_family_detection": per_family_detection,
        "inference_time_seconds": round(inference_time, 6),
        "inference_samples": len(X_test),
        "artifact_path": str(artifact_path),
        "artifact_size_bytes": artifact_size,
        "environment": get_environment_metadata(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "methodological_notes": [
            "Protocol B Regime C: IF cross-capture anomaly detection.",
            "Trained exclusively on Mon-Wed BENIGN traffic.",
            "Threshold calibrated on held-out 20% of Mon-Wed benign.",
            "decision_function convention: lower scores = more anomalous.",
            f"All test attack families are unseen: {PROTOCOL_B_UNSEEN_FAMILIES}",
        ],
    }

    metrics_path = REPORTS_DIR / f"protocol_b_isolationforest_{feature_set_name.lower()}.json"
    save_metrics_json(result, metrics_path)

    return result


# ---------------------------------------------------------------------------
# Smoke Test
# ---------------------------------------------------------------------------

def _sample_balanced_subset(split_df: pd.DataFrame, max_total: int = 50_000, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """Extract a representative subsample preserving representation of all classes."""
    parts = []
    for fam, grp in split_df.groupby("attack_family"):
        n_take = min(len(grp), 500)
        parts.append(grp.sample(n=n_take, random_state=seed))
    base = pd.concat(parts)
    remaining_needed = max(0, max_total - len(base))
    if remaining_needed > 0:
        unused = split_df.drop(base.index)
        if len(unused) > 0:
            extra = unused.sample(n=min(remaining_needed, len(unused)), random_state=seed)
            return pd.concat([base, extra]).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return base.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def run_smoke_test(df: pd.DataFrame, feature_sets: dict[str, list[str]]) -> bool:
    """Run end-to-end smoke test on a ~70k-row representative split.

    Validates: preprocessing, training, prediction, probability generation,
    metrics computation, serialization, reload, and prediction consistency
    for all 4 models across both feature sets (K=48 and K=47) and both protocols (A and B).

    Returns True if all checks pass.
    """
    logger.info("=" * 60)
    logger.info("SMOKE TEST: Starting representative end-to-end validation")
    logger.info("=" * 60)

    t_start = time.perf_counter()

    # Create full splits first to preserve exact partition boundaries
    logger.info("Creating Protocol A full splits...")
    train_full, val_full, test_full, _ = create_protocol_a_splits(df, RANDOM_SEED)

    # Subsample representative sets
    train_df = _sample_balanced_subset(train_full, max_total=50_000, seed=RANDOM_SEED)
    val_df = _sample_balanced_subset(val_full, max_total=10_000, seed=RANDOM_SEED)
    test_df = _sample_balanced_subset(test_full, max_total=10_000, seed=RANDOM_SEED)

    logger.info(
        f"Smoke Protocol A splits: train={len(train_df):,} ({train_df['attack_family'].nunique()} families), "
        f"val={len(val_df):,} ({val_df['attack_family'].nunique()} families), "
        f"test={len(test_df):,} ({test_df['attack_family'].nunique()} families)"
    )

    # Protocol B full splits & subsample
    logger.info("Creating Protocol B full splits...")
    pb_train_full, pb_test_full, _ = create_protocol_b_splits(df)
    pb_train_df = _sample_balanced_subset(pb_train_full, max_total=35_000, seed=RANDOM_SEED)
    pb_test_df = _sample_balanced_subset(pb_test_full, max_total=25_000, seed=RANDOM_SEED)

    logger.info(
        f"Smoke Protocol B splits: train={len(pb_train_df):,} ({pb_train_df['attack_family'].nunique()} families), "
        f"test={len(pb_test_df):,} ({pb_test_df['attack_family'].nunique()} families)"
    )

    all_passed = True
    smoke_dir = MODELS_DIR / "smoke_test"
    smoke_dir.mkdir(parents=True, exist_ok=True)

    for fs_name, feature_list in feature_sets.items():
        logger.info(f"\n--- Smoke test: {fs_name} ({len(feature_list)} features) ---")

        # Verify all features present
        missing = [f for f in feature_list if f not in train_df.columns]
        if missing:
            logger.error(f"Missing features in smoke data: {missing}")
            all_passed = False
            continue

        X_train_raw = train_df[feature_list].values.astype(np.float64)
        X_val_raw = val_df[feature_list].values.astype(np.float64)
        X_test_raw = test_df[feature_list].values.astype(np.float64)

        # Fit scaler on train
        scaler = fit_scaler(X_train_raw)
        X_train_scaled = scaler.transform(X_train_raw)
        X_val_scaled = scaler.transform(X_val_raw)
        X_test_scaled = scaler.transform(X_test_raw)

        # Label encoding
        le = LabelEncoder()
        y_train = le.fit_transform(train_df["attack_family"])
        # Map val and test labels, replacing any unseen with -1 or closest
        y_val = np.array([le.transform([v])[0] if v in le.classes_ else -1 for v in val_df["attack_family"]])
        y_test = np.array([le.transform([v])[0] if v in le.classes_ else -1 for v in test_df["attack_family"]])
        class_names = list(le.classes_)

        y_train_binary = (train_df["attack_family"] != "BENIGN").astype(int).values
        y_val_binary = (val_df["attack_family"] != "BENIGN").astype(int).values
        y_test_binary = (test_df["attack_family"] != "BENIGN").astype(int).values

        # --- Test each supervised model under Protocol A ---
        models_to_test = [
            ("LogisticRegression", train_logistic_regression, X_train_scaled, X_val_scaled, X_test_scaled, True),
            ("RandomForest", train_random_forest, X_train_raw, X_val_raw, X_test_raw, False),
            ("XGBoost", train_xgboost, X_train_raw, X_val_raw, X_test_raw, False),
        ]

        for model_name, train_fn, X_tr, X_v, X_te, uses_scaler in models_to_test:
            try:
                logger.info(f"  Smoke Protocol A: {model_name} training...")
                model, meta = train_fn(X_tr, y_train)

                # Predict
                y_pred, y_proba, inf_time = evaluate_supervised_model(model, X_te, y_test, class_names)
                assert len(y_pred) == len(y_test), f"Prediction length mismatch for {model_name}"
                assert y_proba is not None, f"No probabilities for {model_name}"
                assert y_proba.shape == (len(y_test), len(class_names)), f"Proba shape mismatch for {model_name}"

                # Metrics
                metrics = compute_multiclass_metrics(y_test, y_pred, y_proba, class_names)
                assert "macro_f1" in metrics, f"Missing macro_f1 in metrics for {model_name}"
                assert 0 <= metrics["macro_f1"] <= 1, f"Invalid macro_f1 for {model_name}"

                # Serialize
                artifact_path = smoke_dir / f"smoke_pa_{model_name.lower()}_{fs_name.lower()}.joblib"
                save_model_artifact(model, scaler if uses_scaler else None, le, meta, artifact_path)

                # Reload and verify consistency
                loaded = load_model_artifact(artifact_path)
                loaded_model = loaded["model"]

                y_pred_reload = loaded_model.predict(X_te)
                assert np.array_equal(y_pred, y_pred_reload), (
                    f"Prediction inconsistency after reload for {model_name}"
                )

                logger.info(f"  ✓ Protocol A | {model_name} | {fs_name} | macro_f1={metrics['macro_f1']:.4f} | PASSED")

            except Exception as e:
                logger.error(f"  ✗ Protocol A | {model_name} | {fs_name} | FAILED: {e}")
                all_passed = False

        # --- Protocol A Isolation Forest ---
        try:
            logger.info(f"  Smoke Protocol A: IsolationForest training...")
            benign_mask_train = train_df["attack_family"] == "BENIGN"
            X_if_train = X_train_scaled[benign_mask_train.values]

            if len(X_if_train) < 10:
                logger.warning("  Too few benign samples for IF smoke test, skipping")
            else:
                model_if, meta_if = train_isolation_forest(X_if_train)

                # Score validation benign for calibration
                val_benign_mask = val_df["attack_family"] == "BENIGN"
                val_benign_scores, _ = evaluate_isolation_forest(model_if, X_val_scaled[val_benign_mask.values])
                thresholds = calibrate_isolation_forest_threshold(val_benign_scores, IF_FPR_TARGETS)

                # Score test set
                test_scores, inf_time = evaluate_isolation_forest(model_if, X_test_scaled)
                if_metrics = compute_isolation_forest_metrics(y_test_binary, test_scores, thresholds)
                assert "roc_auc" in if_metrics, "Missing roc_auc in IF metrics"

                # Serialize
                artifact_path = smoke_dir / f"smoke_pa_isolationforest_{fs_name.lower()}.joblib"
                save_model_artifact(model_if, scaler, le, meta_if, artifact_path)

                # Reload and verify
                loaded_if = load_model_artifact(artifact_path)
                scores_reload, _ = evaluate_isolation_forest(loaded_if["model"], X_test_scaled)
                assert np.allclose(test_scores, scores_reload, atol=1e-10), (
                    "IF score inconsistency after reload"
                )

                logger.info(f"  ✓ Protocol A | IsolationForest | {fs_name} | roc_auc={if_metrics['roc_auc']:.4f} | PASSED")

        except Exception as e:
            logger.error(f"  ✗ Protocol A | IsolationForest | {fs_name} | FAILED: {e}")
            all_passed = False

        # --- Smoke Test Protocol B (Supervised & IF) ---
        try:
            logger.info(f"  Smoke Protocol B: Supervised & IF Regime C ({fs_name})...")
            X_pb_tr_raw = pb_train_df[feature_list].values.astype(np.float64)
            X_pb_te_raw = pb_test_df[feature_list].values.astype(np.float64)
            scaler_pb = fit_scaler(X_pb_tr_raw)
            X_pb_tr_scaled = scaler_pb.transform(X_pb_tr_raw)
            X_pb_te_scaled = scaler_pb.transform(X_pb_te_raw)

            le_pb = LabelEncoder()
            y_pb_tr = le_pb.fit_transform(pb_train_df["attack_family"])
            class_names_pb = list(le_pb.classes_)

            # Test Protocol B LR
            res_pb_lr = run_protocol_b_experiment(
                model_name="LogisticRegression",
                train_fn=train_logistic_regression,
                X_train=X_pb_tr_scaled, y_train=y_pb_tr,
                y_train_families=pb_train_df["attack_family"].values,
                X_test=X_pb_te_scaled,
                y_test_families=pb_test_df["attack_family"].values,
                class_names=class_names_pb,
                feature_names=feature_list,
                feature_set_name=f"smoke_{fs_name}",
                scaler_for_lr=scaler_pb,
            )
            assert "regime_a_known_class_generalization" in res_pb_lr
            assert "regime_b_unseen_attack_open_set" in res_pb_lr

            # Test Protocol B IF
            pb_benign_mask = pb_train_df["attack_family"] == "BENIGN"
            res_pb_if = run_protocol_b_isolation_forest(
                X_train_benign=X_pb_tr_scaled[pb_benign_mask.values],
                X_test=X_pb_te_scaled,
                y_test_binary=(pb_test_df["attack_family"] != "BENIGN").astype(int).values,
                y_test_families=pb_test_df["attack_family"].values,
                class_names=class_names_pb,
                feature_names=feature_list,
                feature_set_name=f"smoke_{fs_name}",
                scaler=scaler_pb,
                n_train_benign_total=int(pb_benign_mask.sum()),
            )
            assert "calibration" in res_pb_if
            assert "test_metrics" in res_pb_if

            logger.info(f"  ✓ Protocol B | Supervised + IF | {fs_name} | PASSED")

        except Exception as e:
            logger.error(f"  ✗ Protocol B | {fs_name} | FAILED: {e}")
            all_passed = False

    elapsed = time.perf_counter() - t_start
    if all_passed:
        logger.info(f"\n{'='*60}")
        logger.info(f"SMOKE TEST PASSED — all models × feature sets × protocols verified ({elapsed:.1f}s)")
        logger.info(f"{'='*60}")
    else:
        logger.error(f"\n{'='*60}")
        logger.error(f"SMOKE TEST FAILED — see errors above ({elapsed:.1f}s)")
        logger.error(f"{'='*60}")

    return all_passed


# ---------------------------------------------------------------------------
# Full-Scale Experiment Runner
# ---------------------------------------------------------------------------

def run_full_experiments(df: pd.DataFrame, feature_sets: dict[str, list[str]]) -> dict:
    """Run all Protocol A and Protocol B experiments.

    Each experiment saves its results immediately.
    Returns a summary dict.
    """
    logger.info("=" * 70)
    logger.info("FULL-SCALE BASELINE EXPERIMENTS: Starting")
    logger.info("=" * 70)

    t_total_start = time.perf_counter()
    all_results = {"protocol_a": {}, "protocol_b": {}}

    # Ensure output directories exist
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # ----- Create Splits -----
    logger.info("Creating Protocol A splits...")
    train_df, val_df, test_df, pa_report = create_protocol_a_splits(df, RANDOM_SEED)
    save_metrics_json(pa_report, REPORTS_DIR / "protocol_a_split_report.json")

    logger.info("Creating Protocol B splits...")
    pb_train_df, pb_test_df, pb_report = create_protocol_b_splits(df)
    save_metrics_json(pb_report, REPORTS_DIR / "protocol_b_split_report.json")

    # Load contamination data
    contamination_path = Path("artifacts/reports/duplicate_boundary_contamination.json")
    contamination_count = 34_771  # default known value
    if contamination_path.exists():
        with open(contamination_path, "r") as f:
            contam_data = json.load(f)
            contamination_count = contam_data.get("protocol_a", {}).get(
                "shared_train_test_vectors", contamination_count
            )

    for fs_name, feature_list in feature_sets.items():
        logger.info(f"\n{'='*70}")
        logger.info(f"FEATURE SET: {fs_name} ({len(feature_list)} features)")
        logger.info(f"{'='*70}")

        # ===== Protocol A =====
        X_train_raw = train_df[feature_list].values.astype(np.float64)
        X_val_raw = val_df[feature_list].values.astype(np.float64)
        X_test_raw = test_df[feature_list].values.astype(np.float64)

        # Fit scaler on train for LR and IF
        scaler = fit_scaler(X_train_raw)
        X_train_scaled = scaler.transform(X_train_raw)
        X_val_scaled = scaler.transform(X_val_raw)
        X_test_scaled = scaler.transform(X_test_raw)

        # Label encoding (Protocol A)
        le_a = LabelEncoder()
        y_train = le_a.fit_transform(train_df["attack_family"])
        y_val = le_a.transform(val_df["attack_family"])
        y_test = le_a.transform(test_df["attack_family"])
        class_names = list(le_a.classes_)

        y_train_binary = (train_df["attack_family"] != "BENIGN").astype(int).values
        y_val_binary = (val_df["attack_family"] != "BENIGN").astype(int).values
        y_test_binary = (test_df["attack_family"] != "BENIGN").astype(int).values

        # Record class distribution
        train_class_dist = {cn: int((y_train == i).sum()) for i, cn in enumerate(class_names)}
        logger.info(f"Protocol A class distribution (train): {train_class_dist}")

        fs_results_a = {}

        # --- LR (scaled) ---
        fs_results_a["LogisticRegression"] = run_protocol_a_supervised(
            model_name="LogisticRegression",
            train_fn=train_logistic_regression,
            X_train=X_train_scaled, y_train=y_train,
            X_val=X_val_scaled, y_val=y_val,
            X_test=X_test_scaled, y_test=y_test,
            class_names=class_names,
            feature_names=feature_list,
            feature_set_name=fs_name,
            scaler_for_lr=scaler,
        )

        # --- RF (unscaled) ---
        fs_results_a["RandomForest"] = run_protocol_a_supervised(
            model_name="RandomForest",
            train_fn=train_random_forest,
            X_train=X_train_raw, y_train=y_train,
            X_val=X_val_raw, y_val=y_val,
            X_test=X_test_raw, y_test=y_test,
            class_names=class_names,
            feature_names=feature_list,
            feature_set_name=fs_name,
            scaler_for_lr=None,
        )

        # --- XGBoost (unscaled) ---
        fs_results_a["XGBoost"] = run_protocol_a_supervised(
            model_name="XGBoost",
            train_fn=train_xgboost,
            X_train=X_train_raw, y_train=y_train,
            X_val=X_val_raw, y_val=y_val,
            X_test=X_test_raw, y_test=y_test,
            class_names=class_names,
            feature_names=feature_list,
            feature_set_name=fs_name,
            scaler_for_lr=None,
        )

        # --- Isolation Forest (scaled) ---
        benign_mask_train = train_df["attack_family"] == "BENIGN"
        X_train_benign_scaled = X_train_scaled[benign_mask_train.values]

        fs_results_a["IsolationForest"] = run_protocol_a_isolation_forest(
            X_train_benign=X_train_benign_scaled,
            X_val=X_val_scaled, y_val_binary=y_val_binary,
            X_test=X_test_scaled, y_test_binary=y_test_binary,
            y_test_families=test_df["attack_family"].values,
            class_names=class_names,
            feature_names=feature_list,
            feature_set_name=fs_name,
            scaler=scaler,
        )

        all_results["protocol_a"][fs_name] = fs_results_a

        # ===== Protocol B =====
        X_pb_train_raw = pb_train_df[feature_list].values.astype(np.float64)
        X_pb_test_raw = pb_test_df[feature_list].values.astype(np.float64)

        # Fit scaler on Protocol B train for LR and IF
        scaler_b = fit_scaler(X_pb_train_raw)
        X_pb_train_scaled = scaler_b.transform(X_pb_train_raw)
        X_pb_test_scaled = scaler_b.transform(X_pb_test_raw)

        # Label encoding (Protocol B uses same class vocabulary as A)
        le_b = LabelEncoder()
        le_b.fit(pb_train_df["attack_family"])
        y_pb_train = le_b.transform(pb_train_df["attack_family"])
        class_names_b = list(le_b.classes_)
        # Test families may include classes not in train
        y_pb_test_families = pb_test_df["attack_family"].values
        y_pb_test_binary = (pb_test_df["attack_family"] != "BENIGN").astype(int).values

        fs_results_b = {}

        # --- LR (scaled) ---
        fs_results_b["LogisticRegression"] = run_protocol_b_experiment(
            model_name="LogisticRegression",
            train_fn=train_logistic_regression,
            X_train=X_pb_train_scaled, y_train=y_pb_train,
            y_train_families=pb_train_df["attack_family"].values,
            X_test=X_pb_test_scaled,
            y_test_families=y_pb_test_families,
            class_names=class_names_b,
            feature_names=feature_list,
            feature_set_name=fs_name,
            scaler_for_lr=scaler_b,
        )

        # --- RF (unscaled) ---
        fs_results_b["RandomForest"] = run_protocol_b_experiment(
            model_name="RandomForest",
            train_fn=train_random_forest,
            X_train=X_pb_train_raw, y_train=y_pb_train,
            y_train_families=pb_train_df["attack_family"].values,
            X_test=X_pb_test_raw,
            y_test_families=y_pb_test_families,
            class_names=class_names_b,
            feature_names=feature_list,
            feature_set_name=fs_name,
            scaler_for_lr=None,
        )

        # --- XGBoost (unscaled) ---
        fs_results_b["XGBoost"] = run_protocol_b_experiment(
            model_name="XGBoost",
            train_fn=train_xgboost,
            X_train=X_pb_train_raw, y_train=y_pb_train,
            y_train_families=pb_train_df["attack_family"].values,
            X_test=X_pb_test_raw,
            y_test_families=y_pb_test_families,
            class_names=class_names_b,
            feature_names=feature_list,
            feature_set_name=fs_name,
            scaler_for_lr=None,
        )

        # --- IF Regime C (scaled) ---
        pb_benign_mask = pb_train_df["attack_family"] == "BENIGN"
        X_pb_train_benign_scaled = X_pb_train_scaled[pb_benign_mask.values]

        fs_results_b["IsolationForest_Regime_C"] = run_protocol_b_isolation_forest(
            X_train_benign=X_pb_train_benign_scaled,
            X_test=X_pb_test_scaled,
            y_test_binary=y_pb_test_binary,
            y_test_families=y_pb_test_families,
            class_names=class_names_b,
            feature_names=feature_list,
            feature_set_name=fs_name,
            scaler=scaler_b,
            n_train_benign_total=int(pb_benign_mask.sum()),
        )

        all_results["protocol_b"][fs_name] = fs_results_b

    total_time = time.perf_counter() - t_total_start

    # Save consolidated summary
    summary = {
        "total_runtime_seconds": round(total_time, 2),
        "total_runtime_human": f"{total_time / 60:.1f} minutes",
        "dataset_total_rows": len(df),
        "protocol_a_train_test_contamination_count": contamination_count,
        "contamination_note": (
            f"{contamination_count:,} feature-identical vectors are shared between "
            "Protocol A Train and Test partitions due to row-level random splitting "
            "of duplicate flows. This is a known limitation documented in "
            "docs/experiments/duplicate_analysis_report.md."
        ),
        "feature_sets": {k: len(v) for k, v in feature_sets.items()},
        "models_evaluated": ["LogisticRegression", "RandomForest", "XGBoost", "IsolationForest"],
        "environment": get_environment_metadata(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    save_metrics_json(summary, REPORTS_DIR / "experiment_summary.json")

    logger.info(f"\n{'='*70}")
    logger.info(f"ALL EXPERIMENTS COMPLETE in {total_time:.1f}s ({total_time/60:.1f} min)")
    logger.info(f"{'='*70}")

    return all_results


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Stage 3 Baseline ML Experiments")
    parser.add_argument("--smoke-test", action="store_true", help="Run smoke test only")
    parser.add_argument("--full", action="store_true", help="Run full-scale experiments")
    args = parser.parse_args()

    logger.info("Loading dataset...")
    t0 = time.perf_counter()
    df, load_reports = load_dataset(reject_non_finite=True)
    load_time = time.perf_counter() - t0
    logger.info(f"Dataset loaded: {len(df):,} rows in {load_time:.1f}s")

    feature_sets = load_feature_sets()

    if args.smoke_test or (not args.full):
        passed = run_smoke_test(df, feature_sets)
        if not passed:
            logger.error("Smoke test FAILED. Aborting.")
            sys.exit(1)
        else:
            logger.info("Smoke test completed with 100% checks passed.")

    if args.full:
        results = run_full_experiments(df, feature_sets)
        logger.info("Full experiments completed successfully.")

    sys.exit(0)


if __name__ == "__main__":
    main()
