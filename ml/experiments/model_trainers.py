"""Model training, evaluation, and serialization for Stage 3 baseline experiments.

Provides functions for each of the 4 baseline models:
- Logistic Regression (class_weight='balanced', scaled)
- Random Forest (class_weight='balanced_subsample', unscaled)
- XGBoost (explicit sample weights, unscaled)
- Isolation Forest (unsupervised, scaled, threshold-calibrated on benign validation)

Each function records training time, inference latency, and full metadata.
Model artifacts include the model object, scaler (if any), and metadata dict.
"""

from __future__ import annotations

import logging
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler

from ml.experiments.config import RANDOM_SEED

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Environment metadata
# ---------------------------------------------------------------------------

def get_environment_metadata() -> dict:
    """Capture software/library versions and platform info."""
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "sklearn_version": sklearn.__version__,
        "xgboost_version": xgb.__version__,
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__,
        "joblib_version": joblib.__version__,
    }


def _model_size_bytes(filepath: Path) -> int:
    """Return file size in bytes."""
    return filepath.stat().st_size if filepath.exists() else 0


# ---------------------------------------------------------------------------
# XGBoost sample weight computation (class-imbalance handling)
# ---------------------------------------------------------------------------

def compute_xgb_sample_weights(y_train: np.ndarray) -> np.ndarray:
    """Compute sample weights inversely proportional to class frequency.

    For each class c:
        weight_c = n_samples / (n_classes * n_samples_c)

    This is equivalent to sklearn's class_weight='balanced' behaviour,
    applied explicitly via sample_weight because XGBoost does not
    natively support multiclass class_weight.

    Parameters
    ----------
    y_train : integer-encoded class labels for training data

    Returns
    -------
    sample_weights : array of per-sample weights
    """
    classes, counts = np.unique(y_train, return_counts=True)
    n_samples = len(y_train)
    n_classes = len(classes)
    class_weights = {c: n_samples / (n_classes * cnt) for c, cnt in zip(classes, counts)}
    sample_weights = np.array([class_weights[y] for y in y_train], dtype=np.float64)
    logger.info(
        f"XGBoost sample weights: {n_classes} classes, "
        f"weight range [{min(class_weights.values()):.4f}, {max(class_weights.values()):.4f}]"
    )
    return sample_weights


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------

def fit_scaler(X_train: np.ndarray) -> StandardScaler:
    """Fit a StandardScaler on training data only."""
    scaler = StandardScaler()
    scaler.fit(X_train)
    return scaler


# ---------------------------------------------------------------------------
# Training Functions
# ---------------------------------------------------------------------------

def train_logistic_regression(
    X_train: np.ndarray,
    y_train: np.ndarray,
    seed: int = RANDOM_SEED,
) -> tuple[LogisticRegression, dict]:
    """Train Logistic Regression with class_weight='balanced'.

    Scaling REQUIRED for LR — caller must provide pre-scaled X_train.

    Returns (fitted_model, metadata_dict)
    """
    hyperparams = {
        "max_iter": 1000,
        "solver": "lbfgs",
        "C": 1.0,
        "class_weight": "balanced",
        "random_state": seed,
    }

    model = LogisticRegression(**hyperparams)
    logger.info("Training Logistic Regression (class_weight='balanced')...")
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    train_time = time.perf_counter() - t0
    logger.info(f"Logistic Regression trained in {train_time:.2f}s")

    return model, {
        "model_name": "LogisticRegression",
        "hyperparameters": hyperparams,
        "training_time_seconds": round(train_time, 4),
        "training_rows": len(y_train),
        "scaling_applied": True,
        "class_imbalance_strategy": "class_weight='balanced'",
    }


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    seed: int = RANDOM_SEED,
) -> tuple[RandomForestClassifier, dict]:
    """Train Random Forest with class_weight='balanced_subsample'.

    Scaling NOT required for tree models — caller provides raw features.

    Returns (fitted_model, metadata_dict)
    """
    hyperparams = {
        "n_estimators": 200,
        "max_depth": 20,
        "min_samples_split": 10,
        "class_weight": "balanced_subsample",
        "random_state": seed,
        "n_jobs": -1,
    }

    model = RandomForestClassifier(**hyperparams)
    logger.info("Training Random Forest (class_weight='balanced_subsample')...")
    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    train_time = time.perf_counter() - t0
    logger.info(f"Random Forest trained in {train_time:.2f}s")

    return model, {
        "model_name": "RandomForest",
        "hyperparameters": hyperparams,
        "training_time_seconds": round(train_time, 4),
        "training_rows": len(y_train),
        "scaling_applied": False,
        "class_imbalance_strategy": "class_weight='balanced_subsample'",
    }


def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    seed: int = RANDOM_SEED,
) -> tuple[xgb.XGBClassifier, dict]:
    """Train XGBoost with explicit sample weights for class imbalance.

    Scaling NOT required for tree models — caller provides raw features.

    Returns (fitted_model, metadata_dict)
    """
    n_classes = len(np.unique(y_train))
    hyperparams = {
        "n_estimators": 200,
        "max_depth": 8,
        "learning_rate": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "eval_metric": "mlogloss",
        "tree_method": "hist",
        "random_state": seed,
        "n_jobs": -1,
        "num_class": n_classes,
    }

    model = xgb.XGBClassifier(
        n_estimators=hyperparams["n_estimators"],
        max_depth=hyperparams["max_depth"],
        learning_rate=hyperparams["learning_rate"],
        subsample=hyperparams["subsample"],
        colsample_bytree=hyperparams["colsample_bytree"],
        eval_metric=hyperparams["eval_metric"],
        tree_method=hyperparams["tree_method"],
        random_state=seed,
        n_jobs=-1,
        num_class=n_classes,
    )

    sample_weights = compute_xgb_sample_weights(y_train)

    logger.info("Training XGBoost (explicit balanced sample_weight)...")
    t0 = time.perf_counter()
    model.fit(X_train, y_train, sample_weight=sample_weights)
    train_time = time.perf_counter() - t0
    logger.info(f"XGBoost trained in {train_time:.2f}s")

    # Document weight statistics
    classes, counts = np.unique(y_train, return_counts=True)
    weight_doc = {
        int(c): {
            "count": int(cnt),
            "weight": round(float(len(y_train) / (len(classes) * cnt)), 6),
        }
        for c, cnt in zip(classes, counts)
    }

    return model, {
        "model_name": "XGBoost",
        "hyperparameters": hyperparams,
        "training_time_seconds": round(train_time, 4),
        "training_rows": len(y_train),
        "scaling_applied": False,
        "class_imbalance_strategy": "explicit_sample_weight (balanced, inversely proportional to class frequency)",
        "sample_weight_per_class": weight_doc,
    }


def train_isolation_forest(
    X_train_benign: np.ndarray,
    seed: int = RANDOM_SEED,
) -> tuple[IsolationForest, dict]:
    """Train Isolation Forest on BENIGN traffic only.

    Scaling is applied (caller provides pre-scaled data).

    Returns (fitted_model, metadata_dict)
    """
    hyperparams = {
        "n_estimators": 200,
        "max_samples": 0.5,
        "contamination": "auto",
        "random_state": seed,
        "n_jobs": -1,
    }

    model = IsolationForest(**hyperparams)
    logger.info(f"Training Isolation Forest on {len(X_train_benign):,} benign flows...")
    t0 = time.perf_counter()
    model.fit(X_train_benign)
    train_time = time.perf_counter() - t0
    logger.info(f"Isolation Forest trained in {train_time:.2f}s")

    return model, {
        "model_name": "IsolationForest",
        "hyperparameters": hyperparams,
        "training_time_seconds": round(train_time, 4),
        "training_rows": len(X_train_benign),
        "training_data": "BENIGN-only traffic",
        "scaling_applied": True,
        "class_imbalance_strategy": "N/A (unsupervised, trained on benign only)",
    }


# ---------------------------------------------------------------------------
# Evaluation Functions
# ---------------------------------------------------------------------------

def evaluate_supervised_model(
    model: Any,
    X: np.ndarray,
    y: np.ndarray,
    class_names: list[str],
) -> tuple[np.ndarray, np.ndarray | None, float]:
    """Run prediction and probability estimation, return (y_pred, y_proba, inference_seconds).

    Parameters
    ----------
    model : fitted sklearn/xgboost classifier
    X : feature matrix
    y : true labels (for shape reference, not used in prediction)
    class_names : ordered class names

    Returns
    -------
    y_pred, y_proba, inference_time
    """
    t0 = time.perf_counter()
    y_pred = model.predict(X)
    try:
        y_proba = model.predict_proba(X)
    except Exception:
        y_proba = None
    inference_time = time.perf_counter() - t0
    logger.info(
        f"Inference on {len(X):,} samples in {inference_time:.4f}s "
        f"({len(X) / inference_time:.0f} samples/sec)"
    )
    return y_pred, y_proba, inference_time


def evaluate_isolation_forest(
    model: IsolationForest,
    X: np.ndarray,
) -> tuple[np.ndarray, float]:
    """Run IF decision_function, return (anomaly_scores, inference_seconds).

    decision_function returns higher values for inliers (more normal),
    lower/negative for anomalies. This matches scikit-learn 1.x convention.

    Returns
    -------
    anomaly_scores, inference_time
    """
    t0 = time.perf_counter()
    anomaly_scores = model.decision_function(X)
    inference_time = time.perf_counter() - t0
    logger.info(
        f"IF inference on {len(X):,} samples in {inference_time:.4f}s "
        f"({len(X) / inference_time:.0f} samples/sec)"
    )
    return anomaly_scores, inference_time


# ---------------------------------------------------------------------------
# Artifact Serialization
# ---------------------------------------------------------------------------

def save_model_artifact(
    model: Any,
    scaler: StandardScaler | None,
    label_encoder: LabelEncoder,
    metadata: dict,
    filepath: str | Path,
) -> int:
    """Save model artifact bundle via joblib.

    Returns file size in bytes.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    artifact = {
        "model": model,
        "scaler": scaler,
        "label_encoder": label_encoder,
        "metadata": metadata,
    }
    joblib.dump(artifact, path, compress=3)
    size = _model_size_bytes(path)
    logger.info(f"Saved model artifact to {path} ({size:,} bytes)")
    return size


def load_model_artifact(filepath: str | Path) -> dict:
    """Load a saved model artifact bundle.

    Returns dict with keys: model, scaler, label_encoder, metadata
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Model artifact not found: {path}")
    artifact = joblib.load(path)
    logger.info(f"Loaded model artifact from {path}")
    return artifact
