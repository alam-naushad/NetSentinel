"""Metric computation utilities for Stage 3 baseline ML experiments.

Provides functions for:
- Multiclass classification metrics (Protocol A supervised)
- Binary detection metrics (anomaly detection)
- Isolation Forest threshold-calibrated metrics
- Open-set / OOD metrics (Protocol B Regime B)
- JSON-safe serialization helpers
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_serializable(obj: Any) -> Any:
    """Recursively convert numpy types to Python-native for JSON."""
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(v) for v in obj]
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, np.bool_):
        return bool(obj)
    return obj


def save_metrics_json(metrics: dict, filepath: str | Path) -> None:
    """Save metrics dict as JSON, creating parent dirs as needed."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(_to_serializable(metrics), f, indent=2)
    logger.info(f"Saved metrics to {path}")


# ---------------------------------------------------------------------------
# Multiclass Classification Metrics (Protocol A supervised models)
# ---------------------------------------------------------------------------

def compute_multiclass_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray | None,
    class_names: list[str],
) -> dict:
    """Compute comprehensive multiclass classification metrics.

    Parameters
    ----------
    y_true : array of integer class indices
    y_pred : array of predicted class indices
    y_proba : (n_samples, n_classes) probability matrix, or None
    class_names : ordered list of class name strings

    Returns
    -------
    dict with per_class, macro, weighted, confusion_matrix, binary_fpr, roc_auc, pr_auc
    """
    n_classes = len(class_names)

    # Per-class precision / recall / F1 / support
    report = classification_report(
        y_true, y_pred,
        labels=list(range(n_classes)),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    per_class = {}
    for cls_name in class_names:
        if cls_name in report:
            per_class[cls_name] = {
                "precision": round(report[cls_name]["precision"], 6),
                "recall": round(report[cls_name]["recall"], 6),
                "f1_score": round(report[cls_name]["f1-score"], 6),
                "support": int(report[cls_name]["support"]),
            }

    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    accuracy = float(accuracy_score(y_true, y_pred))

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred, labels=list(range(n_classes)))

    # Binary FPR: treat BENIGN (index 0) as negative, all attacks as positive
    benign_idx = class_names.index("BENIGN") if "BENIGN" in class_names else 0
    y_true_binary = (y_true != benign_idx).astype(int)
    y_pred_binary = (y_pred != benign_idx).astype(int)

    # FP = benign predicted as attack, TN = benign predicted as benign
    fp = int(((y_true_binary == 0) & (y_pred_binary == 1)).sum())
    tn = int(((y_true_binary == 0) & (y_pred_binary == 0)).sum())
    binary_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # ROC-AUC and PR-AUC (OVR, macro)
    roc_auc_ovr = None
    pr_auc_macro = None
    if y_proba is not None and y_proba.shape[1] == n_classes:
        try:
            roc_auc_ovr = float(roc_auc_score(
                y_true, y_proba,
                multi_class="ovr",
                average="macro",
                labels=list(range(n_classes)),
            ))
        except ValueError:
            roc_auc_ovr = None

        # Binary ROC-AUC (attack vs benign)
        try:
            attack_prob = 1.0 - y_proba[:, benign_idx]
            binary_roc_auc = float(roc_auc_score(y_true_binary, attack_prob))
        except ValueError:
            binary_roc_auc = None

        # Binary PR-AUC
        try:
            binary_pr_auc = float(average_precision_score(y_true_binary, attack_prob))
        except ValueError:
            binary_pr_auc = None
    else:
        binary_roc_auc = None
        binary_pr_auc = None

    return {
        "accuracy": round(accuracy, 6),
        "macro_f1": round(macro_f1, 6),
        "weighted_f1": round(weighted_f1, 6),
        "binary_fpr": round(binary_fpr, 6),
        "roc_auc_ovr_macro": round(roc_auc_ovr, 6) if roc_auc_ovr is not None else None,
        "binary_roc_auc": round(binary_roc_auc, 6) if binary_roc_auc is not None else None,
        "binary_pr_auc": round(binary_pr_auc, 6) if binary_pr_auc is not None else None,
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labels": class_names,
    }


# ---------------------------------------------------------------------------
# Isolation Forest Metrics
# ---------------------------------------------------------------------------

def calibrate_isolation_forest_threshold(
    benign_scores: np.ndarray,
    fpr_targets: Sequence[float] = (0.01, 0.05),
) -> dict[float, float]:
    """Calibrate anomaly score thresholds from benign validation data.

    In scikit-learn's IsolationForest, decision_function returns scores where
    *lower* (more negative) values indicate more anomalous samples.
    score_samples() returns the raw anomaly score of the isolating forest.

    We calibrate thresholds such that at most `fpr_target` fraction of
    benign validation samples are flagged as anomalous (score < threshold).

    Parameters
    ----------
    benign_scores : anomaly scores (decision_function output) for benign validation flows
    fpr_targets : desired false-positive rates

    Returns
    -------
    dict mapping fpr_target -> threshold value
    """
    thresholds = {}
    for fpr_target in fpr_targets:
        # We want the threshold such that P(score < threshold | benign) = fpr_target
        # This means threshold = quantile(fpr_target) of benign scores
        threshold = float(np.quantile(benign_scores, fpr_target))
        thresholds[fpr_target] = threshold
    return thresholds


def compute_isolation_forest_metrics(
    y_true_binary: np.ndarray,
    anomaly_scores: np.ndarray,
    thresholds: dict[float, float],
) -> dict:
    """Compute IF metrics at calibrated thresholds.

    Parameters
    ----------
    y_true_binary : 1 = attack, 0 = benign
    anomaly_scores : decision_function output (lower = more anomalous)
    thresholds : {fpr_target: threshold_value}

    Returns
    -------
    dict with per-threshold metrics + binary ROC-AUC
    """
    # For ROC-AUC: negate scores so that higher = more anomalous
    neg_scores = -anomaly_scores

    try:
        roc_auc = float(roc_auc_score(y_true_binary, neg_scores))
    except ValueError:
        roc_auc = None

    try:
        pr_auc = float(average_precision_score(y_true_binary, neg_scores))
    except ValueError:
        pr_auc = None

    threshold_results = {}
    for fpr_target, thresh in thresholds.items():
        # Anomalous if score < threshold (decision_function convention)
        y_pred = (anomaly_scores < thresh).astype(int)

        n_benign = int((y_true_binary == 0).sum())
        n_attack = int((y_true_binary == 1).sum())
        tp = int(((y_true_binary == 1) & (y_pred == 1)).sum())
        fp = int(((y_true_binary == 0) & (y_pred == 1)).sum())
        tn = int(((y_true_binary == 0) & (y_pred == 0)).sum())
        fn = int(((y_true_binary == 1) & (y_pred == 0)).sum())

        actual_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        threshold_results[str(fpr_target)] = {
            "threshold_value": round(float(thresh), 6),
            "target_fpr": fpr_target,
            "actual_fpr": round(actual_fpr, 6),
            "recall": round(recall, 6),
            "precision": round(precision, 6),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "n_benign": n_benign,
            "n_attack": n_attack,
        }

    return {
        "roc_auc": round(roc_auc, 6) if roc_auc is not None else None,
        "pr_auc": round(pr_auc, 6) if pr_auc is not None else None,
        "threshold_results": threshold_results,
    }


# ---------------------------------------------------------------------------
# Open-Set / OOD Metrics (Protocol B Regime B)
# ---------------------------------------------------------------------------

def compute_open_set_metrics(
    y_true_families: np.ndarray,
    y_pred_indices: np.ndarray,
    y_proba: np.ndarray | None,
    class_names: list[str],
    unseen_families: list[str],
) -> dict:
    """Compute open-set evaluation metrics for unseen attack families.

    Parameters
    ----------
    y_true_families : string array of true attack_family labels
    y_pred_indices : integer array of predicted class indices
    y_proba : probability matrix (n_samples, n_classes)
    class_names : ordered class names from the training label encoder
    unseen_families : list of family names not seen during training

    Returns
    -------
    dict with NADR, escape rate, per-family detection, prediction distribution
    """
    benign_idx = class_names.index("BENIGN") if "BENIGN" in class_names else 0

    results = {}
    for family in unseen_families:
        mask = y_true_families == family
        n_total = int(mask.sum())
        if n_total == 0:
            continue

        preds_for_family = y_pred_indices[mask]

        # NADR: fraction predicted as any class other than BENIGN
        n_detected = int((preds_for_family != benign_idx).sum())
        nadr = n_detected / n_total
        escape_rate = 1.0 - nadr

        # Prediction distribution: where does this family get classified?
        pred_dist = {}
        for cls_idx, cls_name in enumerate(class_names):
            count = int((preds_for_family == cls_idx).sum())
            if count > 0:
                pred_dist[cls_name] = {
                    "count": count,
                    "fraction": round(count / n_total, 6),
                }

        results[family] = {
            "n_total": n_total,
            "n_detected_as_attack": n_detected,
            "n_escaped_as_benign": n_total - n_detected,
            "nadr": round(nadr, 6),
            "escape_rate": round(escape_rate, 6),
            "prediction_distribution": pred_dist,
        }

    # Aggregate across all unseen families
    total_unseen = sum(r["n_total"] for r in results.values())
    total_detected = sum(r["n_detected_as_attack"] for r in results.values())
    aggregate_nadr = total_detected / total_unseen if total_unseen > 0 else 0.0

    # Open-Set ROC-AUC: binary discrimination between test benign and unseen attacks
    # using P(attack) = 1 - P(BENIGN)
    open_set_roc_auc = None
    open_set_pr_auc = None
    if y_proba is not None:
        attack_prob = 1.0 - y_proba[:, benign_idx]
        # Create binary labels: 0 = BENIGN, 1 = unseen attack
        is_unseen = np.isin(y_true_families, unseen_families).astype(int)
        is_benign = (y_true_families == "BENIGN").astype(int)
        eval_mask = (is_unseen == 1) | (is_benign == 1)

        if eval_mask.sum() > 0:
            y_binary = is_unseen[eval_mask]
            scores = attack_prob[eval_mask]
            try:
                open_set_roc_auc = float(roc_auc_score(y_binary, scores))
            except ValueError:
                pass
            try:
                open_set_pr_auc = float(average_precision_score(y_binary, scores))
            except ValueError:
                pass

    return {
        "aggregate_nadr": round(aggregate_nadr, 6),
        "aggregate_escape_rate": round(1.0 - aggregate_nadr, 6),
        "total_unseen_flows": total_unseen,
        "total_detected": total_detected,
        "open_set_roc_auc": round(open_set_roc_auc, 6) if open_set_roc_auc is not None else None,
        "open_set_pr_auc": round(open_set_pr_auc, 6) if open_set_pr_auc is not None else None,
        "per_family": results,
    }


# ---------------------------------------------------------------------------
# Protocol B Regime A: Known-Class Cross-Capture Generalization
# ---------------------------------------------------------------------------

def compute_known_class_generalization_metrics(
    y_true_families: np.ndarray,
    y_pred_indices: np.ndarray,
    class_names: list[str],
) -> dict:
    """Compute metrics on BENIGN test flows only (cross-capture FPR).

    Parameters
    ----------
    y_true_families : string array of true attack_family labels
    y_pred_indices : integer array of predicted class indices
    class_names : ordered class names

    Returns
    -------
    dict with FPR, TNR/specificity on benign test flows
    """
    benign_idx = class_names.index("BENIGN") if "BENIGN" in class_names else 0
    benign_mask = y_true_families == "BENIGN"
    n_benign = int(benign_mask.sum())

    if n_benign == 0:
        return {"n_benign": 0, "fpr": None, "tnr": None}

    preds_benign = y_pred_indices[benign_mask]
    n_misclassified = int((preds_benign != benign_idx).sum())
    fpr = n_misclassified / n_benign
    tnr = 1.0 - fpr

    # Where are false positives classified?
    fp_dist = {}
    for cls_idx, cls_name in enumerate(class_names):
        if cls_idx == benign_idx:
            continue
        count = int((preds_benign == cls_idx).sum())
        if count > 0:
            fp_dist[cls_name] = count

    return {
        "n_benign_test_flows": n_benign,
        "n_false_positives": n_misclassified,
        "n_true_negatives": n_benign - n_misclassified,
        "fpr": round(fpr, 6),
        "tnr_specificity": round(tnr, 6),
        "false_positive_distribution": fp_dist,
    }
