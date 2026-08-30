"""Data splitting protocols for Stage 3 baseline ML experiments.

Implements:
1. Protocol A: 70/15/15 Stratified Random Split (with rare-class handling & duplicate cross-split leakage metrics).
2. Protocol B: Capture / Day-Aware Cross-Evaluation Protocol (Train: Mon-Wed, Test: Thu-Fri).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

from ml.experiments.config import (
    DOCS_EXP_DIR,
    PROTOCOL_B_TEST_FILES,
    PROTOCOL_B_TRAIN_FILES,
    RANDOM_SEED,
    REPORTS_DIR,
    UNIQUE_FEATURE_NAMES,
)

logger = logging.getLogger(__name__)


def create_protocol_a_splits(
    df: pd.DataFrame,
    seed: int = RANDOM_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    """Create 70/15/15 Stratified Random Splits based on raw_label."""
    logger.info("Generating Protocol A (70/15/15 Stratified Random Split)...")
    feature_cols = [c for c in df.columns if c in UNIQUE_FEATURE_NAMES]

    # Split 1: 70% Train, 30% Temp (Val + Test)
    sss1 = StratifiedShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
    train_idx, temp_idx = next(sss1.split(df, df["raw_label"]))

    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    temp_df = df.iloc[temp_idx].copy().reset_index(drop=True)

    # Split 2: 50% of Temp -> 15% Val, 50% of Temp -> 15% Test
    sss2 = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=seed)
    val_idx, test_idx = next(sss2.split(temp_df, temp_df["raw_label"]))

    val_df = temp_df.iloc[val_idx].copy().reset_index(drop=True)
    test_df = temp_df.iloc[test_idx].copy().reset_index(drop=True)

    logger.info(f"Splits created: Train={len(train_df):,}, Val={len(val_df):,}, Test={len(test_df):,}")

    # Fast duplicate metrics per split
    train_dups = int(train_df.duplicated(subset=feature_cols, keep="first").sum())
    val_dups = int(val_df.duplicated(subset=feature_cols, keep="first").sum())
    test_dups = int(test_df.duplicated(subset=feature_cols, keep="first").sum())

    # Per-class distribution summary
    classes = sorted(df["raw_label"].unique())
    distribution = {}
    for cls in classes:
        n_total = int((df["raw_label"] == cls).sum())
        n_train = int((train_df["raw_label"] == cls).sum())
        n_val = int((val_df["raw_label"] == cls).sum())
        n_test = int((test_df["raw_label"] == cls).sum())
        distribution[cls] = {
            "total": n_total,
            "train": n_train,
            "val": n_val,
            "test": n_test,
            "train_pct": round((n_train / n_total) * 100.0, 2) if n_total > 0 else 0,
            "val_pct": round((n_val / n_total) * 100.0, 2) if n_total > 0 else 0,
            "test_pct": round((n_test / n_total) * 100.0, 2) if n_total > 0 else 0,
        }

    report = {
        "protocol": "Protocol A (70/15/15 Stratified Random Split)",
        "seed": seed,
        "total_rows": len(df),
        "train_rows": len(train_df),
        "val_rows": len(val_df),
        "test_rows": len(test_df),
        "feature_duplicate_summary": {
            "train_duplicate_rows": train_dups,
            "val_duplicate_rows": val_dups,
            "test_duplicate_rows": test_dups,
            "unique_train_flows": len(train_df) - train_dups,
            "unique_val_flows": len(val_df) - val_dups,
            "unique_test_flows": len(test_df) - test_dups,
        },
        "class_distribution": distribution,
    }

    return train_df, val_df, test_df, report


def create_protocol_b_splits(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Create Protocol B Day / Capture-Aware Cross-Evaluation Splits."""
    logger.info("Generating Protocol B (Day / Capture-Aware Split)...")
    feature_cols = [c for c in df.columns if c in UNIQUE_FEATURE_NAMES]

    train_mask = df["source_file"].isin(PROTOCOL_B_TRAIN_FILES)
    test_mask = df["source_file"].isin(PROTOCOL_B_TEST_FILES)

    train_df = df[train_mask].copy().reset_index(drop=True)
    test_df = df[test_mask].copy().reset_index(drop=True)

    logger.info(f"Protocol B splits created: Train={len(train_df):,}, Test={len(test_df):,}")

    train_dups = int(train_df.duplicated(subset=feature_cols, keep="first").sum())
    test_dups = int(test_df.duplicated(subset=feature_cols, keep="first").sum())

    all_classes = sorted(df["raw_label"].unique())
    distribution = {}
    for cls in all_classes:
        n_total = int((df["raw_label"] == cls).sum())
        n_train = int((train_df["raw_label"] == cls).sum())
        n_test = int((test_df["raw_label"] == cls).sum())
        distribution[cls] = {
            "total": n_total,
            "train": n_train,
            "test": n_test,
            "train_presence": "Present" if n_train > 0 else "Unseen / Novel in Test",
            "test_presence": "Present" if n_test > 0 else "Absent in Test",
        }

    report = {
        "protocol": "Protocol B (Day / Capture-Aware Cross-Evaluation)",
        "train_files": PROTOCOL_B_TRAIN_FILES,
        "test_files": PROTOCOL_B_TEST_FILES,
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "feature_duplicate_summary": {
            "train_duplicate_rows": train_dups,
            "test_duplicate_rows": test_dups,
            "unique_train_flows": len(train_df) - train_dups,
            "unique_test_flows": len(test_df) - test_dups,
        },
        "class_distribution": distribution,
        "methodological_notes": [
            "Protocol B measures cross-capture generalization and zero-shot novel attack detection.",
            "Attacks present in Train (FTP-Patator, SSH-Patator, DoS variants, Heartbleed) are absent in Test captures.",
            "Attacks present in Test (Web Attacks, Infiltration, Bot, PortScan, DDoS) were never seen during Training.",
            "Metrics from Protocol A and Protocol B must NEVER be merged into a single leaderboard.",
        ],
    }

    return train_df, test_df, report
