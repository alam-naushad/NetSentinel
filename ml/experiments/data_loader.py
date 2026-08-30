"""Data loader and pre-validation utilities for CICIDS2017 dataset."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence
import numpy as np
import pandas as pd

from ml.experiments.config import (
    DATA_DIR,
    FEATURE_NAME_MAP,
    RAW_CSV_FILES,
    RAW_LABEL_TO_FAMILY,
    UNIQUE_FEATURE_NAMES,
)

logger = logging.getLogger(__name__)


def normalise_label_string(raw: str) -> str:
    """Clean and standardise raw label string, resolving encoding anomalies."""
    if not isinstance(raw, str):
        return "UNKNOWN"
    cleaned = raw.strip().replace("", "–").replace("�", "")
    # Unify any remaining non-standard dash characters
    cleaned = cleaned.replace(" - ", " – ").replace(" -- ", " – ")
    if cleaned in RAW_LABEL_TO_FAMILY:
        return cleaned
    # Fallback normalisation for slight spacing differences
    norm = " ".join(cleaned.split())
    for k in RAW_LABEL_TO_FAMILY:
        if " ".join(k.split()) == norm:
            return k
    return cleaned


def load_single_csv(
    file_path: Path | str,
    drop_duplicate_header_col: bool = True,
    reject_non_finite: bool = True,
) -> tuple[pd.DataFrame, dict]:
    """Load, clean, and validate a single CICIDS2017 CSV file.

    Returns:
        tuple of (cleaned_df, report_dict)
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")

    # Read CSV with encoding error replacement
    df = pd.read_csv(
        path,
        encoding="utf-8-sig",
        low_memory=False,
    )
    total_raw_rows = len(df)

    # Rename columns using schema map
    renamed_cols = {}
    for col in df.columns:
        if col in FEATURE_NAME_MAP:
            renamed_cols[col] = FEATURE_NAME_MAP[col]
        elif col.strip() == "Label":
            renamed_cols[col] = "raw_label"
        elif col.strip().lower() == "label":
            renamed_cols[col] = "raw_label"

    df = df.rename(columns=renamed_cols)

    # Drop the duplicate column 55 if present and requested
    if drop_duplicate_header_col and "fwd_header_length_dup" in df.columns:
        df = df.drop(columns=["fwd_header_length_dup"])

    # Normalise raw_label
    if "raw_label" in df.columns:
        df["raw_label"] = df["raw_label"].astype(str).apply(normalise_label_string)
        df["attack_family"] = df["raw_label"].map(RAW_LABEL_TO_FAMILY).fillna("UNKNOWN")
        df["is_attack"] = (df["raw_label"] != "BENIGN").astype(np.int32)
    else:
        raise ValueError(f"Missing Label column in {path.name}")

    # Track source file for cross-capture tracing
    df["source_file"] = path.name

    # Identify numeric features
    feature_cols = [c for c in df.columns if c in UNIQUE_FEATURE_NAMES]

    # Convert numeric features to float64 for validation
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    rejection_reasons = {
        "nan_or_inf": 0,
        "negative_duration": 0,
        "negative_packets": 0,
        "invalid_port": 0,
    }

    if reject_non_finite:
        # Check non-finites (NaN, Inf, -Inf) across numeric features
        is_finite_mask = np.isfinite(df[feature_cols].values).all(axis=1)
        rejection_reasons["nan_or_inf"] = int((~is_finite_mask).sum())

        valid_mask = is_finite_mask.copy()

        # Check negative durations
        if "flow_duration_ms" in df.columns:
            dur_valid = df["flow_duration_ms"] >= 0
            rejection_reasons["negative_duration"] = int((valid_mask & (~dur_valid)).sum())
            valid_mask = valid_mask & dur_valid

        # Check negative packet counts
        if "total_forward_packets" in df.columns and "total_backward_packets" in df.columns:
            fwd_p_valid = df["total_forward_packets"] >= 0
            bwd_p_valid = df["total_backward_packets"] >= 0
            pkt_valid = fwd_p_valid & bwd_p_valid
            rejection_reasons["negative_packets"] = int((valid_mask & (~pkt_valid)).sum())
            valid_mask = valid_mask & pkt_valid

        # Check port range [0, 65535]
        if "destination_port" in df.columns:
            port_valid = (df["destination_port"] >= 0) & (df["destination_port"] <= 65535)
            rejection_reasons["invalid_port"] = int((valid_mask & (~port_valid)).sum())
            valid_mask = valid_mask & port_valid

        accepted_df = df[valid_mask].copy()
    else:
        accepted_df = df.copy()

    # Downcast numeric features to float32 to conserve memory
    for col in feature_cols:
        accepted_df[col] = accepted_df[col].astype(np.float32)

    total_rejected = total_raw_rows - len(accepted_df)
    report = {
        "file": path.name,
        "total_raw_rows": total_raw_rows,
        "accepted_rows": len(accepted_df),
        "rejected_rows": total_rejected,
        "rejection_reasons": rejection_reasons,
        "label_distribution": accepted_df["raw_label"].value_counts().to_dict(),
        "family_distribution": accepted_df["attack_family"].value_counts().to_dict(),
    }

    return accepted_df, report


def load_dataset(
    file_list: Sequence[str] | None = None,
    data_dir: Path = DATA_DIR,
    reject_non_finite: bool = True,
) -> tuple[pd.DataFrame, list[dict]]:
    """Load and concatenate all or selected CSV files.

    Returns:
        tuple of (full_df, list_of_reports)
    """
    if file_list is None:
        file_list = RAW_CSV_FILES

    dfs = []
    reports = []

    for fname in file_list:
        fpath = data_dir / fname
        df, rep = load_single_csv(fpath, reject_non_finite=reject_non_finite)
        dfs.append(df)
        reports.append(rep)

    full_df = pd.concat(dfs, ignore_index=True)
    return full_df, reports
