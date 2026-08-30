"""Duplicate flow analysis across the CICIDS2017 dataset.

Investigates exact duplicate network flows across all numeric features,
per-class duplicate rates, cross-label collisions, and cross-file leakage.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import numpy as np
import pandas as pd

from ml.experiments.config import (
    DATA_DIR,
    DOCS_EXP_DIR,
    REPORTS_DIR,
    UNIQUE_FEATURE_NAMES,
)
from ml.experiments.data_loader import load_dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def run_duplicate_analysis(
    df: pd.DataFrame | None = None,
    save_reports: bool = True,
) -> dict:
    """Perform comprehensive duplicate analysis on the cleaned CICIDS2017 dataset."""
    if df is None:
        logger.info("Loading full dataset across 8 CSV files...")
        df, _ = load_dataset(reject_non_finite=True)

    total_rows = len(df)
    logger.info(f"Total cleaned rows: {total_rows:,}")

    feature_cols = [c for c in df.columns if c in UNIQUE_FEATURE_NAMES]
    logger.info(f"Analyzing duplicates across {len(feature_cols)} feature columns...")

    # 1. Exact duplicates across features only
    feature_dups_mask = df.duplicated(subset=feature_cols, keep="first")
    feature_dups_count = int(feature_dups_mask.sum())
    unique_feature_rows = total_rows - feature_dups_count
    feature_dup_pct = (feature_dups_count / total_rows) * 100.0

    # 2. Exact duplicates across features AND raw_label
    full_dups_mask = df.duplicated(subset=feature_cols + ["raw_label"], keep="first")
    full_dups_count = int(full_dups_mask.sum())
    full_dup_pct = (full_dups_count / total_rows) * 100.0

    # 3. Cross-label collisions (same features, different label)
    cross_label_collision_count = feature_dups_count - full_dups_count
    collision_details = []

    if cross_label_collision_count > 0:
        logger.info(f"Found {cross_label_collision_count} cross-label collisions. Sampling collision examples...")
        colliding_mask = feature_dups_mask != full_dups_mask
        colliding_indices = df.index[colliding_mask]
        
        # Sample distinct collision rows
        for idx in colliding_indices[:10]:
            collision_details.append({
                "index": int(idx),
                "raw_label": df.loc[idx, "raw_label"],
                "attack_family": df.loc[idx, "attack_family"],
                "destination_port": int(df.loc[idx, "destination_port"]) if "destination_port" in df.columns else None,
                "flow_duration_ms": float(df.loc[idx, "flow_duration_ms"]) if "flow_duration_ms" in df.columns else None,
                "source_file": df.loc[idx, "source_file"],
            })

    # 4. Per-Class Duplicate Breakdown (Vectorized index grouping)
    logger.info("Computing per-class duplicate breakdown...")
    class_breakdown = {}
    for label, grp_indices in df.groupby("raw_label").groups.items():
        cls_total = len(grp_indices)
        cls_dups = int(feature_dups_mask.iloc[grp_indices].sum())
        cls_unique = cls_total - cls_dups
        cls_dup_pct = (cls_dups / cls_total) * 100.0 if cls_total > 0 else 0.0
        family = df.loc[grp_indices[0], "attack_family"]
        class_breakdown[label] = {
            "attack_family": family,
            "total_rows": cls_total,
            "unique_rows": cls_unique,
            "duplicate_rows": cls_dups,
            "duplicate_percentage": round(cls_dup_pct, 4),
        }

    # 5. Per-File Duplicate Breakdown (Vectorized index grouping)
    logger.info("Computing per-file duplicate breakdown...")
    file_breakdown = {}
    for fname, grp_indices in df.groupby("source_file").groups.items():
        f_total = len(grp_indices)
        f_dups = int(feature_dups_mask.iloc[grp_indices].sum())
        f_unique = f_total - f_dups
        f_dup_pct = (f_dups / f_total) * 100.0 if f_total > 0 else 0.0
        file_breakdown[fname] = {
            "total_rows": f_total,
            "unique_rows": f_unique,
            "duplicate_rows": f_dups,
            "duplicate_percentage": round(f_dup_pct, 4),
        }

    results = {
        "dataset_summary": {
            "total_cleaned_rows": total_rows,
            "unique_feature_vectors": unique_feature_rows,
            "total_duplicate_rows": feature_dups_count,
            "duplicate_percentage": round(feature_dup_pct, 4),
            "feature_and_label_duplicates": full_dups_count,
            "cross_label_collision_rows": cross_label_collision_count,
        },
        "class_breakdown": class_breakdown,
        "file_breakdown": file_breakdown,
        "sample_collisions": collision_details[:10],
    }

    if save_reports:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        json_path = REPORTS_DIR / "duplicate_analysis.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Saved duplicate analysis JSON to {json_path}")

        DOCS_EXP_DIR.mkdir(parents=True, exist_ok=True)
        md_path = DOCS_EXP_DIR / "duplicate_analysis_report.md"
        generate_markdown_report(results, md_path)
        logger.info(f"Saved duplicate analysis Markdown report to {md_path}")

    return results


def generate_markdown_report(results: dict, output_path: Path) -> None:
    """Generate a research-grade Markdown duplicate analysis report."""
    summary = results["dataset_summary"]
    cls_data = results["class_breakdown"]
    file_data = results["file_breakdown"]

    md = []
    md.append("# CICIDS2017 Flow Duplicate & Data Quality Analysis Report\n")
    md.append("## 1. Executive Summary\n")
    md.append(f"- **Total Cleaned Flows Analyzed:** {summary['total_cleaned_rows']:,}")
    md.append(f"- **Unique Flow Feature Vectors:** {summary['unique_feature_vectors']:,}")
    md.append(f"- **Exact Duplicate Flows (Feature-level):** {summary['total_duplicate_rows']:,} ({summary['duplicate_percentage']:.2f}%)")
    md.append(f"- **Feature & Label Duplicate Flows:** {summary['feature_and_label_duplicates']:,}")
    md.append(f"- **Cross-Label Feature Collisions (Ambiguous Flows):** {summary['cross_label_collision_rows']:,}\n")

    md.append("### Key Methodological Implications")
    md.append("1. **In-Session Burst Replication:** Network traffic (especially PortScan, DoS Hulk, DDoS, and repeated Benign background polling) frequently generates identical flow-level statistical summaries within short burst intervals.")
    md.append("2. **Train/Test Contamination Risk under Random Splitting:** When applying standard row-level random splitting (e.g. 70/15/15), identical flow feature vectors will randomly land in both Train and Test sets. This inflates conventional evaluation metrics (memorization of repeated burst patterns).")
    md.append("3. **Protocol Distinction:** Protocol A (70/15/15 stratified random split) reflects conventional baseline literature results, whereas Protocol B (Capture/Day-aware cross-evaluation) evaluates true cross-capture generalization where same-burst replication across splits is structurally prevented.\n")

    md.append("## 2. Per-Class Duplicate Breakdown\n")
    md.append("| Raw Label | Attack Family | Total Flows | Unique Flows | Duplicate Flows | Duplicate Rate (%) |")
    md.append("| :--- | :--- | :---: | :---: | :---: | :---: |")

    sorted_classes = sorted(cls_data.items(), key=lambda x: x[1]["total_rows"], reverse=True)
    for label, stats in sorted_classes:
        md.append(
            f"| `{label}` | `{stats['attack_family']}` | {stats['total_rows']:,} | "
            f"{stats['unique_rows']:,} | {stats['duplicate_rows']:,} | {stats['duplicate_percentage']:.2f}% |"
        )
    md.append("")

    md.append("## 3. Per-Capture File Duplicate Breakdown\n")
    md.append("| Capture File | Total Flows | Unique Flows | Duplicate Flows | Duplicate Rate (%) |")
    md.append("| :--- | :---: | :---: | :---: | :---: |")

    for fname, stats in file_data.items():
        md.append(
            f"| `{fname}` | {stats['total_rows']:,} | {stats['unique_rows']:,} | "
            f"{stats['duplicate_rows']:,} | {stats['duplicate_percentage']:.2f}% |"
        )
    md.append("")

    md.append("## 4. Cross-Label Collision Analysis\n")
    if summary["cross_label_collision_rows"] == 0:
        md.append("No cross-label collisions detected. All duplicate feature vectors possess identical ground-truth labels.\n")
    else:
        md.append(f"Detected **{summary['cross_label_collision_rows']:,} flow instances** where identical feature vectors are associated with contradictory ground-truth labels (e.g. Benign vs. Attack).")
        md.append("This occurs when a minimal 0-payload TCP handshake or DNS lookup appears identically in background benign traffic and attack windows.\n")
        md.append("### Sample Collision Records:")
        for idx, col in enumerate(results.get("sample_collisions", [])):
            md.append(f"- **Sample {idx + 1}**: index `{col['index']}`, label `{col['raw_label']}` (`{col['attack_family']}`), port `{col['destination_port']}`, duration `{col['flow_duration_ms']} ms` in `{col['source_file']}`")
        md.append("")

    md.append("## 5. Duplicate Handling Policy for Stage 3 Baselines\n")
    md.append("- **Protocol A (Standard Stratified Split):** To remain consistent with canonical baseline literature and reproducible capstone comparisons, duplicate flows are retained during 70/15/15 random splitting, but the exact overlap count between Train and Test sets is explicitly quantified and reported.")
    md.append("- **Protocol B (Day-Aware Evaluation):** Training is performed exclusively on Monday-Wednesday captures, and evaluation is tested on Thursday-Friday captures. Cross-capture duplicate contamination is thereby eliminated for unseen attack families.")
    md.append("- **Ablation Benchmark:** Feature importance and baseline model evaluations will document the impact of duplicate flows on accuracy vs. generalization.\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
