"""Execution driver for Data Quality, Duplicate, and Feature-Quality Analysis.

Executes:
1. Complete dataset ingestion and validation across all 8 CSV captures.
2. Exact duplicate flow profiling, per-class breakdown, and cross-label collision checks.
3. Protocol A (70/15/15 Stratified Random) and Protocol B (Capture/Day-Aware) split generation.
4. Feature quality analysis strictly fitted on X_train (variance filter, collinearity pruning, tree/MI ranking).
5. Generation of research reports in docs/experiments/ and artifacts/reports/.
"""

import json
import logging
import time
from pathlib import Path
import pandas as pd

from ml.experiments.config import (
    DATA_DIR,
    DOCS_EXP_DIR,
    RANDOM_SEED,
    REPORTS_DIR,
)
from ml.experiments.data_loader import load_dataset
from ml.experiments.duplicate_analysis import run_duplicate_analysis
from ml.experiments.feature_quality import run_feature_quality_analysis
from ml.experiments.split_data import create_protocol_a_splits, create_protocol_b_splits

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    start_time = time.time()
    logger.info("=" * 70)
    logger.info("STAGE 3: DATA, DUPLICATE, AND FEATURE-QUALITY ANALYSIS PIPELINE")
    logger.info("=" * 70)

    # 1. Ingest full cleaned dataset
    logger.info("Step 1: Ingesting official CICIDS2017 dataset across 8 CSV captures...")
    df, load_reports = load_dataset(reject_non_finite=True)
    logger.info(f"Successfully loaded and validated {len(df):,} flows across 8 capture files.")

    # 2. Duplicate Flow Analysis
    logger.info("Step 2: Executing Exact Duplicate Flow Analysis...")
    dup_results = run_duplicate_analysis(df=df, save_reports=True)
    logger.info(
        f"Duplicate Analysis complete. Found {dup_results['dataset_summary']['total_duplicate_rows']:,} "
        f"duplicate flows ({dup_results['dataset_summary']['duplicate_percentage']:.2f}%)."
    )

    # 3. Splitting Protocols Generation
    logger.info("Step 3: Creating Splitting Protocols...")
    
    # Protocol A: 70/15/15 Stratified Random Split
    train_df_a, val_df_a, test_df_a, split_a_report = create_protocol_a_splits(df, seed=RANDOM_SEED)
    split_a_path = REPORTS_DIR / "split_protocol_a_report.json"
    with open(split_a_path, "w", encoding="utf-8") as f:
        json.dump(split_a_report, f, indent=2)
    logger.info(f"Protocol A splits generated and saved report to {split_a_path}")

    # Protocol B: Day / Capture-Aware Split
    train_df_b, test_df_b, split_b_report = create_protocol_b_splits(df)
    split_b_path = REPORTS_DIR / "split_protocol_b_report.json"
    with open(split_b_path, "w", encoding="utf-8") as f:
        json.dump(split_b_report, f, indent=2)
    logger.info(f"Protocol B splits generated and saved report to {split_b_path}")

    # 4. Feature Quality Analysis (Strictly on Protocol A X_train)
    logger.info("Step 4: Executing Feature Quality Analysis strictly on Protocol A Train Set...")
    fq_results = run_feature_quality_analysis(
        train_df=train_df_a,
        variance_threshold=1e-6,
        correlation_threshold=0.95,
        sample_size_trees=50_000,
        sample_size_mi=20_000,
        save_reports=True,
    )
    logger.info(
        f"Feature Quality Analysis complete. Empirically selected K = {fq_results['summary']['final_selected_k']} features."
    )

    elapsed = time.time() - start_time
    logger.info("=" * 70)
    logger.info(f"ANALYSIS PIPELINE COMPLETED SUCCESSFULLY IN {elapsed:.2f} SECONDS")
    logger.info(f"Reports generated:")
    logger.info(f"  - Duplicate Report: docs/experiments/duplicate_analysis_report.md")
    logger.info(f"  - Feature Quality Report: docs/experiments/feature_quality_report.md")
    logger.info(f"  - Selected Features: data/metadata/selected_features.json")
    logger.info(f"  - Protocol A JSON: artifacts/reports/split_protocol_a_report.json")
    logger.info(f"  - Protocol B JSON: artifacts/reports/split_protocol_b_report.json")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
