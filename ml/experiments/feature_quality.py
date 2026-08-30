"""Feature quality, variance, multicollinearity, and importance analysis.

Runs strictly on X_train (Protocol A) to prevent test-set data leakage.
Identifies zero-variance features, highly collinear clusters (|r| >= 0.95),
evaluates mutual information / tree importance, and empirically selects K features.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.model_selection import train_test_split

from ml.experiments.config import (
    DOCS_EXP_DIR,
    RANDOM_SEED,
    REPORTS_DIR,
    UNIQUE_FEATURE_NAMES,
)

logger = logging.getLogger(__name__)


def run_feature_quality_analysis(
    train_df: pd.DataFrame,
    variance_threshold: float = 1e-6,
    correlation_threshold: float = 0.95,
    sample_size_trees: int = 50_000,
    sample_size_mi: int = 20_000,
    save_reports: bool = True,
) -> dict:
    """Analyze feature quality strictly on training data (X_train)."""
    logger.info("Starting Feature Quality Analysis strictly on X_train...")
    feature_cols = [c for c in train_df.columns if c in UNIQUE_FEATURE_NAMES]
    X_train = train_df[feature_cols].copy()
    y_binary = train_df["is_attack"].values
    y_family = train_df["attack_family"].values

    n_samples, n_features = X_train.shape
    logger.info(f"Analyzing {n_features} features across {n_samples:,} training samples.")

    # -------------------------------------------------------------
    # Stage 1: Variance Analysis & Zero-Variance Screening
    # -------------------------------------------------------------
    logger.info("Stage 1: Computing feature variances and constant checks...")
    variances = X_train.var(axis=0)
    std_devs = X_train.std(axis=0)
    means = X_train.mean(axis=0)
    mins = X_train.min(axis=0)
    maxs = X_train.max(axis=0)

    zero_variance_features = []
    near_zero_variance_features = []
    valid_variance_features = []

    variance_table = {}
    for col in feature_cols:
        var_val = float(variances[col])
        std_val = float(std_devs[col])
        mean_val = float(means[col])
        min_val = float(mins[col])
        max_val = float(maxs[col])

        is_const = bool(min_val == max_val)
        if is_const or var_val == 0.0:
            zero_variance_features.append(col)
            status = "ZERO_VARIANCE"
        elif var_val < variance_threshold:
            near_zero_variance_features.append(col)
            status = "NEAR_ZERO_VARIANCE"
        else:
            valid_variance_features.append(col)
            status = "VALID"

        variance_table[col] = {
            "mean": round(mean_val, 6),
            "std": round(std_val, 6),
            "variance": round(var_val, 8),
            "min": round(min_val, 6),
            "max": round(max_val, 6),
            "status": status,
        }

    logger.info(
        f"Stage 1 Result: {len(zero_variance_features)} Zero-Variance, "
        f"{len(near_zero_variance_features)} Near-Zero Variance, "
        f"{len(valid_variance_features)} Candidate features retained."
    )

    # -------------------------------------------------------------
    # Stage 2: Correlation Matrix & Multicollinearity Pruning
    # -------------------------------------------------------------
    logger.info("Stage 2: Analyzing Pearson correlation and collinearity clusters...")
    candidates = valid_variance_features.copy()
    corr_matrix = X_train[candidates].corr(method="pearson").abs()

    highly_correlated_pairs = []
    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            col1 = candidates[i]
            col2 = candidates[j]
            r = corr_matrix.loc[col1, col2]
            if not np.isnan(r) and r >= correlation_threshold:
                highly_correlated_pairs.append({
                    "feature_1": col1,
                    "feature_2": col2,
                    "correlation": round(float(r), 4),
                })

    highly_correlated_pairs.sort(key=lambda x: x["correlation"], reverse=True)

    collinear_clusters = []
    for pair in highly_correlated_pairs:
        f1, f2 = pair["feature_1"], pair["feature_2"]
        found = False
        for cluster in collinear_clusters:
            if f1 in cluster or f2 in cluster:
                cluster.add(f1)
                cluster.add(f2)
                found = True
                break
        if not found:
            collinear_clusters.append({f1, f2})

    logger.info(f"Found {len(highly_correlated_pairs)} collinear pairs across {len(collinear_clusters)} clusters.")

    # -------------------------------------------------------------
    # Stage 3: Mutual Information & Tree-based Feature Importance
    # -------------------------------------------------------------
    logger.info(f"Stage 3: Computing Feature Importance on stratified subsamples...")
    
    # ExtraTrees on 50k stratified subsample
    if len(train_df) > sample_size_trees:
        _, X_sub_tree, _, y_sub_tree = train_test_split(
            X_train[candidates],
            train_df["attack_family"],
            test_size=sample_size_trees,
            stratify=train_df["raw_label"],
            random_state=RANDOM_SEED,
        )
    else:
        X_sub_tree = X_train[candidates]
        y_sub_tree = train_df["attack_family"]

    logger.info("Computing ExtraTrees Gini importance...")
    et_clf = ExtraTreesClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    et_clf.fit(X_sub_tree, y_sub_tree)
    tree_importances = dict(zip(candidates, et_clf.feature_importances_))

    # Mutual Information on 20k stratified subsample
    if len(train_df) > sample_size_mi:
        _, X_sub_mi, _, y_sub_mi = train_test_split(
            X_train[candidates],
            train_df["is_attack"],
            test_size=sample_size_mi,
            stratify=train_df["raw_label"],
            random_state=RANDOM_SEED,
        )
    else:
        X_sub_mi = X_train[candidates]
        y_sub_mi = train_df["is_attack"]

    logger.info("Computing Mutual Information scores...")
    mi_scores = mutual_info_classif(
        X_sub_mi,
        y_sub_mi,
        random_state=RANDOM_SEED,
        n_neighbors=5,
    )
    mi_dict = dict(zip(candidates, mi_scores))

    feature_ranking = []
    for col in candidates:
        tree_score = float(tree_importances.get(col, 0.0))
        mi_score = float(mi_dict.get(col, 0.0))
        var_score = float(variance_table[col]["variance"])
        feature_ranking.append({
            "feature": col,
            "tree_importance": round(tree_score, 6),
            "mutual_info": round(mi_score, 6),
            "variance": round(var_score, 4),
        })

    feature_ranking.sort(key=lambda x: (x["tree_importance"], x["mutual_info"]), reverse=True)

    # -------------------------------------------------------------
    # Stage 4: Empirical Selection of Feature Set K
    # -------------------------------------------------------------
    logger.info("Stage 4: Selecting non-redundant representative features per cluster...")
    cluster_pruned_drops = set()
    cluster_representatives = []

    for cluster in collinear_clusters:
        sorted_members = sorted(
            list(cluster),
            key=lambda c: tree_importances.get(c, 0.0),
            reverse=True,
        )
        rep = sorted_members[0]
        drops = sorted_members[1:]
        cluster_representatives.append({
            "representative": rep,
            "representative_importance": round(float(tree_importances.get(rep, 0.0)), 6),
            "pruned_features": drops,
        })
        for d in drops:
            cluster_pruned_drops.add(d)

    selected_features = []
    for item in feature_ranking:
        f = item["feature"]
        if f not in cluster_pruned_drops:
            selected_features.append(f)

    if "destination_port" in candidates and "destination_port" not in selected_features:
        selected_features.append("destination_port")

    k_selected = len(selected_features)
    logger.info(f"Stage 4 Result: Empirically selected K = {k_selected} features from {n_features} total candidates.")

    results = {
        "summary": {
            "total_initial_features": n_features,
            "zero_variance_features_count": len(zero_variance_features),
            "near_zero_variance_features_count": len(near_zero_variance_features),
            "candidate_features_after_variance": len(candidates),
            "collinear_clusters_count": len(collinear_clusters),
            "pruned_collinear_features_count": len(cluster_pruned_drops),
            "final_selected_k": k_selected,
        },
        "zero_variance_features": zero_variance_features,
        "near_zero_variance_features": near_zero_variance_features,
        "collinear_pairs_sample": highly_correlated_pairs[:20],
        "collinear_clusters": cluster_representatives,
        "selected_features": selected_features,
        "feature_ranking": feature_ranking,
        "variance_table": variance_table,
    }

    if save_reports:
        meta_path = Path("data/metadata/selected_features.json")
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({
                "selection_methodology": "Stage 3 Empirical Quality Analysis (Variance Filter + Multicollinearity Pruning + Tree/MI Ranking)",
                "k_selected": k_selected,
                "selected_features": selected_features,
                "zero_variance_dropped": zero_variance_features,
                "collinear_dropped": list(cluster_pruned_drops),
            }, f, indent=2)
        logger.info(f"Saved selected features list to {meta_path}")

        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        json_path = REPORTS_DIR / "feature_quality.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Saved feature quality JSON to {json_path}")

        DOCS_EXP_DIR.mkdir(parents=True, exist_ok=True)
        md_path = DOCS_EXP_DIR / "feature_quality_report.md"
        generate_feature_quality_markdown(results, md_path)
        logger.info(f"Saved feature quality Markdown report to {md_path}")

    return results


def generate_feature_quality_markdown(results: dict, output_path: Path) -> None:
    """Generate Markdown report for Feature Quality & Empirical Selection."""
    summary = results["summary"]
    zero_vars = results["zero_variance_features"]
    near_zero = results["near_zero_variance_features"]
    clusters = results["collinear_clusters"]
    selected = results["selected_features"]
    ranking = results["feature_ranking"]

    md = []
    md.append("# CICIDS2017 Feature Quality & Empirical Selection Report\n")
    md.append("## 1. Executive Summary & Selection Funnel\n")
    md.append(f"- **Initial Candidate Features Evaluated:** {summary['total_initial_features']}")
    md.append(f"- **Zero-Variance Features Filtered ($\\sigma^2 = 0$):** {summary['zero_variance_features_count']}")
    md.append(f"- **Near-Zero Variance Features Filtered:** {summary['near_zero_variance_features_count']}")
    md.append(f"- **Candidate Pool Retained for Correlation Screening:** {summary['candidate_features_after_variance']}")
    md.append(f"- **Collinear Feature Clusters ($|r| \\ge 0.95$):** {summary['collinear_clusters_count']}")
    md.append(f"- **Redundant Collinear Features Pruned:** {summary['pruned_collinear_features_count']}")
    md.append(f"- **Empirically Selected Feature Set ($K$):** **{summary['final_selected_k']} features**\n")

    md.append("## 2. Zero & Near-Zero Variance Features Dropped\n")
    if zero_vars:
        md.append("The following features contain strictly constant values across all training samples ($\\sigma^2 = 0$) and convey zero statistical discrimination:")
        for z in zero_vars:
            md.append(f"- `{z}`: constant value (0.0)")
    else:
        md.append("No zero-variance features detected.")
    md.append("")

    md.append("## 3. Multicollinearity Analysis & Cluster Pruning ($|r| \\ge 0.95$)\n")
    md.append("To prevent variance inflation in linear models and redundant split competition in tree ensembles, highly collinear feature clusters were resolved by retaining the single highest-signal representative per cluster:\n")
    md.append("| Cluster # | Retained Representative | Representative Gini Importance | Pruned Collinear Features |")
    md.append("| :---: | :--- | :---: | :--- |")
    for idx, cl in enumerate(clusters):
        pruned_str = ", ".join(f"`{p}`" for p in cl["pruned_features"])
        md.append(f"| {idx + 1} | `{cl['representative']}` | {cl['representative_importance']:.6f} | {pruned_str} |")
    md.append("")

    md.append(f"## 4. Final Empirically Selected Feature Set ($K = {summary['final_selected_k']}$)\n")
    md.append("| Rank | Selected Feature Name | ExtraTrees Importance | Mutual Information | Feature Variance |")
    md.append("| :---: | :--- | :---: | :---: | :---: |")

    rank_counter = 1
    for item in ranking:
        if item["feature"] in selected:
            md.append(
                f"| {rank_counter} | `{item['feature']}` | {item['tree_importance']:.6f} | "
                f"{item['mutual_info']:.6f} | {item['variance']:.2f} |"
            )
            rank_counter += 1
    md.append("")

    md.append("## 5. Methodological Guarantee & Next Steps\n")
    md.append("1. **Zero Test-Set Leakage:** Feature variance, Pearson correlation matrices, and tree importances were computed strictly on the training partition ($X_{train}$) of Protocol A.")
    md.append("2. **Destination Port Ablation Guard:** `destination_port` is tracked as an explicit feature to allow measuring the exact impact of service-port memorization vs. flow-statistical learning.")
    md.append("3. **Reproducibility:** The selected feature list is persisted in `data/metadata/selected_features.json` to be consumed by preprocessors and all 4 baseline model pipelines.\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
