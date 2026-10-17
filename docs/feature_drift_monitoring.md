# Production Feature Drift Monitoring: Technical Architecture & Operational Guide

## 1. Executive Summary & Design Scope

The **Production Feature Drift Monitoring** subsystem provides continuous, lightweight statistical observability over incoming network flow distributions in NetSentinel. It benchmarks incoming flow feature vectors against the frozen, verified **Protocol A training baseline** derived from the CICIDS2017 dataset.

### Core Objectives
1. **Statistical Observability**: Quantify whether incoming network traffic features resemble the distribution on which the production machine learning models (XGBoost, Isolation Forest, Random Forest, Logistic Regression) were trained.
2. **Safe Operational Triage**: Provide SOC analysts with actionable drift metrics (Population Stability Index and Standardized Mean Difference) without generating false alerts, modifying model weights, or classifying drift as an attack.
3. **Zero-Budget Impact**: Implemented entirely with pure Python and NumPy in-process operations; zero external cloud services, new packages, or subscription dependencies.
4. **Data-Channel Integrity**: Exclusively monitors channels with verified 48-feature completeness (PCAP reconstructions, batch REST evaluations). Strictly rejects native Zeek `conn.log` streams where 36 packet-timing features are fundamentally missing.

---

## 2. Baseline Provenance & Exact Reproducibility

### Training Population Invariants
The baseline reference distributions are generated from the exact training split used for the production models:
- **Source Dataset**: CICIDS2017 `MachineLearningCVE` (8 raw CSV captures, 2,827,761 total rows).
- **Split Protocol**: **Protocol A** (70/15/15 Stratified Random Split, `random_state=42`).
- **Population Count**: **1,979,432 flows** (Train split exclusively; validation and test splits are strictly excluded).
- **Feature Schema**: Canonical $K=48$ feature list from [`data/metadata/selected_features.json`](file:///c:/Users/ASUS/Documents/Codex/2026-08-29/NetSentinel/data/metadata/selected_features.json).

### Alignment Verification Check
The empirical means and variances computed during baseline generation were compared directly against the frozen `sklearn.preprocessing.StandardScaler` contained inside the production model bundle `artifacts/models/protocol_a_logisticregression_k48.joblib`:
$$\max_{i} |\mu_{\text{computed}, i} - \mu_{\text{StandardScaler}, i}| = 0.000000 \times 10^0$$
$$\max_{i} |\sigma^2_{\text{computed}, i} - \sigma^2_{\text{StandardScaler}, i}| = 0.000000 \times 10^0$$

This mathematical identity certifies that the drift baseline is $100\%$ bit-exact aligned with the production model normalization parameters.

The generated reference artifact is stored statically in [`data/metadata/baseline_feature_distributions.json`](file:///c:/Users/ASUS/Documents/Codex/2026-08-29/NetSentinel/data/metadata/baseline_feature_distributions.json) and can be reproduced at any time via:
```bash
python scripts/generate_drift_baseline.py
```

---

## 3. Mathematical Formulation of Drift Metrics

### 3.1 Population Stability Index (PSI)

For each canonical feature $i \in \{1, \dots, 48\}$, the feature space is partitioned into $B$ discrete bins defined by cutoffs $[c_0, c_1, \dots, c_{B-1}]$ derived from baseline quantiles. Let $Q_b$ denote the baseline reference proportion in bin $b$, and $P_b$ denote the observed proportion of incoming samples in bin $b$:

$$\text{PSI}_i = \sum_{b=1}^{B} (\tilde{P}_b - \tilde{Q}_b) \times \ln\left(\frac{\tilde{P}_b}{\tilde{Q}_b}\right)$$

where epsilon-smoothed proportions $\tilde{P}_b$ and $\tilde{Q}_b$ prevent undefined logarithms and division-by-zero on empty bins:
$$\tilde{P}_b = \frac{P_b + \epsilon}{1.0 + \epsilon \cdot B}, \quad \tilde{Q}_b = \frac{Q_b + \epsilon}{1.0 + \epsilon \cdot B}, \quad \epsilon = 10^{-4}$$

#### Adaptive Zero-Inflation Binning
In network flow feature sets, many features (e.g., flag counts like `fwd_urg_flags`, `ece_flag_count`, `active_std`, `idle_std`) exhibit strong point masses at zero ($>50\%$ to $>99\%$ zeros). Standard quantile deciles on zero-inflated distributions cause duplicate bin edges (e.g. $[0, 0, 0, \dots]$).

To prevent degenerate binning:
1. **Discrete / Binary Features** ($\le 5$ unique values, e.g. `syn_flag_count`):
   Bins are centered around midpoints between consecutive unique values. For $\{0, 1\}$, cutoff is $0.5$, yielding bins $[-\infty, 0.5)$ and $[0.5, \infty)$.
2. **Zero-Inflated Continuous Features** ($\ge 5\%$ zeros):
   Bin 0 is explicitly designated for non-positive values: $(-\infty, 10^{-6}]$. The remaining strictly positive values ($X > 10^{-6}$) are partitioned into empirical quantiles.
3. **Standard Continuous Features**:
   Partitioned into empirical deciles ($B=10$).

### 3.2 Standardized Mean Difference (SMD / Cohen's $d$)

Quantifies the directional shift of the sample mean relative to baseline standard deviation:
$$\text{SMD}_i = \frac{\mu_{\text{observed}, i} - \mu_{\text{baseline}, i}}{\sigma_{\text{baseline}, i}}$$

- If $\sigma_{\text{baseline}, i} < 10^{-9}$ (constant baseline feature), $\text{SMD}_i$ is set to `null` to avoid division by zero.
- A positive SMD indicates an upward physical shift (e.g., higher average packet rates or larger payload sizes); a negative SMD indicates a downward shift.

---

## 4. Operational Thresholds & Scientific Interpretation

| Metric Range | Severity Level | Operational Interpretation | Recommended Action |
| :--- | :---: | :--- | :--- |
| **$\text{PSI} < 0.10$** | **`STABLE`** | No significant distribution departure under operational heuristic threshold. | Continue normal operations. |
| **$0.10 \le \text{PSI} < 0.25$** | **`MODERATE`** | Moderate shift observed in feature dynamics (e.g., mild diurnal variation or workload change). | Review top drifting features in SOC dashboard. |
| **$\text{PSI} \ge 0.25$** | **`SIGNIFICANT`** | Substantial distribution divergence. The feature distribution differs significantly from the training population. | Flag for senior analyst review; evaluate whether model predictions remain calibrated. |

### Operational Status Phrasing
When overall drift status evaluates as `STABLE`:
> *"No substantial distribution shift was detected under the configured PSI threshold. Model performance was not assessed by this metric."*

### Critical Methodological & Scientific Caveats

1. **PSI Thresholds Are Operational Heuristics**:
   The cutoff values ($\text{PSI} < 0.10$ for stability, $\ge 0.25$ for significant drift) are empirical rules of thumb developed for population monitoring. They do not constitute formal hypothesis tests or fixed physical constants.

2. **Low PSI Does Not Prove Model Accuracy or Confidence Is Maintained**:
   A stable feature distribution ($\text{PSI} < 0.10$) confirms that incoming covariate inputs resemble the training baseline. However, it does not guarantee that the relationship between features and true labels remains constant (*concept drift* or *label shift*). Models may degrade even when feature distributions remain unchanged.

3. **High PSI Does Not Prove an Attack Is Occurring**:
   Feature distribution divergence simply reflects changes in network traffic dynamics (e.g., enterprise software deployments, cloud migration, massive backup syncs, video conferences, or new protocols). An attacker may intentionally craft traffic that blends into benign feature profiles ($\text{PSI} \approx 0$), whereas benign operational changes frequently exhibit elevated drift ($\text{PSI} \ge 0.25$).

4. **Drift Monitoring Does Not Measure Prediction Performance**:
   Covariate drift monitoring is completely unsupervised; it evaluates $P(X)$ divergence between observed and training distributions. It does not evaluate conditional accuracy $P(Y \mid X)$ or calibration without suitable ground-truth labels. Therefore, feature drift is an operational observability signal for input distribution sanity, not an assessment of classifier accuracy.

5. **No Automated Model Retraining**:
   In defensive cybersecurity operations, automatically retraining machine learning models on drifting unlabeled live traffic creates severe exposure to **adversarial data poisoning** (where attackers systematically manipulate traffic characteristics to shift the classifier's decision boundary). Drift monitoring is strictly an **observability and auditing tool**, not an autonomous closed-loop retraining pipeline.

---

## 5. Sample Size Requirements & Data Channel Limitations

### 5.1 Minimum Sample Size Constraint
- **Constraint**: **$N \ge 100$ flows**.
- **Rationale**: PSI is an empirical distribution metric. When computed on small batches ($N < 50$), sampling variance produces high fluctuations and false drift alarms.
- **Enforcement**: If a batch has $N < 100$ flows, metrics are computed but the summary explicitly sets `is_sample_size_sufficient = false` and `overall_drift_status = "INSUFFICIENT_DATA"`.

### 5.2 Data Channel Semantics & Limitations

1. **PCAP Capture Batches (`POST /api/v1/pcap/analyze`)**:
   - **Status**: **Fully Supported**.
   - Contains all 48 canonical features with 100% mathematical validity.
   - *Limitation*: Persisted PCAP records in `security_events` reflect analyst-uploaded capture files (e.g., incident triage captures or sample replays). They do **not** represent an unbiased continuous sample of live enterprise production traffic.
2. **REST Batch Inference (`POST /api/v1/predict/batch`)**:
   - **Status**: **Fully Supported**.
   - Accepts up to 5,000 flows and returns instantaneous drift metrics alongside predictions.
3. **Zeek Native Telemetry (`conn.log`)**:
   - **Status**: **STRICTLY EXCLUDED / INELIGIBLE**.
   - As established in Stage 8, Stage 9A, and Phase 1/2A, native Zeek `conn.log` lacks 36 packet-level statistical features (IAT distributions, packet length variances, TCP flag moments).
   - Ingesting Zeek connection records into 48-feature drift monitoring is rejected with `FeatureValidationError`, preventing artificial 100% drift false alarms.

---

## 6. API Specification

### `GET /api/v1/drift/baseline`
- **Authentication**: Required (Analyst session cookie).
- **Description**: Returns static reference baseline metadata and per-feature baseline distribution parameters.

### `POST /api/v1/drift/evaluate-batch`
- **Authentication**: Required.
- **Rate Limit**: Governed by `inference_rate_limiter` (sliding-window per client IP).
- **Request Body**:
  ```json
  {
    "flows": [
      {
        "destination_port": 80.0,
        "flow_duration_ms": 150000.0,
        ... (all 48 canonical features)
      }
    ]
  }
  ```
- **Response**: `DriftEvaluationResponse` containing `summary` and `feature_metrics` dictionary.

### `GET /api/v1/drift/telemetry-window?limit=500&source_channel=PCAP_BATCH`
- **Authentication**: Required.
- **Parameters**: `limit` (integer, 10 to 5,000), `source_channel` (default: `"PCAP_BATCH"`).
- **Description**: Evaluates feature drift across the most recent window of persisted forensic flow vectors in PostgreSQL.

---

## 7. Frontend SOC Dashboard Integration

The feature drift monitoring panel is integrated directly into the existing **Session Analytics View** ([`frontend/src/components/analytics/AnalyticsView.tsx`](file:///c:/Users/ASUS/Documents/Codex/2026-08-29/NetSentinel/frontend/src/components/analytics/AnalyticsView.tsx)) via [`FeatureDriftPanel.tsx`](file:///c:/Users/ASUS/Documents/Codex/2026-08-29/NetSentinel/frontend/src/components/analytics/FeatureDriftPanel.tsx):

- **Overall Drift Status Badge**: Visual indicator (`STABLE`, `MODERATE SHIFT`, `SIGNIFICANT DRIFT`, or `INSUFFICIENT SAMPLE`).
- **Statistical Disclaimer**: Prominent banner reminding analysts that drift is an observability signal, not attack proof.
- **Metrics Summary Cards**: Evaluated flows, canonical feature alignment count (48/48), mean PSI, and shift tallies.
- **Feature Drift Breakdown Table**: Sortable table ranking features by PSI descending, displaying feature type, PSI, SMD, baseline vs. observed moments, and severity badges.
- **Toggle View**: Switch seamlessly between Top 10 Drifting Features and All 48 Features.

---

## 8. Verification & Test Commands

### Backend Automated Tests
```powershell
# Run dedicated feature drift test suite (19 test cases)
cmd /c "set PYTHONPATH=backend;. && .\work\.venv\Scripts\pytest.exe -v tests/test_feature_drift.py"

# Run full backend regression test suite (207 tests)
cmd /c "set PYTHONPATH=backend && .\work\.venv\Scripts\pytest.exe -q tests/"
```

### Frontend Automated Tests & Build
```powershell
# Run frontend test suite (15 tests)
cmd /c "npm test"

# Compile production frontend build
cmd /c "npm run build"
```
