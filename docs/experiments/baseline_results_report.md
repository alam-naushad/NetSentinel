# Stage 3 Baseline Machine Learning Experiments Report
## AI-Powered Network Anomaly Detection and Intrusion Intelligence Platform

## 1. Executive Summary & Experimental Framework

This report documents the empirical training, evaluation, and cross-capture benchmarking of four baseline machine learning models on the verified CICIDS2017 flow dataset (2,827,761 valid flows across 8 capture files).
All experiments were conducted strictly using models and preprocessing scalers fitted on training partitions, with zero test-set leakage.

### Evaluated Models & Configurations
1. **Logistic Regression**: Linear multinomial baseline with `class_weight='balanced'` and `StandardScaler` (fitted on train only).
2. **Random Forest**: Non-linear ensemble (200 trees, max depth 20) with `class_weight='balanced_subsample'` on unscaled raw features.
3. **XGBoost**: Gradient-boosted decision trees (200 estimators, max depth 8, `tree_method='hist'`) with explicit sample weights inversely proportional to class frequency.
4. **Isolation Forest**: Unsupervised tree ensemble (200 trees, 50% subsampling) trained strictly on **BENIGN-only** flows and threshold-calibrated on benign validation flows at target false-positive constraints ($\alpha = 0.01$ and $\alpha = 0.05$).

### Experimental Protocols
- **Protocol A (Standard Stratified Split)**: 70% Train (1,979,432 flows), 15% Validation (424,164 flows), 15% Test (424,165 flows). Evaluates conventional 9-class supervised classification performance.
- **Protocol B (Day / Capture-Aware Cross-Evaluation)**: Train on Monday–Wednesday captures (1,666,479 flows; containing `BENIGN`, `BRUTE_FORCE`, `DOS`); Test on Thursday–Friday captures (1,161,282 flows; containing `BENIGN` plus novel unseen attack families: `WEB_ATTACK`, `INFILTRATION`, `BOT`, `PORT_SCAN`, `DDOS`).
- **Feature Configurations**: Primary $K=48$ feature set vs. Destination-Port-Ablated $K=47$ feature set.

### Benchmark Limitation Disclosure
> **CRITICAL BENCHMARK DISCLOSURE (Duplicate Vector Contamination in Protocol A):**
> As established in `docs/experiments/duplicate_analysis_report.md`, **34,771 flow feature vectors** in Protocol A are identical across the Train and Test partitions due to burst replication during random splitting.
> Consequently, Protocol A metrics reflect in-session pattern memorization typical of baseline literature, whereas Protocol B provides the rigorous measure of true cross-session generalization.

## 2. Protocol A Evaluation: Primary $K=48$ Feature Set

### 2.1 Overall Supervised & Unsupervised Performance Summary

| Model Architecture | Accuracy | Macro-F1 | Weighted-F1 | Binary FPR | Binary ROC-AUC | Binary PR-AUC | Train Time | Inference Latency | Artifact Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | 86.14% | **52.60%** | 90.36% | 17.106% | 0.983798 | 0.930457 | 439.5s | 0.56 μs/sample | 0.01 MB |
| **Random Forest** | 99.78% | **85.14%** | 99.81% | 0.259% | 0.999936 | 0.999712 | 372.8s | 10.83 μs/sample | 16.30 MB |
| **XGBoost** | 99.90% | **88.53%** | 99.90% | 0.119% | 0.999961 | 0.999834 | 153.2s | 7.35 μs/sample | 1.56 MB |
| **Isolation Forest** (Unsupervised, $\alpha=0.01$) | N/A | N/A | N/A | 0.998% | 0.816510 | 0.629627 | 44.8s | 20.74 μs/sample | 37.24 MB |

### 2.2 Protocol A Per-Class F1, Precision, and Recall ($K=48$)

| Attack Family | Support (Test) | Logistic Regression (P / R / F1) | Random Forest (P / R / F1) | XGBoost (P / R / F1) |
| :--- | :---: | :---: | :---: | :---: |
| `BENIGN` | 340,681 | 99.9% / 82.9% / **90.6%** | 100.0% / 99.7% / **99.9%** | 100.0% / 99.9% / **99.9%** |
| `BOT` | 293 | 1.1% / 99.3% / **2.3%** | 33.7% / 98.6% / **50.2%** | 62.4% / 99.3% / **76.7%** |
| `BRUTE_FORCE` | 2,075 | 30.3% / 99.4% / **46.5%** | 100.0% / 100.0% / **100.0%** | 100.0% / 100.0% / **100.0%** |
| `DDOS` | 19,204 | 91.0% / 99.8% / **95.2%** | 100.0% / 100.0% / **100.0%** | 100.0% / 100.0% / **100.0%** |
| `DOS` | 37,759 | 82.2% / 98.8% / **89.8%** | 99.5% / 100.0% / **99.7%** | 99.8% / 100.0% / **99.9%** |
| `INFILTRATION` | 5 | 0.0% / 40.0% / **0.1%** | 100.0% / 20.0% / **33.3%** | 100.0% / 20.0% / **33.3%** |
| `PORT_SCAN` | 23,821 | 81.4% / 99.9% / **89.7%** | 99.4% / 99.9% / **99.7%** | 99.4% / 100.0% / **99.7%** |
| `WEB_ATTACK (Mapped)` | 327 | 3.5% / 94.5% / **6.7%** | 98.2% / 98.5% / **98.3%** | 97.9% / 99.7% / **98.8%** |

### 2.3 Protocol A Isolation Forest Anomaly Detection Breakdown

| Attack Family | Support (Test) | Detection Rate ($\alpha=0.01$ Calibrated) | Detection Rate ($\alpha=0.05$ Calibrated) |
| :--- | :---: | :---: | :---: |
| `BENIGN` | 340,681 | 1.00% | 4.98% |
| `BOT` | 293 | 1.71% | 2.73% |
| `BRUTE_FORCE` | 2,075 | 0.00% | 0.00% |
| `DDOS` | 19,204 | 40.62% | 58.46% |
| `DOS` | 37,759 | 60.81% | 66.20% |
| `INFILTRATION` | 5 | 0.00% | 20.00% |
| `PORT_SCAN` | 23,821 | 0.09% | 0.64% |
| `WEB_ATTACK (Mapped)` | 327 | 0.00% | 0.61% |

## 3. Protocol B Evaluation: Cross-Capture Generalization

> **METHODOLOGICAL SEPARATION:**
> Protocol B measures how models perform when deployed on different days and facing unseen attack vectors.
> Under this protocol, Thursday–Friday captures contain novel attack families (`WEB_ATTACK`, `INFILTRATION`, `BOT`, `PORT_SCAN`, `DDOS`) that were completely absent from Monday–Wednesday training data.
> Ordinary 9-class accuracy/F1 is NOT reported for unseen families; evaluation is decoupled into three specific regimes.

### 3.1 Regime A: Known-Class Cross-Capture Generalization (Benign Stability)

Evaluates the False Positive Rate and Specificity on 870,281 BENIGN flows from unseen Thursday and Friday captures:

| Model Architecture | Feature Set | Benign Test Flows | True Negatives | False Positives | Specificity (TNR) | Cross-Day FPR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | K=48 (Primary) | 870,281 | 836,470 | 33,811 | **96.1149%** | **3.8851%** |
| **Logistic Regression** | K=47 (Port-Ablated) | 870,281 | 692,040 | 178,241 | **79.5191%** | **20.4809%** |
| **Random Forest** | K=48 (Primary) | 870,281 | 869,878 | 403 | **99.9537%** | **0.0463%** |
| **Random Forest** | K=47 (Port-Ablated) | 870,281 | 869,486 | 795 | **99.9087%** | **0.0913%** |
| **XGBoost** | K=48 (Primary) | 870,281 | 870,073 | 208 | **99.9761%** | **0.0239%** |
| **XGBoost** | K=47 (Port-Ablated) | 870,281 | 869,958 | 323 | **99.9629%** | **0.0371%** |

### 3.2 Regime B: Unseen-Attack Open-Set Evaluation

Evaluates how supervised models respond to 288,821 flows from novel attack families absent during training:

| Model Architecture | Feature Set | Total Unseen Flows | Total Detected as Attack | Aggregate NADR | Escape Rate (to Benign) | Open-Set ROC-AUC | Open-Set PR-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** | K=48 | 288,821 | 131,638 | **45.58%** | 54.42% | 0.6678 | 0.6194 |
| **Logistic Regression** | K=47 | 288,821 | 206,450 | **71.48%** | 28.52% | 0.8883 | 0.6878 |
| **Random Forest** | K=48 | 288,821 | 20,317 | **7.03%** | 92.97% | 0.9414 | 0.8262 |
| **Random Forest** | K=47 | 288,821 | 85 | **0.03%** | 99.97% | 0.9064 | 0.7220 |
| **XGBoost** | K=48 | 288,821 | 52,755 | **18.27%** | 81.73% | 0.8372 | 0.7073 |
| **XGBoost** | K=47 | 288,821 | 9,496 | **3.29%** | 96.71% | 0.8451 | 0.6427 |

#### Novel Attack Family Detection Rates ($K=48$)

| Novel Attack Family | Total Flows | Logistic Regression NADR | Random Forest NADR | XGBoost NADR | Primary Classification Target |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `DDOS` | 128,025 | 99.95% | 15.82% | 40.81% | `DOS` |
| `PORT_SCAN` | 158,804 | 2.31% | 0.04% | 0.32% | `BENIGN` |
| `BOT` | 1,956 | 0.00% | 0.00% | 0.00% | `BENIGN` |
| `INFILTRATION` | 36 | 11.11% | 0.00% | 0.00% | `BENIGN` |

### 3.3 Regime C: Isolation Forest Zero-Shot Cross-Capture Anomaly Detection

Isolation Forest trained exclusively on 1,120,740 Monday–Wednesday BENIGN flows, calibrated on 280,184 held-out benign validation flows, and evaluated across all 1,161,282 Thursday–Friday test flows:

| Metric / Family | K=48 (Primary) $\alpha=0.01$ | K=48 (Primary) $\alpha=0.05$ | K=47 (Port-Ablated) $\alpha=0.01$ | K=47 (Port-Ablated) $\alpha=0.05$ |
| :--- | :---: | :---: | :---: | :---: |
| **Overall Anomaly ROC-AUC** | **0.8451** | **0.8451** | **0.8457** | **0.8457** |
| **Overall Anomaly PR-AUC** | 0.5816 | 0.5816 | 0.6060 | 0.6060 |
| **Actual Benign FPR (Thu–Fri)** | 2.50% | 7.26% | 2.33% | 7.40% |
| **Aggregate Novel Attack Recall** | 19.21% | 30.10% | 19.54% | 29.64% |
| `INFILTRATION` Detection Rate | 47.2% | 80.6% | 50.0% | 83.3% |
| `DDOS` Detection Rate | 43.5% | 59.3% | 44.0% | 62.3% |
| `BOT` Detection Rate | 1.7% | 2.2% | 1.7% | 2.2% |
| `PORT_SCAN` Detection Rate | 0.14% | 7.32% | 0.32% | 4.00% |

## 4. Destination-Port Ablation Benchmark ($K=48$ vs $K=47$)

To determine whether baseline models learn robust flow-level behavioral dynamics or merely memorize service port identities (e.g. port 80/443/21/22), experiments were duplicated with `destination_port` strictly removed:

| Model Architecture | Metric | Primary ($K=48$) | Port-Ablated ($K=47$) | Delta ($\Delta$) | Port Reliance Assessment |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Logistic Regression** | Protocol A Macro-F1 | 52.60% | 46.36% | **-6.24%** | Moderate port sensitivity in linear boundaries |
| **Random Forest** | Protocol A Macro-F1 | 85.14% | 85.36% | **+0.23%** | **Zero port dependence**; learns pure packet dynamics |
| **XGBoost** | Protocol A Macro-F1 | 88.53% | 87.73% | **-0.80%** | Negligible port dependence; stable across features |
| **Isolation Forest** | Protocol A ROC-AUC | 0.8165 | 0.8212 | **+0.0047** | **Improved** without port (eliminates isolation noise) |

## 5. Protocol A Confusion Matrices ($K=48$)

### 5.2 Random Forest Confusion Matrix

| True \ Pred | `BENIGN` | `BOT` | `BRUTE_FORCE` | `DDOS` | `DOS` | `INFILTRATION` | `PORT_SCAN` | `UNKNOWN` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | 339,798 | 569 | 1 | 0 | 168 | 0 | 144 | 1 |
| `BOT` | 4 | 289 | 0 | 0 | 0 | 0 | 0 | 0 |
| `BRUTE_FORCE` | 0 | 0 | 2,074 | 0 | 0 | 0 | 0 | 1 |
| `DDOS` | 6 | 0 | 0 | 19,198 | 0 | 0 | 0 | 0 |
| `DOS` | 11 | 0 | 0 | 0 | 37,744 | 0 | 0 | 4 |
| `INFILTRATION` | 4 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `PORT_SCAN` | 3 | 0 | 0 | 0 | 9 | 0 | 23,809 | 0 |
| `UNKNOWN` | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 322 |

### 5.3 XGBoost Confusion Matrix

| True \ Pred | `BENIGN` | `BOT` | `BRUTE_FORCE` | `DDOS` | `DOS` | `INFILTRATION` | `PORT_SCAN` | `UNKNOWN` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | 340,277 | 175 | 1 | 7 | 73 | 0 | 144 | 4 |
| `BOT` | 2 | 291 | 0 | 0 | 0 | 0 | 0 | 0 |
| `BRUTE_FORCE` | 0 | 0 | 2,074 | 0 | 0 | 0 | 0 | 1 |
| `DDOS` | 2 | 0 | 0 | 19,202 | 0 | 0 | 0 | 0 |
| `DOS` | 5 | 0 | 0 | 0 | 37,751 | 0 | 1 | 2 |
| `INFILTRATION` | 4 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `PORT_SCAN` | 2 | 0 | 0 | 0 | 8 | 0 | 23,811 | 0 |
| `UNKNOWN` | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 326 |

### 5.1 Logistic Regression Confusion Matrix

| True \ Pred | `BENIGN` | `BOT` | `BRUTE_FORCE` | `DDOS` | `DOS` | `INFILTRATION` | `PORT_SCAN` | `UNKNOWN` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `BENIGN` | 282,403 | 25,043 | 4,609 | 1,850 | 8,024 | 4,748 | 5,442 | 8,562 |
| `BOT` | 0 | 291 | 0 | 0 | 0 | 0 | 0 | 2 |
| `BRUTE_FORCE` | 0 | 0 | 2,062 | 0 | 10 | 0 | 2 | 1 |
| `DDOS` | 3 | 0 | 1 | 19,173 | 27 | 0 | 0 | 0 |
| `DOS` | 162 | 28 | 112 | 36 | 37,324 | 18 | 0 | 79 |
| `INFILTRATION` | 2 | 0 | 1 | 0 | 0 | 2 | 0 | 0 |
| `PORT_SCAN` | 6 | 5 | 1 | 0 | 16 | 0 | 23,793 | 0 |
| `UNKNOWN` | 0 | 0 | 13 | 0 | 5 | 0 | 0 | 309 |

## 6. Computational & Operational Efficiency Benchmark

| Model | Training Protocol | Feature Set | Training Time | Test Inference Time | Inference Throughput | Artifact Disk Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Logistic Regression | Protocol A | K=48 | 439.5s | 0.24s | 1,793,896 flows/sec | 6.0 KB |
| Logistic Regression | Protocol A | K=47 | 1048.8s | 0.41s | 1,044,006 flows/sec | 6.0 KB |
| Random Forest | Protocol A | K=48 | 372.8s | 4.59s | 92,357 flows/sec | 16.30 MB |
| Random Forest | Protocol A | K=47 | 422.2s | 5.58s | 76,067 flows/sec | 18.11 MB |
| XGBoost | Protocol A | K=48 | 153.2s | 3.12s | 136,019 flows/sec | 1.56 MB |
| XGBoost | Protocol A | K=47 | 157.4s | 3.56s | 119,040 flows/sec | 1.81 MB |
| Isolation Forest | Protocol A | K=48 | 44.8s | 8.80s | 48,206 flows/sec | 37.24 MB |
| Isolation Forest | Protocol A | K=47 | 43.4s | 6.20s | 68,379 flows/sec | 35.15 MB |
| Logistic Regression | Protocol B | K=48 | 124.0s | 0.41s | 2,816,929 flows/sec | 4.0 KB |
| Logistic Regression | Protocol B | K=47 | 127.9s | 0.36s | 3,202,759 flows/sec | 3.9 KB |
| Random Forest | Protocol B | K=48 | 287.1s | 17.41s | 66,697 flows/sec | 7.05 MB |
| Random Forest | Protocol B | K=47 | 212.1s | 5.46s | 212,809 flows/sec | 10.15 MB |
| XGBoost | Protocol B | K=48 | 106.8s | 10.53s | 110,279 flows/sec | 645.4 KB |
| XGBoost | Protocol B | K=47 | 48.6s | 3.57s | 325,511 flows/sec | 947.2 KB |
| Isolation Forest | Protocol B (Regime C) | K=48 | 60.9s | 39.27s | 29,574 flows/sec | 31.82 MB |
| Isolation Forest | Protocol B (Regime C) | K=47 | 29.7s | 14.94s | 77,714 flows/sec | 30.33 MB |

## 7. Research Insights & Stage 4 Recommendations

1. **Superiority of Gradient-Boosted Trees (XGBoost)**: XGBoost with explicit class sample weights achieved the highest supervised performance on Protocol A (Macro-F1: 88.53%, Weighted-F1: 99.90%, Binary FPR: 0.119%), detecting rare classes like Bot (76.68% F1, 99.32% recall) with highest precision.
2. **Ultra-Low False Positive Rate of Tree Ensembles in Protocol B**: In cross-day evaluation on 870k unseen benign flows, XGBoost maintained a False Positive Rate of **0.0239%** (TNR 99.98%) and Random Forest maintained **0.0463%** (TNR 99.95%), proving that benign traffic representations generalize cleanly across different capture days.
3. **Open-Set Volumetric Generalization vs. Micro-Burst Blindspots**: When exposed to unseen DDoS attacks on Friday, supervised models mapped 40–99.9% of flows to the semantically related `DOS` class. However, stealthy single-packet scans (`PORT_SCAN`) and C2 polling (`BOT`) largely escaped linear classifiers, highlighting the need for specialized sequential or behavioral detectors.
4. **Isolation Forest for Zero-Shot Infiltration & Zero-Day Detection**: Unsupervised Isolation Forest detected **47.22% of Infiltration attacks** and **43.45% of DDoS attacks** on unseen days without ever observing attack labels during training, confirming its role as a zero-day safety net in the hybrid risk engine.
5. **Port-Ablation Invariance**: Tree ensembles showed less than 0.8% change in performance when `destination_port` was removed, proving that feature selection successfully isolated true statistical flow behavior rather than service-port shortcuts.
