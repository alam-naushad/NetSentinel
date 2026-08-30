# CICIDS2017 Feature Quality & Empirical Feature Selection Report

## 1. Executive Summary & Selection Funnel

All feature quality, multicollinearity pruning, and ranking steps were fitted **strictly on the Protocol A Training Set ($X_{train}$, $N = 1,979,432$)** to eliminate any potential test-set data leakage.

- **Initial Candidate Features Evaluated:** 77
- **Zero-Variance Features Filtered ($\\sigma^2 = 0.0$):** 8
- **Near-Zero Variance Features Filtered:** 0
- **Candidate Pool Retained for Correlation Screening:** 69
- **Collinear Feature Clusters ($|r| \\ge 0.95$):** 17
- **Redundant Collinear Features Pruned:** 21
- **Empirically Selected Feature Set ($K$):** **48 features**

---

## 2. Zero-Variance Features Dropped ($\\sigma^2 = 0.0$)

The following 8 features were found to have strictly zero variance (constant value of `0.0` across all 1,979,432 training flows) and were removed prior to correlation screening:

1. `bwd_psh_flags` — constant 0.0
2. `bwd_urg_flags` — constant 0.0
3. `fwd_avg_bytes_bulk` — constant 0.0
4. `fwd_avg_packets_bulk` — constant 0.0
5. `fwd_avg_bulk_rate` — constant 0.0
6. `bwd_avg_bytes_bulk` — constant 0.0
7. `bwd_avg_packets_bulk` — constant 0.0
8. `bwd_avg_bulk_rate` — constant 0.0

---

## 3. Multicollinearity Analysis & Cluster Pruning ($|r| \\ge 0.95$)

- **Correlation Metric:** Absolute Pearson Correlation Coefficient ($|r|$) computed across all 1,979,432 training rows for the 69 candidate features.
- **Threshold:** $|r| \\ge 0.95$.
- **Pruning Policy:** For each collinear cluster, feature importances were evaluated, and the single highest-signal representative was retained while all other collinear members were pruned.

### Complete Cluster Pruning Breakdown:

| Cluster # | Retained Representative Feature | Gini Importance | Pruned Collinear Features | Pairwise Correlation ($|r|$) |
| :---: | :--- | :---: | :--- | :---: |
| **1** | `total_forward_packets` | 0.013522 | `subflow_fwd_packets`, `total_backward_packets`, `subflow_bwd_packets`, `total_backward_bytes`, `subflow_bwd_bytes` | $r = 1.0000$ (`subflow_fwd_packets`), $r = 0.9992$ (`total_backward_packets`), $r = 0.9992$ (`subflow_bwd_packets`) |
| **2** | `total_forward_bytes` | 0.007123 | `subflow_fwd_bytes` | $r = 1.0000$ |
| **3** | `total_backward_bytes` | 0.008185 | `subflow_bwd_bytes` | $r = 1.0000$ |
| **4** | `avg_fwd_segment_size` | 0.012544 | `fwd_packet_length_mean` | $r = 1.0000$ |
| **5** | `bwd_packet_length_mean` | 0.045352 | `avg_bwd_segment_size`, `bwd_packet_length_max` | $r = 1.0000$ (`avg_bwd_segment_size`), $r = 0.9542$ (`bwd_packet_length_max`) |
| **6** | `syn_flag_count` | 0.004894 | `fwd_psh_flags` | $r = 1.0000$ |
| **7** | `fwd_urg_flags` | 0.000003 | `cwe_flag_count` | $r = 1.0000$ |
| **8** | `fwd_iat_total` | 0.012305 | `flow_duration_ms` | $r = 0.9995$ |
| **9** | `idle_min` | 0.023598 | `idle_max`, `flow_iat_max`, `fwd_iat_max`, `idle_mean` | $r = 0.9989$ (`idle_max`), $r = 0.9978$ (`idle_mean`), $r = 0.9782$ (`fwd_iat_max`) |
| **10** | `packet_length_mean` | 0.028593 | `average_packet_size` | $r = 0.9986$ |
| **11** | `ece_flag_count` | 0.000000 | `rst_flag_count` | $r = 0.9892$ |
| **12** | `fwd_packets_per_sec` | 0.008841 | `flow_packets_per_sec` | $r = 0.9856$ |
| **13** | `max_packet_length` | 0.030969 | `packet_length_std` | $r = 0.9765$ |
| **14** | `bwd_packet_length_std` | 0.038364 | `bwd_packet_length_max` | $r = 0.9634$ |
| **15** | `fwd_packet_length_max` | 0.017754 | `fwd_packet_length_std` | $r = 0.9582$ |

---

## 4. Feature Importance & Ranking Methodology

### A. Tree-Based Importance (ExtraTrees Classifier)
- **Model:** `ExtraTreesClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)`
- **Training Subsample:** 50,000 stratified samples drawn strictly from Protocol A $X_{train}$ with exact stratification on `raw_label`.
- **Target:** `attack_family` multiclass ground-truth.
- **Metric:** Mean Gini impurity reduction.

### B. Mutual Information Ranking
- **Algorithm:** `mutual_info_classif(n_neighbors=5, random_state=42)`
- **Training Subsample:** 20,000 stratified samples drawn strictly from Protocol A $X_{train}$ with exact stratification on `raw_label`.
- **Target:** `is_attack` binary label.
- **Metric:** Non-parametric mutual information score (bits/nats).

---

## 5. Final Deterministic Selected Feature Set ($K = 48$)

| Rank | Feature Name | ExtraTrees Gini Importance | Mutual Information Score | Feature Variance |
| :---: | :--- | :---: | :---: | :---: |
| 1 | `psh_flag_count` | 0.065896 | 0.017401 | 0.21 |
| 2 | `bwd_packet_length_mean` | 0.045352 | 0.276607 | 366,588.50 |
| 3 | `min_seg_size_fwd` | 0.040785 | 0.038293 | 1,079,715,364,864.00 |
| 4 | `bwd_packet_length_std` | 0.038364 | 0.183086 | 705,111.81 |
| 5 | `bwd_packet_length_min` | 0.035437 | 0.111731 | 4,760.38 |
| 6 | `max_packet_length` | 0.030969 | 0.262047 | 4,118,605.00 |
| 7 | `destination_port` | 0.029257 | 0.265912 | 333,988,512.00 |
| 8 | `ack_flag_count` | 0.029241 | 0.006773 | 0.22 |
| 9 | `packet_length_mean` | 0.028593 | 0.292393 | 93,421.91 |
| 10 | `fwd_iat_std` | 0.024166 | 0.122453 | 92,984,297,127,936.00 |
| 11 | `idle_min` | 0.023598 | 0.098850 | 546,687,630,180,352.00 |
| 12 | `init_win_bytes_fwd` | 0.023121 | 0.268865 | 205,633,360.00 |
| 13 | `packet_length_variance` | 0.020822 | 0.329634 | 2,715,498,315,776.00 |
| 14 | `min_packet_length` | 0.019947 | 0.115969 | 634.43 |
| 15 | `fwd_packet_length_max` | 0.017754 | 0.241506 | 519,617.22 |
| 16 | `act_data_pkt_fwd` | 0.015708 | 0.056348 | 485,032.88 |
| 17 | `flow_iat_std` | 0.014403 | 0.137854 | 64,775,413,301,248.00 |
| 18 | `total_forward_packets` | 0.013522 | 0.086199 | 654,947.50 |
| 19 | `down_up_ratio` | 0.013328 | 0.010866 | 0.46 |
| 20 | `flow_iat_mean` | 0.013065 | 0.155746 | 20,354,405,761,024.00 |
| 21 | `avg_fwd_segment_size` | 0.012544 | 0.157257 | 34,858.86 |
| 22 | `fwd_header_length` | 0.012420 | 0.175035 | 590,191,186,149,376.00 |
| 23 | `bwd_header_length` | 0.012405 | 0.172538 | 1,822,464,933,888.00 |
| 24 | `fwd_iat_total` | 0.012305 | 0.163075 | 1,128,874,305,912,832.00 |
| 25 | `fin_flag_count` | 0.011333 | 0.012270 | 0.03 |
| 26 | `bwd_iat_total` | 0.009669 | 0.142429 | 826,991,993,421,824.00 |
| 27 | `fwd_packets_per_sec` | 0.008841 | 0.165858 | 61,355,827,200.00 |
| 28 | `urg_flag_count` | 0.007787 | 0.017087 | 0.09 |
| 29 | `init_win_bytes_bwd` | 0.007575 | 0.249444 | 71,737,576.00 |
| 30 | `fwd_iat_mean` | 0.007516 | 0.151041 | 90,821,143,560,192.00 |
| 31 | `fwd_packet_length_min` | 0.007340 | 0.114188 | 3,648.09 |
| 32 | `total_forward_bytes` | 0.007123 | 0.279213 | 131,869,640.00 |
| 33 | `bwd_packets_per_sec` | 0.005540 | 0.183087 | 1,450,806,400.00 |
| 34 | `syn_flag_count` | 0.004894 | 0.004402 | 0.04 |
| 35 | `bwd_iat_max` | 0.003790 | 0.148822 | 295,076,064,395,264.00 |
| 36 | `bwd_iat_mean` | 0.003561 | 0.134046 | 79,080,170,979,328.00 |
| 37 | `bwd_iat_std` | 0.003211 | 0.082596 | 39,440,881,811,456.00 |
| 38 | `active_mean` | 0.002987 | 0.122218 | 427,459,575,808.00 |
| 39 | `flow_bytes_per_sec` | 0.002735 | 0.191654 | 703,757,234,995,200.00 |
| 40 | `active_min` | 0.002683 | 0.118850 | 338,674,843,648.00 |
| 41 | `flow_iat_min` | 0.002640 | 0.071753 | 8,738,739,585,024.00 |
| 42 | `active_max` | 0.002580 | 0.118207 | 1,066,055,041,024.00 |
| 43 | `fwd_iat_min` | 0.002409 | 0.057618 | 73,917,326,688,256.00 |
| 44 | `idle_std` | 0.002268 | 0.021153 | 21,227,517,247,488.00 |
| 45 | `bwd_iat_min` | 0.001869 | 0.100100 | 69,146,326,859,776.00 |
| 46 | `active_std` | 0.000206 | 0.015200 | 156,154,413,056.00 |
| 47 | `fwd_urg_flags` | 0.000003 | 0.001811 | 0.00 |
| 48 | `ece_flag_count` | 0.000000 | 0.000000 | 0.00 |

---

## 6. Status of `destination_port` & Ablation Protocol

- **Primary Inclusion:** `destination_port` **is included** in the primary $K=48$ feature set (Rank 7, Gini importance $0.029257$, Mutual Information $0.265912$).
- **Port Ablation Study Requirement:** To guard against port overfitting and rigorously evaluate whether baseline models learn actual flow statistical dynamics or merely memorize service ports (e.g. port 80 = HTTP attack, port 21 = FTP attack), all models will also be evaluated under a secondary **Port-Ablated Feature Set ($K=47$)** where `destination_port` is excluded.
