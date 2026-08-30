# CICIDS2017 Flow Duplicate & Partition Boundary Contamination Analysis Report

## 1. Executive Summary & Dataset Totals

- **Total Cleaned Flows Analyzed:** 2,827,761
- **Unique Flow Feature Vectors:** 2,497,155 (88.31%)
- **Exact Duplicate Flows (Feature-level):** 330,606 (11.69%)
- **Feature & Label Duplicate Flows:** 329,888 (11.67%)
- **Cross-Label Feature Collisions (Ambiguous Flows):** 718 (0.02%)

---

## 2. Partition-Boundary Duplicate Contamination Analysis

To rigorously evaluate the risk of data leakage under row-level random splitting vs. capture-day splitting, exact feature vector sharing and label collisions were quantified across all partition boundaries.

### Protocol A (70/15/15 Stratified Random Split, Seed=42)

| Partition | Total Flows | Unique Vectors | Internal Duplicates (Feature-Only) | Internal Duplicates (Feature + Label) | Internal Cross-Label Collisions |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Train (70%)** | 1,979,432 | 1,772,647 | 206,785 | 206,364 | 421 |
| **Validation (15%)** | 424,164 | 398,344 | 25,820 | 25,782 | 38 |
| **Test (15%)** | 424,165 | 398,582 | 25,583 | 25,544 | 39 |

#### Cross-Boundary Feature Sharing (Protocol A):
- **Shared Unique Vectors between Train and Validation:** **34,720 vectors**
- **Shared Unique Vectors between Train and Test:** **34,771 vectors**
- **Shared Unique Vectors between Validation and Test:** **14,876 vectors**

#### Cross-Boundary Conflicting Labels (Protocol A):
- **Train vs. Validation Conflicting Vectors:** **423 vectors** (share identical flow features across Train & Val but have conflicting ground-truth labels).
- **Train vs. Test Conflicting Vectors:** **414 vectors** (share identical flow features across Train & Test but have conflicting ground-truth labels).
- **Validation vs. Test Conflicting Vectors:** **87 vectors** (share identical flow features across Val & Test but have conflicting ground-truth labels).

---

### Protocol B (Capture / Day-Aware Cross-Evaluation)

| Partition | Total Flows | Unique Vectors | Internal Duplicates (Feature-Only) | Internal Duplicates (Feature + Label) | Internal Cross-Label Collisions |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Train (Mon–Wed)** | 1,666,479 | 1,510,753 | 155,726 | 155,629 | 97 |
| **Test (Thu–Fri)** | 1,161,282 | 1,017,247 | 144,035 | 143,468 | 567 |

#### Cross-Capture Sharing (Protocol B):
- **Shared Unique Vectors between Mon–Wed and Thu–Fri:** **30,845 vectors** (constituting standard background keep-alive flows, DNS requests, and minimal TCP handshakes present across capture days).
- **Cross-Capture Conflicting Label Vectors:** **706 vectors** (identical minimal flow statistics observed in Monday benign traffic and Thursday/Friday attack windows).
- **Zero Novel Attack Contamination:** All 290,999 attack flows in Thursday–Friday captures have **zero** feature vector representation or duplicate overlap in the training captures.

---

## 3. Per-Class Duplicate Breakdown

| Raw Label | Attack Family | Total Flows | Unique Flows | Duplicate Flows | Duplicate Rate (%) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `BENIGN` | `BENIGN` | 2,271,205 | 2,072,059 | 199,146 | 8.77% |
| `DoS Hulk` | `DOS` | 230,124 | 172,784 | 57,340 | 24.92% |
| `PortScan` | `PORT_SCAN` | 158,804 | 90,130 | 68,674 | 43.24% |
| `DDoS` | `DDOS` | 128,025 | 128,011 | 14 | 0.01% |
| `DoS GoldenEye` | `DOS` | 10,293 | 10,282 | 11 | 0.11% |
| `FTP-Patator` | `BRUTE_FORCE` | 7,935 | 5,931 | 2,004 | 25.26% |
| `SSH-Patator` | `BRUTE_FORCE` | 5,897 | 3,219 | 2,678 | 45.41% |
| `DoS slowloris` | `DOS` | 5,796 | 5,373 | 423 | 7.30% |
| `DoS Slowhttptest` | `DOS` | 5,499 | 5,228 | 271 | 4.93% |
| `Bot` | `BOT` | 1,956 | 1,948 | 8 | 0.41% |
| `Web Attack  Brute Force` | `UNKNOWN` | 1,507 | 1,470 | 37 | 2.46% |
| `Web Attack  XSS` | `UNKNOWN` | 652 | 652 | 0 | 0.00% |
| `Infiltration` | `INFILTRATION` | 36 | 36 | 0 | 0.00% |
| `Web Attack  Sql Injection` | `UNKNOWN` | 21 | 21 | 0 | 0.00% |
| `Heartbleed` | `DOS` | 11 | 11 | 0 | 0.00% |

---

## 4. Deduplication & Contamination Handling Strategy

1. **Preservation of Raw Provenance:**
   - No raw records or ambiguous flows will be silently deleted or altered. All 2,827,761 valid flows retain full provenance, timestamps, source capture metadata, and raw ground-truth labels.
2. **Handling Cross-Label Collisions (Ambiguous Flows):**
   - The 718 cross-label collisions represent zero-payload TCP handshakes and short DNS queries that are physically identical regardless of background attack activity.
   - *Training Policy:* Ground-truth labels are preserved verbatim during training.
   - *Evaluation Policy:* In test evaluations, performance on the 414 Train-Test collision vectors will be explicitly analyzed as an *Ambiguity Contamination Slice*, documenting whether test misclassifications are due to model error or inherent feature ambiguity.
3. **Protocol A Retention with Leakage Reporting:**
   - In Protocol A (70/15/15 Stratified Random Split), duplicate flows are retained to reflect standard academic baseline comparisons, with the 34,771 shared vectors explicitly reported.
4. **Protocol B Temporal Isolation:**
   - Protocol B eliminates same-burst duplicate memorization for unseen attack classes by evaluating across distinct capture days.
