# Stage 9A: Zeek Packet-Level Feature Reconstruction & Offline ML Compatibility Report
## Subtitle: Research / Compatibility Validation Phase

## 1. Executive Summary & Research Hypothesis

Stage 9A is an offline **Research and Compatibility Validation** study investigating whether packet-level Zeek feature reconstruction (`flowmeter.zeek`) can reliably feed the frozen Stage 3 machine learning models (`protocol_a_xgboost_k48.joblib` and `protocol_a_isolationforest_k48.joblib`).

### Core Research Hypothesis
> **Hypothesis**: Can a packet-level Zeek event script extract flow features with sufficient parity to the canonical Java-based CICFlowMeter tool that the frozen Stage 3 models produce reliable, attack-sensitive predictions?

### Compatibility Gate Verdict: **FAIL**
Although aggregate supervised XGBoost prediction agreement reached **99.69%** across 954 paired flows, the Stage 9A Compatibility Gate has **FAILED** on three critical scientific criteria:
1. **Unsupervised Distribution Drift**: Isolation Forest exhibited a benign False Positive Rate of **13.67%** at the calibrated $\alpha=0.01$ threshold, substantially exceeding the $\le 3.0\%$ gate limit.
2. **Failure on Attack Ground Truth**: In the securely paired attack subset (`DDOS`), XGBoost prediction agreement was **0.00%** (0 / 3 flows). The model classified all three paired DDoS flows as `BENIGN` due to timing and rate feature divergence.
3. **Severe Ambiguity in Attack Traffic**: Under strict non-circular pairing, attack flood probes (`PORT_SCAN`, `DOS`, `WEB_ATTACK`) produced massive endpoint collisions, preventing unique 1-to-1 pairing without model-feature circularity.

> [!CAUTION]
> **Stage 9A Gate Conclusion**: Direct ML inference on Zeek-extracted flows is **NOT certified for production**. In accordance with the Stage 9 governance rules, **Stage 9B (Production Zeek ML Pipeline) MUST NOT be implemented**. The platform will maintain Stage 8 Native Telemetry (`source_channel = "ZEEK_CONN"`, `ml_classification_performed = False`) as the permanent operational mode for Zeek data.

---

## 2. Non-Circular Pairing Methodology

To ensure absolute scientific integrity and avoid artificial inflation of compatibility scores, pairing between Zeek-extracted flows and the reference CICIDS2017 ground-truth dataset was performed using **provenance and network identity information only**:

1. **Capture File Identity**: Exact dataset matching (e.g. `friday_nmap_portscan.pcapng` $\leftrightarrow$ `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`).
2. **Transport Protocol**: Canonical layer 4 protocol match (`proto == 6` for TCP, `17` for UDP).
3. **Canonical Socket Endpoints**: Canonical bidirectional endpoint match:
   $$\{ (\text{src\_ip}, \text{src\_port}), (\text{dst\_ip}, \text{dst\_port}) \}_{\text{zeek}} \equiv \{ (\text{src\_ip}, \text{src\_port}), (\text{dst\_ip}, \text{dst\_port}) \}_{\text{ref}}$$
4. **Session Start Timestamp Alignment**: Flow start timestamp alignment within a strict $1.0\text{-second}$ window ($|\Delta t| \le 1,000,000\ \mu\text{s}$).

### Zero Model Feature Circularity
- **No model feature** (`destination_port`, `flow_bytes_per_sec`, packet counts, byte counts, flags, or IATs) was permitted as a pairing key or candidate disambiguation selector.
- If multiple reference candidate records matched the identity keys within the time window, the flow was marked **AMBIGUOUS and EXCLUDED**.
- Unmatched flows were marked **UNMATCHED and EXCLUDED**.
- Feature comparison and ML inference were initiated **only after** pairing was frozen.

---

## 3. Dataset Ingestion & Cardinality Summary

Across all 7 benchmark captures from the CICIDS2017 evaluation suite:

| Capture Dataset | Capture Day / Window | Extracted Zeek Flows | 1-to-1 Paired | Ambiguous (Excluded) | Unmatched (Excluded) | XGBoost Agreement (%) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Monday Benign** | Morning (11:55 UTC) | 1,417 | **136** | 18 | 1,263 | **100.00%** |
| **Tuesday WorkingHours** | Morning (09:00 UTC) | 2,509 | **274** | 39 | 2,196 | **100.00%** |
| **Wednesday DoS** | Morning (09:00 UTC) | 435 | **37** | 9 | 389 | **100.00%** |
| **Thursday Web Attacks** | Morning (09:00 UTC) | 1,237 | **188** | 55 | 994 | **100.00%** |
| **Friday Morning Benign** | Morning (11:59 UTC) | 1,053 | **180** | 44 | 829 | **100.00%** |
| **Friday Afternoon PortScan**| Afternoon (14:31 UTC)| 2,820 | **75** | 0 | 2,745 | **100.00%** |
| **Friday Afternoon LOIC DDoS**| Afternoon (15:33 UTC)| 2,618 | **64** | 0 | 2,554 | **95.31%** |
| **TOTAL** | **7 Benchmark PCAPs** | **12,089** | **954** | **165** | **10,970** | **99.69%** |

---

## 4. Class-Level Compatibility Breakdown

The 954 securely paired flows represent the following ground-truth distribution:

| Ground-Truth Class | Sample Count ($N$) | XGBoost Agreement (%) | Mean Confidence Delta | Mean Jensen-Shannon Divergence | Isolation Forest Mean Drift |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **BENIGN** | **951** | **100.00%** | 0.0011 | 0.0077 | 0.0471 |
| **DDOS** | **3** | **0.00%** | 0.0102 | 0.8166 | 0.0482 |
| **PORT_SCAN** | 0 | N/A | N/A | N/A | N/A |
| **DOS** | 0 | N/A | N/A | N/A | N/A |
| **WEB_ATTACK** | 0 | N/A | N/A | N/A | N/A |

### Why Did Attack Classes Lack Secure 1-to-1 Non-Circular Pairs?
- In high-rate attack traffic (`PORT_SCAN`, `DOS`, `DDOS`), attackers emit hundreds of rapid, near-simultaneous packets to identical ports with near-identical durations and timestamps.
- Without using model features (such as packet lengths or byte counts) to cheat and pick a specific row, multiple reference rows match the same session window.
- In accordance with Requirement 2, all multiple-match candidates were strictly classified as **ambiguous and excluded**.
- The 3 securely paired `DDOS` flows in Friday afternoon traffic were connection-closing teardowns that the reference CSV classified as DDoS, but which both Zeek and the model evaluated as `BENIGN`, resulting in **0.00% attack agreement** and a massive divergence ($\text{JSD} = 0.8166$).

---

## 5. Feature-Level Discrepancy Analysis (Top 15 Discrepant Features)

Feature comparison across all 954 paired flows revealed that while static flags and endpoint ports exhibit zero error, rate features and active/idle statistical features exhibit severe variance:

| Feature Name | Mean Absolute Error (MAE) | Median AE | P95 AE | Mean Relative Error | Primary Root Cause |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `flow_bytes_per_sec` | **4,923,652.64** | 7,773.61 | 9,250,000.00 | $>100.0$ | Microsecond duration division in short flows ($<100\ \mu\text{s}$) |
| `idle_min` | **1,069,826.33** | 0.00 | 2,705,674.40 | $>100.0$ | Differences in 5.0s idle threshold state machine boundary |
| `fwd_iat_total` | **315,394.78** | 2.00 | 285,346.65 | $>100.0$ | Cumulative microsecond drift across packet arrivals |
| `fwd_packets_per_sec`| **256,472.79** | 419.01 | 1,992,893.57 | 4,584.6 | Rate denominator sensitivity |
| `bwd_iat_total` | **181,442.09** | 0.00 | 107,937.15 | $>100.0$ | Backward direction packet arrival time alignment |
| `active_mean` | **173,095.48** | 0.00 | 614,955.15 | $>100.0$ | Active burst duration accumulation differences |
| `active_max` | **166,872.63** | 0.00 | 201,855.80 | $>100.0$ | Max burst timing threshold differences |
| `active_min` | **165,832.90** | 0.00 | 200,701.85 | 0.0709 | Active window initiation timing |
| `idle_std` | **139,669.14** | 0.00 | 0.00 | $>100.0$ | Welford variance accumulation on sparse idle gaps |
| `fwd_iat_std` | **138,075.69** | 0.00 | 52,742.83 | $>100.0$ | Variance divergence on multi-packet bursts |
| `flow_iat_std` | **109,619.33** | 1.32 | 42,566.55 | $>100.0$ | Bidirectional packet inter-arrival variance |
| `fwd_iat_mean` | **93,728.16** | 0.00 | 41,202.14 | $>100.0$ | Mean arrival interval calculation |
| `active_std` | **87,772.89** | 0.00 | 155,256.27 | $>100.0$ | Active period duration variance |
| `bwd_iat_max` | **86,294.57** | 0.00 | 60,134.85 | $>100.0$ | Backward max inter-arrival gap |
| `packet_length_variance`| **81,070.12** | 14.03 | 501,543.65 | $>100.0$ | High-order variance calculation across payloads |

---

## 6. Isolation Forest Anomaly Detection Assessment

- **Model Artifact**: Frozen `protocol_a_isolationforest_k48.joblib`
- **Convention**: Raw scikit-learn `decision_function(X)` (anomalies $< \text{threshold}$)
- **Calibrated Threshold**: $\alpha = 0.01$ threshold ($= 0.051838$)
- **Mean Raw Score Drift**: **0.0471** (Median: 0.0000, P95: 0.0000)
- **Benign False Positive Rate (FPR)**: **13.67%** (130 / 951 benign flows flagged as anomalies)

> [!WARNING]
> In Stage 3 calibration, the Isolation Forest model was calibrated to a nominal 1.0% benign false positive rate. On Zeek-reconstructed flows, the benign FPR jumps to **13.67%** (a 13-fold increase in false alarms). This demonstrates that unsupervised high-dimensional anomaly detection is highly sensitive to the rate and IAT variance introduced by Zeek's event timing heuristics.

---

## 7. Comprehensive Stage 9A Compatibility Gate Verdict

| Gate Requirement | Evaluation Standard | Measured Result | Verdict |
| :--- | :--- | :--- | :---: |
| **XGBoost Agreement** | $\ge 95.0\%$ across all paired flows | **99.69%** (951 / 954) | **PASS** |
| **Confidence Stability** | Mean $|\Delta\text{Conf}| \le 0.05$, P95 $\le 0.15$ | Mean = **0.0011**, P95 = **0.0044** | **PASS** |
| **Probability Divergence**| Mean $\text{JSD} \le 0.05$ | Mean = **0.0102**, Median = **0.0016** | **PASS** |
| **Numeric Validity** | 100% finite features (no NaN, no $\pm\infty$) | 100% finite (48 / 48) | **PASS** |
| **Isolation Forest FPR** | Benign False Positive Rate $\le 3.0\%$ | **13.67%** ($> 3.0\%$) | **FAIL** |
| **Attack Class Coverage** | $\ge 20$ paired flows per key attack class | $N=3$ for DDoS, $N=0$ for PortScan/DoS | **FAIL** |
| **Attack Prediction Parity**| High attack classification fidelity | **0.00%** agreement on paired attack flows | **FAIL** |

### Final Gate Verdict: **FAIL**

---

## 8. Architectural Recommendations & Future Roadmap

1. **Stage 9B Cancellation**: Do **NOT** proceed with Stage 9B (Production Zeek ML Inference). Feeding Zeek-derived flows into the frozen K48 XGBoost and Isolation Forest models would generate high false alarm rates (13.67% on benign) and fail to reliably catch attacks (0% agreement on DDoS).
2. **Preserve Stage 8 Native Telemetry**: Stage 8 Zeek Native Telemetry (`conn.log` metadata ingestion, 5-tuple tracking, connection state distribution, and frontend table) remains the authoritative, scientifically sound integration for Zeek.
3. **Future Retraining Scope (Stage 10 / Post-Capstone)**: If Zeek ML is required in future work, a dedicated model must be trained directly on native Zeek `conn.log` or `flowmeter.log` feature distributions rather than attempting to force Zeek data into models trained on Java CICFlowMeter PCAP distributions.

---

## 9. Forensic Diagnostic of Paired DDoS Flows & Root Cause Analysis

A targeted forensic investigation of the 3 securely paired DDoS flows was conducted to determine the exact mechanical cause of the 0.00% attack agreement.

### 9.1 Flow-by-Flow Provenance & Vector Comparison

All three flows originated from `data/samples/friday_loic_ddos.pcapng` and were evaluated against `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`.

#### Pair #1
- **Zeek Provenance**: `UID: Z_6_192.168.10.14_53188_1499442828153438`
  - 5-Tuple: `192.168.10.14:53188 -> 178.255.83.1:80 (tcp)`
  - Start Time: `1499442828.153438` ($153,438\ \mu\text{s}$) | Duration: `0.047540s`
  - Captured Packets: Forward = 2, Backward = 0 | Captured Bytes: Forward = 0, Backward = 0
- **Reference Ground-Truth Row**: **Row Index 196971**
  - Label: `DDoS` | Dest Port: `80` | Duration: `2965 us`
  - Total Fwd Packets: 4 | Fwd Bytes: 24 | Backward Packets: 0 | Backward Bytes: 0
- **Model Inferences**:
  - Reference Vector: Predicted **`DDOS`** (Confidence: **0.9949**)
  - Zeek Vector: Predicted **`BENIGN`** (Confidence: **0.9997**)
  - Prediction Agreement: **False** | $\text{JSD} = 0.8229$
- **Top Feature Discrepancies**:
  - `packet_length_variance`: Ref = $0.0$, Zeek = $114,155.0$ ($|\Delta| = 114,155.0$)
  - `bwd_iat_total`: Ref = $0.0$, Zeek = $24,161.0$ ($|\Delta| = 24,161.0$)
  - `fwd_iat_total`: Ref = $2,965.0$, Zeek = $23,800.0$ ($|\Delta| = 20,835.0$)
  - `flow_bytes_per_sec`: Ref = $8,094.4$, Zeek = $27,092.9$ ($|\Delta| = 18,998.5$)

#### Pair #2
- **Zeek Provenance**: `UID: Z_6_192.168.10.14_53188_1499442828201004`
  - 5-Tuple: `192.168.10.14:53188 -> 178.255.83.1:80 (tcp)`
  - Start Time: `1499442828.201004` ($201,004\ \mu\text{s}$) | Duration: `0.002947s`
  - Captured Packets: Forward = 2, Backward = 0 | Captured Bytes: Forward = 0, Backward = 0
- **Reference Ground-Truth Row**: **Row Index 196971** (Identical reference row as Pair #1)
  - Label: `DDoS` | Dest Port: `80` | Duration: `2965 us` | Fwd Pkts: 4 | Fwd Bytes: 24
- **Model Inferences**:
  - Reference Vector: Predicted **`DDOS`** (Confidence: **0.9949**)
  - Zeek Vector: Predicted **`BENIGN`** (Confidence: **0.9743**)
  - Prediction Agreement: **False** | $\text{JSD} = 0.8038$
- **Top Feature Discrepancies**:
  - `flow_bytes_per_sec`: Ref = $8,094.4$, Zeek = $0.0$ ($|\Delta| = 8,094.4$)
  - `flow_iat_min`: Ref = $6.0$, Zeek = $2,947.0$ ($|\Delta| = 2,941.0$)
  - `total_forward_bytes`: Ref = $24.0$, Zeek = $0.0$ ($|\Delta| = 24.0$)

#### Pair #3
- **Zeek Provenance**: `UID: Z_6_178.255.83.1_80_1499442828227194`
  - 5-Tuple: `178.255.83.1:80 -> 192.168.10.14:53188 (tcp)` (Inverted socket direction)
  - Start Time: `1499442828.227194` ($227,194\ \mu\text{s}$) | Duration: `0.000000s`
  - Captured Packets: Forward = 2, Backward = 0 | Captured Bytes: Forward = 0, Backward = 0
- **Reference Ground-Truth Row**: **Row Index 196971** (Identical reference row as Pairs #1 & #2)
  - Label: `DDoS` | Dest Port: `80` | Duration: `2965 us` | Fwd Pkts: 4 | Fwd Bytes: 24
- **Model Inferences**:
  - Reference Vector: Predicted **`DDOS`** (Confidence: **0.9949**)
  - Zeek Vector: Predicted **`BENIGN`** (Confidence: **1.0000**)
  - Prediction Agreement: **False** | $\text{JSD} = 0.8230$
- **Top Feature Discrepancies**:
  - `destination_port`: Ref = **80.0**, Zeek = **53188.0** ($|\Delta| = \mathbf{53,108.0}$)
  - `flow_bytes_per_sec`: Ref = $8,094.4$, Zeek = $0.0$ ($|\Delta| = 8,094.4$)
  - `fwd_iat_total`: Ref = $2,965.0$, Zeek = $0.0$ ($|\Delta| = 2,965.0$)

---

### 9.2 Root Cause Categorization

The root causes for the 0% DDoS prediction agreement fall cleanly into distinct, documented categories:

1. **Primary Root Cause: A (Pairing / Ground-Truth Alignment) & E (1-to-Many Collision on Same Socket)**
   - **Triple-Claim of Single Reference Row**: All three Zeek flows matched the exact same CSV row (**Row Index 196971**). In true bijective 1-to-1 pairing, a single reference row cannot represent three separate connection events. Because 3 PCAP sessions occurred within a 100 ms burst on `192.168.10.14:53188 <-> 178.255.83.1:80`, the candidate match was ambiguous and should have been excluded.
   - **Ground-Truth Mismatch**: The reference CSV row represented a 4-packet, 24-byte payload HTTP flood probe. However, the three packets captured by Zeek at that microsecond timestamp were **0-payload TCP FIN/ACK teardown packets**. The XGBoost model predicted `BENIGN` on the Zeek vector with $>97.4\%$ confidence because the packets were, in fact, benign TCP connection termination packets!
2. **Secondary Root Cause: D (Flow Direction Inversion on Pair #3)**
   - In Pair #3, the first packet observed was an inbound response from `178.255.83.1:80`. In flow reconstruction semantics, the initiator defines the forward direction. Consequently, Zeek set `destination_port = 53188` (ephemeral port) rather than `80` (service port). This inverted feature fundamentally altered the feature vector.
3. **Reconstruction & Event Timing (B & C)**
   - Zeek observed 2 packets with 0 bytes of payload, resulting in zero packet length variance and zero transfer rate, contrasting with the 24-byte attack probe in the CSV.

---

### 9.3 Confirmation of the Isolation Forest Result

- The measured **13.67% benign False Positive Rate** on the frozen Isolation Forest model was verified and confirmed:
  - Scikit-learn raw convention: `score = model.decision_function(scaled_X)`
  - Stage 3 calibrated $\alpha = 0.01$ threshold: `score < 0.051838`
  - Total benign flows evaluated: 951
  - Benign flows flagged as statistical anomalies: **130** ($130 / 951 = \mathbf{13.67\%}$)
- **Mechanistic Verification**: This is not a software bug. It is a genuine distributional divergence. Unsupervised tree partitioning in Isolation Forest is acutely sensitive to small perturbations in rate and timing features (`flow_bytes_per_sec`, `flow_iat_std`, `active_std`). Because Zeek accumulates these metrics through event callbacks rather than Java CICFlowMeter thread loops, the points land in less dense regions of the feature space, yielding shorter path lengths and tripping the anomaly threshold.

---

### 9.4 Final Decision & Gate Conclusion

1. **Bijective Pairing Reassessment**:
   - If Pairs #1, #2, and #3 are evaluated as candidate pairs, the gate **FAILS** due to **0.00% attack agreement** on DDoS ($\text{JSD} = 0.8166$) and **13.67% benign FPR**.
   - If bijective uniqueness is enforced (excluding the 3 flows because they represent a 3-to-1 collision on a single reference row), the securely paired attack count drops to **$N=0$ for all attack classes** (`DDOS`, `PORT_SCAN`, `DOS`, `WEB_ATTACK`), which **FAILS** the $\ge 20$ class coverage gate requirement.
2. **Definitive Verdict**:
   - Under both interpretations, the Stage 9A Compatibility Gate **FAILS**.
   - The conclusion remains firm: **Packet-level Zeek feature reconstruction cannot reliably substitute for PCAP-derived CICFlowMeter features on the frozen Stage 3 models.**
   - Stage 9B must remain disabled.
