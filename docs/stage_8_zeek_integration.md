# Stage 8: Zeek Native Telemetry Integration

## 1. Overview & Operational Scope

Stage 8 of the cybersecurity AI capstone project implements Zeek Native Telemetry Integration. This stage enables the ingestion of standard Zeek `conn.log` data (in both JSON and TSV formats) into the existing SOC analysis platform. 

**Critical Operational Scope:**
- **Telemetry-Only Persistence and Visualization:** Zeek data ingestion is strictly for telemetry persistence and frontend visualization. 
- **NO ML Inference:** Under no circumstances is the standard Zeek `conn.log` data subjected to machine learning inference.
- **System Preservation:** This stage explicitly preserves the integrity of Stage 3 models, Stage 4 inference logic, Stage 6A/6B PCAP pipeline, and the defined `AttackFamily` taxonomy. None of these components are to be modified or bypassed.

## 2. Crucial Distinctions: Zeek Connection Duration vs. CICFlowMeter IAT

A fundamental architectural principle of this system is recognizing the inherent incompatibility between standard Zeek connection logs and the CICFlowMeter statistical features used by our ML models.

- **Zeek Connection-Level Duration:** The `duration` field in Zeek is a single float value representing the total wall-clock duration of a connection from the first observed packet to the last observed packet, expressed in **seconds**.
- **CICFlowMeter Packet-Level Timing/Statistical Features:** Features such as `flow_iat_*`, `fwd_iat_*`, and `bwd_iat_*` represent sample mean, sample standard deviation, minimum, and maximum in **microseconds**, computed across discrete individual packet arrival intervals.

> [!WARNING]
> Converting Zeek duration from seconds to microseconds (e.g. duration * 1,000,000) does NOT reproduce CICFlowMeter IAT semantics because IAT features represent statistical distributions over individual packet arrival intervals within the bidirectional flow, which requires packet-level timestamps that standard conn.log does not export.

## 3. Feature Support & Compatibility Matrix

Attempting to feed standard `conn.log` data into the frozen K48 XGBoost model would be scientifically invalid and produce unreliable predictions due to massive feature misalignment. 

We rigidly categorize the 48 canonical features required by the K48 model into the following support tiers when mapping from standard Zeek `conn.log`:

### Zeek-Native (Direct Mapping)
Only a handful of features can be directly mapped with high confidence:
- `destination_port`
- `total_forward_packets` (requires mapping orig_pkts)
- `total_forward_bytes` (requires mapping orig_bytes)

### Approximate Derived Values (Low Confidence)
These features can be approximated but lack the precise semantics expected by the model:
- `down_up_ratio`
- `avg_fwd_segment_size`
- `bwd_packet_length_mean`
- `fwd_header_length`
- `bwd_header_length`
- `flow_bytes_per_sec`
- `fwd_packets_per_sec`
- `bwd_packets_per_sec`
- `packet_length_mean`

### Unsupported (Model-Breaking)
36 canonical features are entirely unsupported by standard `conn.log`. These require packet-level distributions, individual flag counts, initial window sizes, and active/idle state machines:
- All IAT features (`flow_iat_*`, `fwd_iat_*`, `bwd_iat_*`)
- TCP Flag counts (FIN, SYN, RST, PSH, ACK, URG)
- Initial window sizes (`init_win_bytes_forward`, `init_win_bytes_backward`)
- Subflow features
- Active/Idle time statistical distributions

## 4. Architecture & Data Flow

### Ingestion Pipeline
1. **Upload:** User uploads `conn.log`.
2. **ZeekLogParser:** Automatically detects JSON or TSV format and parses records.
3. **ZeekConnectionRecord:** Standardized internal representation.
4. **ZeekAnalysisService:** Processes records for persistence (No ML inference).
5. **TelemetryPersistenceService:** Writes telemetry to PostgreSQL.
6. **React SOC Dashboard:** Reads and visualizes the telemetry.

### UID Deduplication
To maintain data integrity, Zeek connections are deduplicated based on a composite key:
` (analysis_job_id, source_channel, zeek_uid) `

### Schema Modifications
The database schema has been adapted to accommodate Zeek telemetry without polluting the ML data paths:
- `ml_classification_performed` is set to `false`.
- ML columns are explicitly nullable and set to `NULL` (`predicted_family = NULL`, `class_confidence = NULL`, etc.).
- The `source_channel` is explicitly marked as `"ZEEK_CONN"`.
- Zeek-specific provenance fields have been added: `zeek_uid`, `conn_state`, `history`, `service`, `missed_bytes`, `zeek_metadata`.

> [!IMPORTANT]
> The system enforces a strict policy of no fabricated values. We do not use `AttackFamily.UNCLASSIFIED`, nor do we generate fabricated risk scores for Zeek telemetry.

## 5. API Specification

### `POST /api/v1/zeek/analyze`
**Description:** Ingests a Zeek `conn.log` file for telemetry persistence and analysis.

**Constraints:**
- **Supported Formats:** Zeek `conn.log` (JSON, TSV)
- **Size Limit:** 50 MB per upload
- **Connection Limit:** 100,000 connections per file

**Request:**
- `multipart/form-data` with file field `file`.

**Response Schema (Success 200 OK):**
```json
{
  "summary": {
    "filename": "conn.log",
    "file_size_bytes": 1234567,
    "total_connections_parsed": 5000,
    "total_connections_persisted": 4990,
    "connections_skipped_malformed": 8,
    "connections_skipped_duplicate": 2,
    "protocol_distribution": {"tcp": 4200, "udp": 780, "icmp": 20},
    "service_distribution": {"http": 2100, "dns": 700, "ssl": 300, "-": 1900},
    "conn_state_distribution": {"SF": 3500, "S0": 800, "OTH": 700},
    "processing_time_ms": 45.2,
    "ml_classification_performed": false,
    "analysis_type": "TELEMETRY_ONLY"
  },
  "connections": [
    {
      "zeek_uid": "CYsKjJ3qWQc2pSKXEh",
      "src_ip": "192.168.1.50",
      "dst_ip": "10.0.0.1",
      "src_port": 50000,
      "dst_port": 80,
      "proto": "tcp",
      "service": "http",
      "duration_sec": 1.234,
      "orig_bytes": 500,
      "resp_bytes": 12000,
      "conn_state": "SF",
      "history": "ShADadFf",
      "orig_pkts": 10,
      "resp_pkts": 15,
      "missed_bytes": 0
    }
  ],
  "job_id": "840d86f3-d8ea-4774-a762-89484bf9ebf8",
  "persisted": true,
  "persistence_error": null
}
```

## 6. Frontend Dashboard

The React SOC Dashboard has been updated to provide a dedicated experience for Zeek data.

- **Zeek Telemetry Tab:** A separate tab specifically for analyzing Zeek `conn.log` data.
- **Prominent Info Banner:** To prevent analyst confusion, the dashboard displays a prominent banner stating: **"Telemetry Only — ML Classification Not Performed"**.
- **Visualizations:**
  - Protocol distribution charts (TCP, UDP, ICMP).
  - Service distribution (HTTP, DNS, SSL, etc.).
  - Connection state distribution (S0, SF, REJ, etc.).
- **Data Table:** A sortable, paginated connection table detailing the raw Zeek telemetry.

## 7. Future Research: Packet-Level Zeek ML Compatibility Study (Placeholder)

While standard `conn.log` cannot be used for inference with our existing K48 model, future research may explore extending Zeek's capabilities to achieve compatibility.

**Required Methodology:**
- **Custom Scripts:** Implementation of custom Zeek packet-level feature extraction scripts (e.g., `flowmeter.zeek`) that hook into Zeek's event engine at the packet level.
- **Empirical Parity Validation:** Any resulting system must undergo rigorous empirical parity validation matching our Stage 6A standards. It must achieve >=99% agreement on derived feature values when processing identical PCAP flows compared to the canonical CICFlowMeter baseline.

**Explicit Caveat:**
We reiterate that the standard `conn.log` alone cannot achieve this parity. It fundamentally lacks the granular packet arrival times and flag states required to compute the statistical distributions upon which the K48 model was trained.
