# Data Pipeline Documentation

## 1. Scope & Architecture

`ml/data_pipeline.py` converts raw CICIDS2017 flow CSV files into the canonical feature and target contract defined in `data/metadata/feature_schema.json` (v0.2.0).

- **Immutability:** Raw CSV files in `data/extracted/` and raw archives in `data/raw/` are treated as strictly read-only.
- **Output:** Processed outputs and detailed validation reports are written to caller-specified paths under `data/processed/`.
- **Streaming Execution:** Files are processed in streaming batches (default chunk size: 10,000 rows) for memory efficiency.

---

## 2. Supported Fields & Canonical Mapping

The pipeline maps the following CICFlowMeter source headers:

| Raw CICIDS Header | Canonical Field | Description | Type |
| :--- | :--- | :--- | :--- |
| ` Destination Port` | `destination_port` | Target service port | Integer (0-65535) |
| ` Flow Duration` | `flow_duration_ms` | Flow duration in microseconds | Float ($\ge 0$) |
| ` Total Fwd Packets` | `total_forward_packets` | Total forward packet count | Integer ($\ge 0$) |
| ` Total Backward Packets` | `total_backward_packets` | Total backward packet count | Integer ($\ge 0$) |
| `Total Length of Fwd Packets` | `total_forward_bytes` | Total forward payload bytes | Float ($\ge 0$) |
| ` Total Length of Bwd Packets` | `total_backward_bytes` | Total backward payload bytes | Float ($\ge 0$) |
| ` Flow Packets/s` | `packets_per_second` | Flow packet transmission rate | Float ($\ge 0$) |
| ` Label` | `raw_label`<br>`attack_family`<br>`is_attack` | Verbatim raw label,<br>normalized attack family,<br>binary attack indicator | String<br>String<br>Integer (0 or 1) |

*(For the complete inventory of all 79 raw features, see `docs/data-dictionary.md`.)*

---

## 3. Label Normalization & Attack Family Taxonomy

Original raw labels are preserved verbatim in `raw_label`. A structured canonical mapping assigns an `attack_family` and binary `is_attack` flag:

- **`BENIGN`** (0): `BENIGN`
- **`DOS`** (1): `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest`
- **`DDOS`** (1): `DDoS` *(Maintained as a separate family from DoS)*
- **`PORT_SCAN`** (1): `PortScan`
- **`BRUTE_FORCE`** (1): `FTP-Patator`, `SSH-Patator`
- **`BOTNET`** (1): `Bot`
- **`WEB_ATTACK`** (1): `Web Attack – Brute Force`, `Web Attack – XSS`, `Web Attack – Sql Injection`
- **`INFILTRATION`** (1): `Infiltration`
- **`HEARTBLEED`** (1): `Heartbleed`

---

## 4. Validation & Rejection Rules

Rows are rejected and logged in the execution report if any of the following conditions occur:
1. Missing or empty values in required fields.
2. Non-numeric values (e.g. invalid string parsing).
3. Non-finite values (`NaN`, `Infinity`, `-Infinity`).
4. Negative values in flow duration, packet counts, or byte counts.
5. Port number out of boundary ($< 0$ or $> 65535$).

---

## 5. Execution

### A. Run Against the Safe Sample Dataset
```powershell
python ml/data_pipeline.py `
  --input data/samples/cicids_tiny.csv `
  --output data/processed/sample_canonical.csv `
  --report data/processed/sample_report.json
```

### B. Run Against an Extracted CICIDS2017 Dataset File
```powershell
python ml/data_pipeline.py `
  --input data/extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv `
  --output data/processed/webattacks_canonical.csv `
  --report data/processed/webattacks_report.json `
  --limit 20000
```
