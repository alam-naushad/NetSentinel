# CICIDS2017 Dataset Provenance Record

## 1. Dataset Provenance & Source Metadata

- **Dataset Name:** Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset 2017 (CICIDS2017)
- **Official Source Authority:** Canadian Institute for Cybersecurity (CIC) / University of New Brunswick (UNB)
- **Official Source URL:** [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Primary Publication:** Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*, 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.
- **License / Terms of Use:** Open for academic and non-commercial research with proper attribution to UNB/CIC.
- **Acquisition Archive Name:** `MachineLearningCSV.zip`
- **Archive Size:** 235,102,953 bytes (224.21 MB)
- **Archive MD5 Checksum:** `4f83860afbf29cac8163854095bf6cf7` (Verified against `MachineLearningCSV.md5`)
- **Archive SHA-256 Checksum:** `c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928`
- **Extracted Content Directory:** `data/extracted/MachineLearningCVE/` (8 CSV files, 79 columns each)

---

## 2. File-by-File Inventory & Distribution

Total records across all 8 files: **2,830,743 flows** (excluding header rows).

| File Name | File Size (Bytes) | Row Count | Class Distribution (Raw Count & Percentage) |
| :--- | :--- | :--- | :--- |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 77,123,859 | 225,745 | **DDoS**: 128,027 (56.71%)<br>**BENIGN**: 97,718 (43.29%) |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 76,906,168 | 286,467 | **PortScan**: 158,930 (55.48%)<br>**BENIGN**: 127,537 (44.52%) |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 58,316,725 | 191,033 | **BENIGN**: 189,067 (98.97%)<br>**Bot**: 1,966 (1.03%) |
| `Monday-WorkingHours.pcap_ISCX.csv` | 176,927,918 | 529,918 | **BENIGN**: 529,918 (100.00%) |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 83,102,436 | 288,602 | **BENIGN**: 288,566 (99.99%)<br>**Infiltration**: 36 (0.01%) |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 52,023,263 | 170,366 | **BENIGN**: 168,186 (98.72%)<br>**Web Attack – Brute Force**: 1,507 (0.88%)<br>**Web Attack – XSS**: 652 (0.38%)<br>**Web Attack – Sql Injection**: 21 (0.01%) |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 135,078,995 | 445,909 | **BENIGN**: 432,074 (96.90%)<br>**FTP-Patator**: 7,938 (1.78%)<br>**SSH-Patator**: 5,897 (1.32%) |
| `Wednesday-workingHours.pcap_ISCX.csv` | 225,166,395 | 692,703 | **BENIGN**: 440,031 (63.52%)<br>**DoS Hulk**: 231,073 (33.36%)<br>**DoS GoldenEye**: 10,293 (1.49%)<br>**DoS slowloris**: 5,796 (0.84%)<br>**DoS Slowhttptest**: 5,499 (0.79%)<br>**Heartbleed**: 11 (0.002%) |
| **Total** | **884,645,759** | **2,830,743** | **15 distinct raw classes** |

---

## 3. Label Taxonomy & Canonical Family Mapping

The platform preserves all original raw labels verbatim while providing a clean canonical family mapping:

| Raw Dataset Label | Flow Count | % of Dataset | Canonical Attack Family | Is Attack |
| :--- | :--- | :--- | :--- | :--- |
| `BENIGN` | 2,273,097 | 80.3004% | `BENIGN` | 0 |
| `DoS Hulk` | 231,073 | 8.1630% | `DOS` | 1 |
| `PortScan` | 158,930 | 5.6144% | `PORT_SCAN` | 1 |
| `DDoS` | 128,027 | 4.5227% | `DDOS` | 1 |
| `DoS GoldenEye` | 10,293 | 0.3636% | `DOS` | 1 |
| `FTP-Patator` | 7,938 | 0.2804% | `BRUTE_FORCE` | 1 |
| `SSH-Patator` | 5,897 | 0.2083% | `BRUTE_FORCE` | 1 |
| `DoS slowloris` | 5,796 | 0.2048% | `DOS` | 1 |
| `DoS Slowhttptest` | 5,499 | 0.1943% | `DOS` | 1 |
| `Bot` | 1,966 | 0.0695% | `BOTNET` | 1 |
| `Web Attack – Brute Force` | 1,507 | 0.0532% | `WEB_ATTACK` | 1 |
| `Web Attack – XSS` | 652 | 0.0230% | `WEB_ATTACK` | 1 |
| `Infiltration` | 36 | 0.0013% | `INFILTRATION` | 1 |
| `Web Attack – Sql Injection` | 21 | 0.0007% | `WEB_ATTACK` | 1 |
| `Heartbleed` | 11 | 0.0004% | `HEARTBLEED` | 1 |
| **Total** | **2,830,743** | **100.0000%** | — | — |

### Canonical Family Aggregations

- **`BENIGN`**: 2,273,097 (80.30%)
- **`DOS`**: 252,661 (8.93%) *(DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest)*
- **`PORT_SCAN`**: 158,930 (5.61%)
- **`DDOS`**: 128,027 (4.52%) *(Separated strictly from single-source DoS)*
- **`BRUTE_FORCE`**: 13,835 (0.49%) *(FTP-Patator, SSH-Patator)*
- **`BOTNET`**: 1,966 (0.07%) *(Ares botnet)*
- **`WEB_ATTACK`**: 2,180 (0.08%) *(Brute Force, XSS, SQL Injection)*
- **`INFILTRATION`**: 36 (0.0013%) *(Metasploit Infiltration & Drop)*
- **`HEARTBLEED`**: 11 (0.0004%) *(OpenSSL Heartbleed exploit)*

---

## 4. Raw Data Quality & Preprocessing Observations

1. **Header Quirks:**
   - Most column names contain leading spaces (e.g. `' Destination Port'`).
   - Column index 34 and column index 55 are duplicate names (`' Fwd Header Length'`).
2. **Missing Protocol Column:**
   - Raw CICIDS2017 `MachineLearningCVE` CSVs do not contain a `Protocol` column. The canonical model pipeline must not assume one exists in raw files.
3. **Character Encoding:**
   - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` uses Windows-1252 (CP1252) byte `0x96` (en-dash `–`) for Web Attack labels. Parsers must decode with CP1252 or handle fallback encoding.
4. **Non-Finite Floats (`Infinity` / `NaN`):**
   - Certain rows in `Flow Bytes/s` and `Flow Packets/s` contain literal string values `Infinity` or `NaN` (occurring when `Flow Duration` is 0). The data pipeline identifies and logs these as rejected rows without crashing.
5. **Class Imbalance & Split Strategy:**
   - Extreme class imbalance is present: `Heartbleed` (11 rows) and `Infiltration` (36 rows) vs. `BENIGN` (2.27M rows).
   - Stratified train/val/test splits or grouping by capture session must be applied in Stage 3 to prevent data leakage across temporal bursts.
