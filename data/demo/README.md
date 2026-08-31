# Demonstration and Verification Dataset Assets

This directory contains deterministic, minimal test and demonstration assets for evaluating the AI Network Anomaly Detection and Intrusion Intelligence Platform.

> **CRITICAL SAFEGUARD**:
> Files in this directory are demonstration/test assets only. The backend application **does NOT automatically ingest or process these assets during startup**. They are utilized strictly through explicit demo commands (e.g. `scripts/demo_walkthrough.py`), automated test suites, or user-initiated dashboard actions.

---

## Asset Provenance and Characterization

| File Name | Format | Size | Source Provenance | Description & Target Detection |
| :--- | :--- | :--- | :--- | :--- |
| `demo_benign_flow.json` | JSON | ~2.5 KB | CICIDS2017 Monday Normal Flow Baseline | Formatted 48-feature vector representing an HTTPS session. Verified target: `BENIGN`, Risk Score: `LOW` (0-15). |
| `demo_ddos_loic.pcap` | PCAP | ~76.7 KB | CICIDS2017 Friday Afternoon DDoS (`LOIC`) | 60-packet capture slice of HTTP Low Orbit Ion Cannon flooding. Verified target: `DDOS`, Severity: `HIGH`/`CRITICAL`. |
| `demo_portscan_nmap.pcap` | PCAP | ~11.7 KB | CICIDS2017 Friday Afternoon PortScan (`Nmap`) | 60-packet capture slice of TCP SYN port scanning. Verified target: `PORT_SCAN`, Severity: `HIGH`/`CRITICAL`. |
| `demo_zeek_conn.log` | JSON / TSV | ~6.0 KB | Verified Stage 8 Native Zeek Test Fixture | 15 native Zeek connection records across HTTP, SSL, DNS, and ICMP. Verified target: `TELEMETRY_ONLY` (no ML distortion). |

---

## Usage in Automated Walkthrough

To run an interactive end-to-end evaluation using these demo assets against a running backend instance:

```bash
python scripts/demo_walkthrough.py
```
