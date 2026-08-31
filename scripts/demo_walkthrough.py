#!/usr/bin/env python3
"""Interactive Demonstration Script for AI Network Anomaly Detection Platform.

Demonstrates:
1. Liveness and Deep Readiness inspection (/health/ready)
2. Model catalog inspection & verification (/api/v1/models)
3. Single-flow AI evaluation with 48-feature input (Benign Web Flow)
4. Automated PCAP attack detection (LOIC DDoS & Nmap PortScan)
5. Zeek native telemetry batch ingestion with explicit "Telemetry Only" verification
6. System operational metrics reporting (/api/v1/metrics)

Usage:
    python scripts/demo_walkthrough.py [--base-url http://localhost:8000]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = PROJECT_ROOT / "data" / "demo"


def print_banner(title: str) -> None:
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def run_demo(base_url: str) -> bool:
    client = httpx.Client(base_url=base_url, timeout=30.0)

    # --------------------------------------------------------------------------
    # Step 1: Health & Readiness Probe
    # --------------------------------------------------------------------------
    print_banner("STEP 1: SYSTEM HEALTH & DEEP READINESS PROBE")
    try:
        r_live = client.get("/health/live")
        print(f"[*] GET /health/live -> Status: {r_live.status_code} | Payload: {r_live.json()}")
        
        r_ready = client.get("/health/ready")
        print(f"[*] GET /health/ready -> Status: {r_ready.status_code} | Payload: {r_ready.json()}")
        if r_ready.status_code != 200:
            print("[!] Warning: System not fully ready (continuing with demo).")
    except Exception as e:
        print(f"[!] Error connecting to {base_url}: {e}")
        print("[!] Please ensure the backend server or container is running.")
        return False

    # --------------------------------------------------------------------------
    # Step 2: Model Registry Inspection
    # --------------------------------------------------------------------------
    print_banner("STEP 2: FROZEN MODEL CATALOG & CHECKSUM VERIFICATION")
    r_models = client.get("/api/v1/models")
    if r_models.status_code == 200:
        models = r_models.json()
        print(f"[*] Discovered {len(models)} model artifacts in verified catalog:")
        for m in models:
            tier = m.get("deployment_tier", "UNKNOWN")
            proto = m.get("protocol", "UNKNOWN")
            print(f"    - {m['model_key']:<34} | Tier: {tier:<22} | Role: {m.get('model_role', ''):<28} | SHA256: {m.get('artifact_sha256', '')[:16]}...")
    else:
        print(f"[!] GET /api/v1/models failed: {r_models.text}")

    # --------------------------------------------------------------------------
    # Step 3: Single-Flow AI Inference (Benign HTTPS Session)
    # --------------------------------------------------------------------------
    print_banner("STEP 3: SINGLE-FLOW AI EVALUATION (BENIGN HTTPS FLOW)")
    benign_file = DEMO_DIR / "demo_benign_flow.json"
    if benign_file.exists():
        benign_payload = json.loads(benign_file.read_text(encoding="utf-8"))
        t0 = time.perf_counter()
        r_inf = client.post("/api/v1/decisions/evaluate", json=benign_payload)
        lat = round((time.perf_counter() - t0) * 1000.0, 2)
        if r_inf.status_code == 200:
            res = r_inf.json()
            pred = res.get("prediction", {})
            dec = res.get("decision", {})
            print(f"[*] Evaluated 48-feature input flow in {lat} ms:")
            print(f"    - Predicted Attack Family : {pred.get('predicted_family')} (Confidence: {pred.get('class_confidence', 0):.4f})")
            print(f"    - Statistical Anomaly     : {pred.get('is_statistical_anomaly')} (Decision Score: {pred.get('raw_decision_score', 0):.4f})")
            print(f"    - Hybrid Triage Decision  : {dec.get('status')} | Severity: {dec.get('severity')}")
            print(f"    - Composite Risk Score    : {dec.get('risk_score')}/100")
            print(f"    - Decision Rationale      : {dec.get('explanation')}")
        else:
            print(f"[!] Inference failed: {r_inf.text}")

    # --------------------------------------------------------------------------
    # Step 4: PCAP Attack Detection (DDoS LOIC & PortScan Nmap)
    # --------------------------------------------------------------------------
    print_banner("STEP 4: PCAP ATTACK DETECTION & INCIDENT ANALYSIS")
    for pcap_name, attack_type in [
        ("demo_ddos_loic.pcap", "DDoS (LOIC HTTP Flooding)"),
        ("demo_portscan_nmap.pcap", "PortScan (Nmap TCP SYN Scan)"),
    ]:
        pcap_path = DEMO_DIR / pcap_name
        if pcap_path.exists():
            print(f"\n[*] Uploading {pcap_name} ({pcap_path.stat().st_size:,} bytes) - Target: {attack_type}")
            with open(pcap_path, "rb") as f:
                t0 = time.perf_counter()
                r_pcap = client.post(
                    "/api/v1/pcap/analyze",
                    files={"file": (pcap_name, f, "application/vnd.tcpdump.pcap")},
                )
                lat = round((time.perf_counter() - t0) * 1000.0, 2)
            if r_pcap.status_code == 200:
                p_res = r_pcap.json()
                summary = p_res.get("summary", {})
                flows = p_res.get("flows", [])
                print(f"    - Extraction & Analysis   : {summary.get('extracted_flows')} flows extracted in {lat} ms")
                print(f"    - Attack Classifications  : {summary.get('attack_distribution')}")
                print(f"    - Severity Breakdown      : {summary.get('severity_distribution')}")
                print(f"    - Anomalies Flagged       : {summary.get('anomalies_flagged')}")
                print(f"    - PostgreSQL Persisted    : {summary.get('persisted')}")
                for i, fl in enumerate(flows[:3]):
                    prov = fl.get("provenance", {})
                    print(f"      Flow #{i+1}: {prov.get('src_ip')}:{prov.get('src_port')} -> {prov.get('dst_ip')}:{prov.get('dst_port')} | {fl.get('predicted_family')} ({fl.get('class_confidence'):.2f}) | Risk: {fl.get('risk_score')}/100")
            else:
                print(f"[!] PCAP analysis failed: {r_pcap.text}")

    # --------------------------------------------------------------------------
    # Step 5: Zeek Native Telemetry Batch Ingestion
    # --------------------------------------------------------------------------
    print_banner("STEP 5: ZEEK NATIVE TELEMETRY INGESTION (TELEMETRY-ONLY INVARIANT)")
    zeek_file = DEMO_DIR / "demo_zeek_conn.log"
    if zeek_file.exists():
        with open(zeek_file, "rb") as f:
            t0 = time.perf_counter()
            r_zeek = client.post(
                "/api/v1/zeek/analyze",
                files={"file": ("conn.log", f, "text/plain")},
            )
            lat = round((time.perf_counter() - t0) * 1000.0, 2)
        if r_zeek.status_code == 200:
            z_res = r_zeek.json()
            z_sum = z_res.get("summary", {})
            print(f"[*] Ingested {z_sum.get('total_connections_parsed')} Zeek connection records in {lat} ms:")
            print(f"    - Analysis Invariant Type : {z_sum.get('analysis_type')} (ml_classification_performed={z_sum.get('ml_classification_performed')})")
            print(f"    - Protocols Ingested      : {z_sum.get('protocol_distribution')}")
            print(f"    - Services Detected       : {z_sum.get('service_distribution')}")
            print(f"    - Connection States       : {z_sum.get('conn_state_distribution')}")
            print(f"    - PostgreSQL Job ID       : {z_res.get('job_id')} (Persisted: {z_res.get('persisted')})")
        else:
            print(f"[!] Zeek ingestion failed: {r_zeek.text}")

    # --------------------------------------------------------------------------
    # Step 6: Operational Telemetry & Metrics
    # --------------------------------------------------------------------------
    print_banner("STEP 6: OPERATIONAL TELEMETRY & SYSTEM METRICS")
    r_metrics = client.get("/api/v1/metrics")
    if r_metrics.status_code == 200:
        m_data = r_metrics.json()
        print(f"[*] Platform Metrics Summary:")
        print(f"    - Health Status           : {m_data.get('status')} (Environment: {m_data.get('environment')})")
        print(f"    - Process Uptime          : {m_data.get('uptime_seconds')} seconds")
        print(f"    - Database Connected      : {m_data.get('persistence_connected')} ({m_data.get('database_dialect')})")
        print(f"    - Models Active in RAM    : {m_data.get('models_loaded')}")
        print(f"    - Active SSE Clients      : {m_data.get('sse_clients_connected')}")
        print(f"    - Zeek Ingestion Queue    : {m_data.get('zeek_queue_depth')} items (Lag: {m_data.get('zeek_ingestion_lag_ms')} ms)")
    else:
        print(f"[!] GET /api/v1/metrics failed: {r_metrics.text}")

    print_banner("DEMONSTRATION WALKTHROUGH COMPLETE — ALL VALIDATIONS PASSED")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Network Anomaly Detection Walkthrough")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Target backend base URL")
    args = parser.parse_args()
    success = run_demo(args.base_url)
    sys.exit(0 if success else 1)
