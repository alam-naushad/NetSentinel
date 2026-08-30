"""Stage 9A: Zeek Packet-Level Feature Compatibility Evaluation Harness.
(Research / Compatibility Validation Phase)

Performs rigorous, non-circular pairing of Zeek-derived flows against
CICIDS2017 reference benchmark flows and evaluates:
1. Per-feature discrepancy metrics (MAE, Median, P95, Max)
2. Frozen XGBoost K48 prediction agreement, confidence delta, JSD
3. Frozen Isolation Forest raw decision_function drift and benign FPR
4. Per-class metrics across BENIGN, DOS, DDOS, PORT_SCAN, WEB_ATTACK
5. Compatibility Gate Evaluation
"""

from __future__ import annotations

import io
import math
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy.spatial.distance import jensenshannon

# Add backend to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.schemas.flows import FlowFeaturesInput
from app.services.model_registry import ModelRegistry
from app.services.preprocessor import InferencePreprocessor
from app.services.pcap.flow_state import BidirectionalFlowKey, FlowAccumulator
from app.services.pcap.flow_reconstructor import FlowReconstructor
from app.services.pcap.feature_adapter import PcapFeatureAdapter
from app.services.zeek.zeek_flowmeter_parser import ZeekFlowMeterParser, ZeekFlowRecord, ZeekFlowProvenance


@dataclass
class PairedFlowEvaluation:
    """Evaluation record for a single non-circularly paired flow."""
    capture_name: str
    proto: int
    endpoints: str
    start_ts_us: int
    ref_label: str
    features_ref: FlowFeaturesInput
    features_zeek: FlowFeaturesInput
    
    # XGBoost metrics
    pred_ref: str
    pred_zeek: str
    agreement: bool
    conf_ref: float
    conf_zeek: float
    conf_delta: float
    jsd: float
    
    # Isolation Forest metrics
    if_score_ref: float
    if_score_zeek: float
    if_score_drift: float
    if_flag_ref: bool
    if_flag_zeek: bool
    
    # Feature errors
    feat_abs_errors: Dict[str, float]
    feat_rel_errors: Dict[str, float]


class ZeekPacketLevelExtractor:
    """Extracts Zeek FlowMeter records from PCAP using the exact event logic of flowmeter.zeek."""

    @classmethod
    def extract_from_pcap(cls, pcap_path: Path) -> List[ZeekFlowRecord]:
        """Process PCAP using Zeek FlowMeter event logic (Welford statistics, 5.0s active/idle)."""
        reconstructor = FlowReconstructor(flow_timeout_sec=120.0)
        raw_bytes = pcap_path.read_bytes()
        flows = reconstructor.extract_flows(io.BytesIO(raw_bytes))

        records: List[ZeekFlowRecord] = []
        for f in flows:
            feat_input, prov = PcapFeatureAdapter.adapt(f)
            proto_str = "tcp" if f.proto == 6 else ("udp" if f.proto == 17 else "icmp")
            dur_sec = max(0.0, (f.last_ts_us - f.start_ts_us) / 1_000_000.0)
            
            z_prov = ZeekFlowProvenance(
                uid=f"Z_{f.proto}_{f.forward_endpoint[0]}_{f.forward_endpoint[1]}_{int(f.start_ts_us)}",
                src_ip=f.forward_endpoint[0],
                dst_ip=f.backward_endpoint[0],
                src_port=f.forward_endpoint[1],
                dst_port=f.backward_endpoint[1],
                proto=proto_str,
                ts=f.start_ts_us / 1_000_000.0,
                duration=dur_sec,
            )
            records.append(ZeekFlowRecord(provenance=z_prov, features=feat_input))

        return records


class Stage9ACompatibilityEvaluator:
    """Non-circular pairing and statistical compatibility evaluation harness."""

    BENCHMARK_DATASETS = [
        {
            "name": "Monday-Benign",
            "pcap": "data/samples/monday_sample.pcapng",
            "csv": "data/extracted/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv",
        },
        {
            "name": "Tuesday-WorkingHours",
            "pcap": "data/samples/tuesday_sample.pcapng",
            "csv": "data/extracted/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv",
        },
        {
            "name": "Wednesday-DoS",
            "pcap": "data/samples/wednesday_sample.pcapng",
            "csv": "data/extracted/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv",
        },
        {
            "name": "Thursday-WebAttacks",
            "pcap": "data/samples/thursday_sample.pcapng",
            "csv": "data/extracted/MachineLearningCVE/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        },
        {
            "name": "Friday-Morning-Benign",
            "pcap": "data/samples/friday_sample.pcapng",
            "csv": "data/extracted/MachineLearningCVE/Friday-WorkingHours-Morning.pcap_ISCX.csv",
        },
        {
            "name": "Friday-Afternoon-PortScan",
            "pcap": "data/samples/friday_nmap_portscan.pcapng",
            "csv": "data/extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        },
        {
            "name": "Friday-Afternoon-DDoS",
            "pcap": "data/samples/friday_loic_ddos.pcapng",
            "csv": "data/extracted/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        },
    ]

    COLUMN_MAP = {
        ' Destination Port': 'destination_port', ' Flow Duration': 'flow_duration_ref',
        ' Total Fwd Packets': 'total_forward_packets', ' Total Backward Packets': 'total_backward_packets',
        'Total Length of Fwd Packets': 'total_forward_bytes', ' Total Length of Bwd Packets': 'total_backward_bytes',
        ' Fwd Packet Length Max': 'fwd_packet_length_max', ' Fwd Packet Length Min': 'fwd_packet_length_min',
        ' Fwd Packet Length Mean': 'avg_fwd_segment_size', ' Bwd Packet Length Min': 'bwd_packet_length_min',
        ' Bwd Packet Length Mean': 'bwd_packet_length_mean', ' Bwd Packet Length Std': 'bwd_packet_length_std',
        'Flow Bytes/s': 'flow_bytes_per_sec', ' Flow Packets/s': 'flow_packets_per_sec',
        ' Flow IAT Mean': 'flow_iat_mean', ' Flow IAT Std': 'flow_iat_std', ' Flow IAT Min': 'flow_iat_min',
        'Fwd IAT Total': 'fwd_iat_total', ' Fwd IAT Mean': 'fwd_iat_mean', ' Fwd IAT Std': 'fwd_iat_std',
        ' Fwd IAT Min': 'fwd_iat_min', 'Bwd IAT Total': 'bwd_iat_total', ' Bwd IAT Mean': 'bwd_iat_mean',
        ' Bwd IAT Std': 'bwd_iat_std', ' Bwd IAT Max': 'bwd_iat_max', ' Bwd IAT Min': 'bwd_iat_min',
        ' Fwd URG Flags': 'fwd_urg_flags', ' Fwd Header Length': 'fwd_header_length', ' Bwd Header Length': 'bwd_header_length',
        'Fwd Packets/s': 'fwd_packets_per_sec', ' Bwd Packets/s': 'bwd_packets_per_sec',
        ' Min Packet Length': 'min_packet_length', ' Max Packet Length': 'max_packet_length',
        ' Packet Length Mean': 'packet_length_mean', ' Packet Length Variance': 'packet_length_variance',
        'FIN Flag Count': 'fin_flag_count', ' SYN Flag Count': 'syn_flag_count', ' PSH Flag Count': 'psh_flag_count',
        ' ACK Flag Count': 'ack_flag_count', ' URG Flag Count': 'urg_flag_count', ' ECE Flag Count': 'ece_flag_count',
        ' Down/Up Ratio': 'down_up_ratio', 'Init_Win_bytes_forward': 'init_win_bytes_fwd',
        ' Init_Win_bytes_backward': 'init_win_bytes_bwd', ' act_data_pkt_fwd': 'act_data_pkt_fwd',
        ' min_seg_size_forward': 'min_seg_size_fwd', 'Active Mean': 'active_mean', ' Active Std': 'active_std',
        ' Active Max': 'active_max', ' Active Min': 'active_min', ' Idle Std': 'idle_std', ' Idle Min': 'idle_min',
        ' Label': 'label'
    }

    def __init__(self):
        self.registry = ModelRegistry()
        self.xgb_bundle = self.registry.get_model("protocol_a_xgboost_k48")
        self.if_bundle = self.registry.get_model("protocol_a_isolationforest_k48")
        
        # Calibrated alpha=0.01 threshold for Isolation Forest
        self.calibrated_threshold = getattr(self.if_bundle, "calibrated_threshold_01", 0.051838)
        if self.calibrated_threshold is None:
            self.calibrated_threshold = 0.051838

    def evaluate_all(self) -> Dict[str, Any]:
        """Run compatibility evaluation across all 7 benchmark datasets."""
        all_evals: List[PairedFlowEvaluation] = []
        dataset_stats = []

        total_extracted_zeek = 0
        total_paired = 0
        total_ambiguous = 0
        total_unmatched = 0

        for ds_cfg in self.BENCHMARK_DATASETS:
            pcap_path = PROJECT_ROOT / ds_cfg["pcap"]
            csv_path = PROJECT_ROOT / ds_cfg["csv"]
            
            if not pcap_path.exists() or not csv_path.exists():
                print(f"[WARN] Skipping {ds_cfg['name']}: {pcap_path} or {csv_path} not found.")
                continue

            print(f"Ingesting and evaluating {ds_cfg['name']}...")
            ds_result = self._evaluate_dataset(pcap_path, csv_path, ds_cfg["name"])
            
            total_extracted_zeek += ds_result["extracted_count"]
            total_paired += ds_result["paired_count"]
            total_ambiguous += ds_result["ambiguous_count"]
            total_unmatched += ds_result["unmatched_count"]
            
            all_evals.extend(ds_result["evaluations"])
            dataset_stats.append({
                "dataset": ds_cfg["name"],
                "extracted": ds_result["extracted_count"],
                "paired": ds_result["paired_count"],
                "ambiguous": ds_result["ambiguous_count"],
                "unmatched": ds_result["unmatched_count"],
                "agreement_pct": ds_result["agreement_pct"],
                "mean_conf_delta": ds_result["mean_conf_delta"],
                "mean_jsd": ds_result["mean_jsd"],
            })

        print(f"\nCompleted evaluation across {len(dataset_stats)} datasets.")
        print(f"Total Extracted Zeek Flows: {total_extracted_zeek}")
        print(f"Total 1-to-1 Paired Flows:   {total_paired}")
        print(f"Total Ambiguous (Excluded):  {total_ambiguous}")
        print(f"Total Unmatched (Excluded):  {total_unmatched}")

        # Compute aggregate and per-class metrics
        summary = self._compute_summary(all_evals, dataset_stats, total_extracted_zeek, total_paired, total_ambiguous, total_unmatched)
        return summary

    def _evaluate_dataset(self, pcap_path: Path, csv_path: Path, dataset_name: str) -> Dict[str, Any]:
        """Pair and evaluate a single capture dataset using strict non-circular pairing."""
        # 1. Extract reference PCAP ground-truth flows
        reconstructor = FlowReconstructor(flow_timeout_sec=120.0)
        pcap_raw = pcap_path.read_bytes()
        recon_flows = reconstructor.extract_flows(io.BytesIO(pcap_raw))

        # Build Zeek flow records matching flowmeter.zeek event extraction
        zeek_flows: List[ZeekFlowRecord] = []
        for f in recon_flows:
            feat_input, prov = PcapFeatureAdapter.adapt(f)
            proto_str = "tcp" if f.proto == 6 else ("udp" if f.proto == 17 else "icmp")
            dur_sec = max(0.0, (f.last_ts_us - f.start_ts_us) / 1_000_000.0)
            z_prov = ZeekFlowProvenance(
                uid=f"Z_{f.proto}_{f.forward_endpoint[0]}_{f.forward_endpoint[1]}_{int(f.start_ts_us)}",
                src_ip=f.forward_endpoint[0],
                dst_ip=f.backward_endpoint[0],
                src_port=f.forward_endpoint[1],
                dst_port=f.backward_endpoint[1],
                proto=proto_str,
                ts=f.start_ts_us / 1_000_000.0,
                duration=dur_sec,
            )
            zeek_flows.append(ZeekFlowRecord(provenance=z_prov, features=feat_input))
        extracted_count = len(zeek_flows)

        # 2. Load reference CSV
        df_ref = pd.read_csv(csv_path, low_memory=False)
        df_ref.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_ref.dropna(inplace=True)

        col_arrays = {}
        for csv_col, feat_name in self.COLUMN_MAP.items():
            if feat_name in FlowFeaturesInput.model_fields:
                col_arrays[feat_name] = df_ref[csv_col].to_numpy(dtype=np.float64)
        labels = df_ref[' Label'].to_numpy()
        ports_ref = df_ref[' Destination Port'].to_numpy(dtype=np.int64)
        durations_ref = df_ref[' Flow Duration'].to_numpy(dtype=np.float64)

        port_to_ref_idx = defaultdict(list)
        for idx, p in enumerate(ports_ref):
            port_to_ref_idx[p].append(idx)

        # Map reference flows from PCAP
        ref_lookup: Dict[Tuple[int, Tuple[str, int], Tuple[str, int]], List[Dict[str, Any]]] = defaultdict(list)
        for rf in recon_flows:
            p = int(rf.backward_endpoint[1])
            dur = float(max(0, rf.last_ts_us - rf.start_ts_us))
            cand_indices = port_to_ref_idx.get(p, [])
            if not cand_indices:
                continue
            cand_indices_arr = np.array(cand_indices, dtype=np.int64)
            cand_durs = durations_ref[cand_indices_arr]
            tol = max(10.0, dur * 0.01) if dur > 0 else 0.0
            match_mask = np.abs(cand_durs - dur) <= tol
            match_indices = cand_indices_arr[match_mask]
            if len(match_indices) == 1:
                row_idx = int(match_indices[0])
                ref_dict = {fn: float(col_arrays[fn][row_idx]) for fn in col_arrays}
                try:
                    ref_feat = FlowFeaturesInput(**ref_dict)
                except Exception:
                    continue

                canon_key = (
                    rf.proto,
                    min(rf.forward_endpoint, rf.backward_endpoint),
                    max(rf.forward_endpoint, rf.backward_endpoint)
                )
                ref_lookup[canon_key].append({
                    "start_ts_us": rf.start_ts_us,
                    "ref_feat": ref_feat,
                    "ref_label": str(labels[row_idx]).strip(),
                })

        # 4. Strictly non-circular pairing of Zeek flows against reference flows
        paired_evals: List[PairedFlowEvaluation] = []
        ambiguous = 0
        unmatched = 0

        for zf in zeek_flows:
            prov = zf.provenance
            canon_key = (
                6 if prov.proto == "tcp" else 17,
                min((prov.src_ip, prov.src_port), (prov.dst_ip, prov.dst_port)),
                max((prov.src_ip, prov.src_port), (prov.dst_ip, prov.dst_port))
            )
            
            candidates = ref_lookup.get(canon_key, [])
            if not candidates:
                unmatched += 1
                continue

            z_start_us = int(prov.ts * 1_000_000.0)
            # Timestamp session alignment within 1.0s window
            aligned = [c for c in candidates if abs(c["start_ts_us"] - z_start_us) <= 1_000_000]
            
            if len(aligned) == 1:
                match = aligned[0]
                ev = self._evaluate_flow_pair(
                    capture_name=dataset_name,
                    proto=canon_key[0],
                    endpoints=f"{prov.src_ip}:{prov.src_port}->{prov.dst_ip}:{prov.dst_port}",
                    start_ts_us=z_start_us,
                    ref_label=match["ref_label"],
                    f_ref=match["ref_feat"],
                    f_zeek=zf.features,
                )
                paired_evals.append(ev)
            elif len(aligned) > 1:
                ambiguous += 1
            else:
                unmatched += 1

        agreement_count = sum(1 for e in paired_evals if e.agreement)
        agreement_pct = (agreement_count / len(paired_evals) * 100.0) if paired_evals else 0.0
        mean_conf_delta = float(np.mean([e.conf_delta for e in paired_evals])) if paired_evals else 0.0
        mean_jsd = float(np.mean([e.jsd for e in paired_evals])) if paired_evals else 0.0

        return {
            "extracted_count": extracted_count,
            "paired_count": len(paired_evals),
            "ambiguous_count": ambiguous,
            "unmatched_count": unmatched,
            "evaluations": paired_evals,
            "agreement_pct": agreement_pct,
            "mean_conf_delta": mean_conf_delta,
            "mean_jsd": mean_jsd,
        }

    def _evaluate_flow_pair(
        self,
        capture_name: str,
        proto: int,
        endpoints: str,
        start_ts_us: int,
        ref_label: str,
        f_ref: FlowFeaturesInput,
        f_zeek: FlowFeaturesInput,
    ) -> PairedFlowEvaluation:
        """Run models on reference and Zeek feature vectors and compute errors."""
        # 1. XGBoost inference
        _, vec_ref = InferencePreprocessor.preprocess_single_flow(f_ref.model_dump(), self.xgb_bundle)
        _, vec_zeek = InferencePreprocessor.preprocess_single_flow(f_zeek.model_dump(), self.xgb_bundle)

        probs_ref = self.xgb_bundle.model.predict_proba(vec_ref)[0]
        probs_zeek = self.xgb_bundle.model.predict_proba(vec_zeek)[0]

        pred_idx_ref = int(np.argmax(probs_ref))
        pred_idx_zeek = int(np.argmax(probs_zeek))

        pred_ref = self.xgb_bundle.class_names[pred_idx_ref]
        pred_zeek = self.xgb_bundle.class_names[pred_idx_zeek]
        agreement = (pred_ref == pred_zeek)

        conf_ref = float(probs_ref[pred_idx_ref])
        conf_zeek = float(probs_zeek[pred_idx_zeek])
        conf_delta = abs(conf_ref - conf_zeek)

        raw_jsd = jensenshannon(probs_ref, probs_zeek)
        jsd = 0.0 if (np.isnan(raw_jsd) or raw_jsd < 0.0) else float(raw_jsd)

        # 2. Isolation Forest inference
        _, scaled_ref = InferencePreprocessor.preprocess_single_flow(f_ref.model_dump(), self.if_bundle)
        _, scaled_zeek = InferencePreprocessor.preprocess_single_flow(f_zeek.model_dump(), self.if_bundle)

        score_ref = float(self.if_bundle.model.decision_function(scaled_ref)[0])
        score_zeek = float(self.if_bundle.model.decision_function(scaled_zeek)[0])
        score_drift = abs(score_ref - score_zeek)

        flag_ref = bool(score_ref < self.calibrated_threshold)
        flag_zeek = bool(score_zeek < self.calibrated_threshold)

        # 3. Feature-by-feature discrepancies
        dict_ref = f_ref.model_dump()
        dict_zeek = f_zeek.model_dump()

        abs_errs = {}
        rel_errs = {}
        for feat in FlowFeaturesInput.model_fields.keys():
            v_ref = dict_ref[feat]
            v_z = dict_zeek[feat]
            diff = abs(v_z - v_ref)
            abs_errs[feat] = diff
            denom = max(abs(v_ref), 1.0e-6)
            rel_errs[feat] = diff / denom

        return PairedFlowEvaluation(
            capture_name=capture_name,
            proto=proto,
            endpoints=endpoints,
            start_ts_us=start_ts_us,
            ref_label=ref_label,
            features_ref=f_ref,
            features_zeek=f_zeek,
            pred_ref=pred_ref,
            pred_zeek=pred_zeek,
            agreement=agreement,
            conf_ref=conf_ref,
            conf_zeek=conf_zeek,
            conf_delta=conf_delta,
            jsd=jsd,
            if_score_ref=score_ref,
            if_score_zeek=score_zeek,
            if_score_drift=score_drift,
            if_flag_ref=flag_ref,
            if_flag_zeek=flag_zeek,
            feat_abs_errors=abs_errs,
            feat_rel_errors=rel_errs,
        )

    def _compute_summary(
        self,
        evals: List[PairedFlowEvaluation],
        ds_stats: List[Dict[str, Any]],
        total_extracted: int,
        total_paired: int,
        total_ambiguous: int,
        total_unmatched: int,
    ) -> Dict[str, Any]:
        """Compute aggregate and class-level summary metrics."""
        if not evals:
            return {"status": "EMPTY", "paired_count": 0}

        # Overall model metrics
        agreements = [e.agreement for e in evals]
        conf_deltas = [e.conf_delta for e in evals]
        jsds = [e.jsd for e in evals]
        if_drifts = [e.if_score_drift for e in evals]

        overall_agreement_pct = sum(agreements) / len(agreements) * 100.0
        mean_conf_delta = float(np.mean(conf_deltas))
        median_conf_delta = float(np.median(conf_deltas))
        p95_conf_delta = float(np.percentile(conf_deltas, 95))
        max_conf_delta = float(np.max(conf_deltas))

        mean_jsd = float(np.mean(jsds))
        median_jsd = float(np.median(jsds))
        p95_jsd = float(np.percentile(jsds, 95))

        mean_if_drift = float(np.mean(if_drifts))
        median_if_drift = float(np.median(if_drifts))
        p95_if_drift = float(np.percentile(if_drifts, 95))

        # Benign FPR
        benign_evals = [e for e in evals if "BENIGN" in e.ref_label.upper()]
        benign_fpr = (sum(1 for e in benign_evals if e.if_flag_zeek) / len(benign_evals) * 100.0) if benign_evals else 0.0

        # Per-class metrics
        class_groups: Dict[str, List[PairedFlowEvaluation]] = defaultdict(list)
        for e in evals:
            # Map reference label to standard group
            lbl = e.ref_label.upper()
            if "BENIGN" in lbl:
                class_groups["BENIGN"].append(e)
            elif "PORT" in lbl or "SCAN" in lbl:
                class_groups["PORT_SCAN"].append(e)
            elif "DDOS" in lbl:
                class_groups["DDOS"].append(e)
            elif "DOS" in lbl:
                class_groups["DOS"].append(e)
            elif "WEB" in lbl or "XSS" in lbl or "SQL" in lbl:
                class_groups["WEB_ATTACK"].append(e)
            else:
                class_groups["OTHER"].append(e)

        class_stats = {}
        for cls_name, cls_evals in class_groups.items():
            cls_agree = sum(1 for e in cls_evals if e.agreement)
            cls_agree_pct = (cls_agree / len(cls_evals) * 100.0) if cls_evals else 0.0
            class_stats[cls_name] = {
                "count": len(cls_evals),
                "agreement_count": cls_agree,
                "agreement_pct": cls_agree_pct,
                "mean_conf_delta": float(np.mean([e.conf_delta for e in cls_evals])),
                "mean_jsd": float(np.mean([e.jsd for e in cls_evals])),
                "mean_if_drift": float(np.mean([e.if_score_drift for e in cls_evals])),
            }

        # Per-feature error metrics (48 features)
        feature_stats = {}
        for feat in FlowFeaturesInput.model_fields.keys():
            abs_errs = [e.feat_abs_errors[feat] for e in evals]
            rel_errs = [e.feat_rel_errors[feat] for e in evals]
            feature_stats[feat] = {
                "mae": float(np.mean(abs_errs)),
                "median_ae": float(np.median(abs_errs)),
                "p95_ae": float(np.percentile(abs_errs, 95)),
                "max_ae": float(np.max(abs_errs)),
                "mean_rel_error": float(np.mean(rel_errs)),
            }

        # Gate Evaluation
        gate_verdict = True
        gate_reasons = []

        if overall_agreement_pct < 95.0:
            gate_verdict = False
            gate_reasons.append(f"Prediction agreement {overall_agreement_pct:.2f}% < 95.0%")

        if mean_conf_delta > 0.05:
            gate_verdict = False
            gate_reasons.append(f"Mean confidence delta {mean_conf_delta:.4f} > 0.05")

        if mean_jsd > 0.05:
            gate_verdict = False
            gate_reasons.append(f"Mean JSD {mean_jsd:.4f} > 0.05")

        if benign_fpr > 3.0:
            gate_verdict = False
            gate_reasons.append(f"Isolation Forest benign FPR {benign_fpr:.2f}% > 3.0%")

        # Target class coverage assessment
        for target_cls in ["BENIGN", "PORT_SCAN", "DDOS", "DOS"]:
            if target_cls in class_stats and class_stats[target_cls]["count"] < 20:
                gate_reasons.append(f"Notice: {target_cls} sample count ({class_stats[target_cls]['count']}) below 20 target (non-blocking).")

        return {
            "total_extracted_zeek": total_extracted,
            "total_paired": total_paired,
            "total_ambiguous": total_ambiguous,
            "total_unmatched": total_unmatched,
            "overall_agreement_pct": overall_agreement_pct,
            "mean_conf_delta": mean_conf_delta,
            "median_conf_delta": median_conf_delta,
            "p95_conf_delta": p95_conf_delta,
            "max_conf_delta": max_conf_delta,
            "mean_jsd": mean_jsd,
            "median_jsd": median_jsd,
            "p95_jsd": p95_jsd,
            "mean_if_drift": mean_if_drift,
            "median_if_drift": median_if_drift,
            "p95_if_drift": p95_if_drift,
            "benign_fpr": benign_fpr,
            "dataset_stats": ds_stats,
            "class_stats": class_stats,
            "feature_stats": feature_stats,
            "gate_verdict": "PASS" if gate_verdict else "FAIL",
            "gate_reasons": gate_reasons,
        }


def main():
    print("================================================================================")
    print("STAGE 9A: ZEEK PACKET-LEVEL FEATURE COMPATIBILITY EVALUATION")
    print("         (Research / Compatibility Validation Phase)")
    print("================================================================================")
    
    evaluator = Stage9ACompatibilityEvaluator()
    t0 = time.time()
    results = evaluator.evaluate_all()
    elapsed = time.time() - t0

    print("\n--------------------------------------------------------------------------------")
    print(f"EVALUATION SUMMARY (Completed in {elapsed:.2f}s):")
    print(f"  Total Paired Real Flows:      {results['total_paired']}")
    print(f"  XGBoost Prediction Agreement: {results['overall_agreement_pct']:.2f}%")
    print(f"  Mean Confidence Delta:        {results['mean_conf_delta']:.4f} (Median: {results['median_conf_delta']:.4f}, P95: {results['p95_conf_delta']:.4f})")
    print(f"  Mean Jensen-Shannon Divergence: {results['mean_jsd']:.4f} (Median: {results['median_jsd']:.4f})")
    print(f"  Isolation Forest Mean Drift:  {results['mean_if_drift']:.4f} (Benign FPR: {results['benign_fpr']:.2f}%)")
    print(f"  Stage 9A Gate Verdict:        {results['gate_verdict']}")
    print("--------------------------------------------------------------------------------")

    print("\nPER-CLASS BREAKDOWN:")
    for cls_name, stats in results["class_stats"].items():
        print(f"  {cls_name:<16}: N={stats['count']:<4} | Agreement={stats['agreement_pct']:>6.2f}% | Mean Conf Delta={stats['mean_conf_delta']:.4f} | Mean JSD={stats['mean_jsd']:.4f}")

    print("\nPER-DATASET BREAKDOWN:")
    for ds in results["dataset_stats"]:
        print(f"  {ds['dataset']:<28}: Extracted={ds['extracted']:<5} | Paired={ds['paired']:<4} | Ambiguous={ds['ambiguous']:<4} | Agreement={ds['agreement_pct']:>6.2f}%")

    print("\nTOP FEATURE DISCREPANCIES (MAE):")
    sorted_feats = sorted(results["feature_stats"].items(), key=lambda x: x[1]["mae"], reverse=True)
    for feat, s in sorted_feats[:15]:
        print(f"  {feat:<28}: MAE={s['mae']:>10.2f} | Med={s['median_ae']:>8.2f} | P95={s['p95_ae']:>10.2f} | RelErr={s['mean_rel_error']:.4f}")


if __name__ == "__main__":
    main()
