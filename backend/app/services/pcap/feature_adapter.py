import math
import numpy as np
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Dict, List, Tuple
from app.schemas.flows import FlowFeaturesInput
from app.services.pcap.flow_state import FlowAccumulator

@dataclass(frozen=True, slots=True)
class PcapFlowProvenance:
    """Strictly isolated flow provenance metadata preserving packet capture origin."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_proto: int
    protocol_name: str
    start_time_iso: str
    end_time_iso: str
    duration_ms: float
    total_packets: int
    total_bytes: int

class PcapFeatureAdapter:
    """Transforms FlowAccumulator state into canonical 48-feature FlowFeaturesInput."""

    @staticmethod
    def _sample_mean(values: List[int]) -> float:
        if not values:
            return 0.0
        return float(np.mean(values))

    @staticmethod
    def _sample_std(values: List[int]) -> float:
        if len(values) <= 1:
            return 0.0
        return float(np.std(values, ddof=1))

    @staticmethod
    def _sample_variance(values: List[int]) -> float:
        if len(values) <= 1:
            return 0.0
        return float(np.var(values, ddof=1))

    @staticmethod
    def _sample_min(values: List[int]) -> float:
        if not values:
            return 0.0
        return float(np.min(values))

    @staticmethod
    def _sample_max(values: List[int]) -> float:
        if not values:
            return 0.0
        return float(np.max(values))

    @classmethod
    def adapt(cls, flow: FlowAccumulator) -> Tuple[FlowFeaturesInput, PcapFlowProvenance]:
        """Convert a closed FlowAccumulator into (FlowFeaturesInput, PcapFlowProvenance)."""
        duration_us = max(0, flow.last_ts_us - flow.start_ts_us)
        duration_sec = duration_us / 1_000_000.0
        duration_ms = duration_us / 1_000.0

        # Destination port of forward direction
        dst_port = float(flow.backward_endpoint[1])

        # Rates (safe with duration_sec = 0)
        tot_bytes = flow.fwd_bytes_total + flow.bwd_bytes_total
        if duration_sec > 0:
            flow_bytes_sec = float(tot_bytes) / duration_sec
            fwd_pkts_sec = float(flow.fwd_packet_count) / duration_sec
            bwd_pkts_sec = float(flow.bwd_packet_count) / duration_sec
        else:
            flow_bytes_sec = 0.0
            fwd_pkts_sec = 0.0
            bwd_pkts_sec = 0.0

        # Down/Up Ratio
        if flow.fwd_packet_count > 0:
            down_up_ratio = float(flow.bwd_packet_count) / float(flow.fwd_packet_count)
        else:
            down_up_ratio = 0.0

        # Avg forward segment size
        if flow.fwd_packet_count > 0:
            avg_fwd_seg = float(sum(flow.fwd_lengths)) / float(flow.fwd_packet_count)
        else:
            avg_fwd_seg = 0.0

        # IAT Totals
        fwd_iat_tot = float(sum(flow.fwd_iats)) if flow.fwd_iats else 0.0
        bwd_iat_tot = float(sum(flow.bwd_iats)) if flow.bwd_iats else 0.0

        # Construct FlowFeaturesInput (canonical 48 model features)
        features = FlowFeaturesInput(
            destination_port=dst_port,
            flow_bytes_per_sec=flow_bytes_sec,
            fwd_packets_per_sec=fwd_pkts_sec,
            bwd_packets_per_sec=bwd_pkts_sec,
            min_packet_length=cls._sample_min(flow.all_lengths),
            max_packet_length=cls._sample_max(flow.all_lengths),
            packet_length_mean=cls._sample_mean(flow.all_lengths),
            packet_length_variance=cls._sample_variance(flow.all_lengths),
            fin_flag_count=float(flow.fin_flag_count),
            syn_flag_count=float(flow.syn_flag_count),
            psh_flag_count=float(flow.psh_flag_count),
            ack_flag_count=float(flow.ack_flag_count),
            urg_flag_count=float(flow.urg_flag_count),
            ece_flag_count=float(flow.ece_flag_count),
            down_up_ratio=down_up_ratio,
            avg_fwd_segment_size=avg_fwd_seg,
            fwd_header_length=float(flow.fwd_hdr_lengths_total),
            bwd_header_length=float(flow.bwd_hdr_lengths_total),
            min_seg_size_fwd=float(flow.min_seg_size_fwd),
            act_data_pkt_fwd=float(flow.act_data_pkt_fwd),
            init_win_bytes_fwd=float(flow.init_win_bytes_fwd),
            init_win_bytes_bwd=float(flow.init_win_bytes_bwd),
            active_mean=cls._sample_mean(flow.active_durations),
            active_std=cls._sample_std(flow.active_durations),
            active_max=cls._sample_max(flow.active_durations),
            active_min=cls._sample_min(flow.active_durations),
            idle_std=cls._sample_std(flow.idle_durations),
            idle_min=cls._sample_min(flow.idle_durations),
            fwd_iat_total=fwd_iat_tot,
            fwd_iat_mean=cls._sample_mean(flow.fwd_iats),
            fwd_iat_std=cls._sample_std(flow.fwd_iats),
            fwd_iat_min=cls._sample_min(flow.fwd_iats),
            bwd_iat_total=bwd_iat_tot,
            bwd_iat_mean=cls._sample_mean(flow.bwd_iats),
            bwd_iat_std=cls._sample_std(flow.bwd_iats),
            bwd_iat_max=cls._sample_max(flow.bwd_iats),
            bwd_iat_min=cls._sample_min(flow.bwd_iats),
            flow_iat_mean=cls._sample_mean(flow.flow_iats),
            flow_iat_std=cls._sample_std(flow.flow_iats),
            flow_iat_min=cls._sample_min(flow.flow_iats),
            fwd_packet_length_max=cls._sample_max(flow.fwd_lengths),
            fwd_packet_length_min=cls._sample_min(flow.fwd_lengths),
            bwd_packet_length_min=cls._sample_min(flow.bwd_lengths),
            bwd_packet_length_mean=cls._sample_mean(flow.bwd_lengths),
            bwd_packet_length_std=cls._sample_std(flow.bwd_lengths),
            total_forward_packets=float(flow.fwd_packet_count),
            total_forward_bytes=float(flow.fwd_bytes_total),
            fwd_urg_flags=float(flow.fwd_urg_flags),
        )

        # Construct Provenance Metadata (strictly separated from model features)
        start_iso = datetime.fromtimestamp(flow.start_ts_us / 1_000_000.0, tz=timezone.utc).isoformat()
        end_iso = datetime.fromtimestamp(flow.last_ts_us / 1_000_000.0, tz=timezone.utc).isoformat()
        proto_str = "TCP" if flow.proto == 6 else "UDP" if flow.proto == 17 else f"IP_{flow.proto}"
        flow_id = f"{proto_str}_{flow.forward_endpoint[0]}_{flow.forward_endpoint[1]}_{flow.backward_endpoint[0]}_{flow.backward_endpoint[1]}_{flow.start_ts_us}"

        provenance = PcapFlowProvenance(
            flow_id=flow_id,
            src_ip=flow.forward_endpoint[0],
            dst_ip=flow.backward_endpoint[0],
            src_port=flow.forward_endpoint[1],
            dst_port=flow.backward_endpoint[1],
            ip_proto=flow.proto,
            protocol_name=proto_str,
            start_time_iso=start_iso,
            end_time_iso=end_iso,
            duration_ms=round(duration_ms, 3),
            total_packets=flow.fwd_packet_count + flow.bwd_packet_count,
            total_bytes=tot_bytes,
        )

        return features, provenance
