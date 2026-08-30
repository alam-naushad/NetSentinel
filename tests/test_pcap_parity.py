import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.pcap.parity_validator import PcapParityValidator
from app.schemas.flows import FlowFeaturesInput

class PcapParityTests(unittest.TestCase):
    """Tests for empirical parity validator."""

    def test_parity_validator_computes_exact_metrics(self):
        f_ref = FlowFeaturesInput(
            destination_port=80.0, flow_bytes_per_sec=1000.0, fwd_packets_per_sec=10.0, bwd_packets_per_sec=5.0,
            min_packet_length=40.0, max_packet_length=1500.0, packet_length_mean=500.0, packet_length_variance=250000.0,
            fin_flag_count=0.0, syn_flag_count=1.0, psh_flag_count=0.0, ack_flag_count=1.0, urg_flag_count=0.0, ece_flag_count=0.0,
            down_up_ratio=0.5, avg_fwd_segment_size=500.0, fwd_header_length=40.0, bwd_header_length=40.0, min_seg_size_fwd=20.0,
            act_data_pkt_fwd=2.0, init_win_bytes_fwd=65535.0, init_win_bytes_bwd=29200.0, active_mean=0.0, active_std=0.0,
            active_max=0.0, active_min=0.0, idle_std=0.0, idle_min=0.0, fwd_iat_total=100000.0, fwd_iat_mean=50000.0,
            fwd_iat_std=10000.0, fwd_iat_min=40000.0, bwd_iat_total=50000.0, bwd_iat_mean=50000.0, bwd_iat_std=0.0,
            bwd_iat_max=50000.0, bwd_iat_min=50000.0, flow_iat_mean=33333.0, flow_iat_std=15000.0, flow_iat_min=20000.0,
            fwd_packet_length_max=1500.0, fwd_packet_length_min=40.0, bwd_packet_length_min=40.0, bwd_packet_length_mean=500.0,
            bwd_packet_length_std=200.0, total_forward_packets=3.0, total_forward_bytes=1500.0, fwd_urg_flags=0.0
        )

        f_recon = f_ref.model_copy(update={'flow_bytes_per_sec': 1005.0})

        metrics = PcapParityValidator.evaluate_feature_parity([f_recon], [f_ref])
        self.assertEqual(len(metrics), 48)
        self.assertEqual(metrics['destination_port'].mean_abs_error, 0.0)
        self.assertEqual(metrics['flow_bytes_per_sec'].mean_abs_error, 5.0)
        self.assertAlmostEqual(metrics['flow_bytes_per_sec'].mean_rel_error, 0.005, places=3)
