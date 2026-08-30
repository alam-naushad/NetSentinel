import sys
import math
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import dpkt
from app.services.pcap.flow_state import BidirectionalFlowKey, FlowAccumulator
from app.services.pcap.feature_adapter import PcapFeatureAdapter
from app.services.pcap.pcap_reader import RawPacket
from app.schemas.flows import FlowFeaturesInput

class PcapFeatureAdapterTests(unittest.TestCase):
    """Tests for canonical 48-feature mapping, payload-length convention, and provenance separation."""

    def test_feature_adapter_populates_all_48_features(self):
        # Forward packet: 20 bytes payload
        p1 = RawPacket(100.0, 100000000, "192.168.1.50", "10.0.0.1", 54321, 80, 6, 60, 40, 20, dpkt.tcp.TH_SYN, 64240, 20)
        # Backward packet: 80 bytes payload
        p2 = RawPacket(100.05, 100050000, "10.0.0.1", "192.168.1.50", 80, 54321, 6, 120, 40, 80, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, 29200, 20)

        key = BidirectionalFlowKey.from_endpoints(6, "192.168.1.50", 54321, "10.0.0.1", 80)
        flow = FlowAccumulator(key, p1)
        flow.add_packet(p2)
        flow.close()

        features, provenance = PcapFeatureAdapter.adapt(flow)

        self.assertIsInstance(features, FlowFeaturesInput)
        self.assertEqual(features.destination_port, 80.0)
        self.assertEqual(features.init_win_bytes_fwd, 64240.0)
        self.assertEqual(features.init_win_bytes_bwd, 29200.0)
        self.assertEqual(features.total_forward_packets, 1.0)
        self.assertEqual(features.down_up_ratio, 1.0)
        self.assertEqual(features.fwd_packets_per_sec, 20.0)
        
        # Verify payload length semantics
        self.assertEqual(features.min_packet_length, 20.0)
        self.assertEqual(features.max_packet_length, 80.0)
        self.assertEqual(features.fwd_packet_length_min, 20.0)
        self.assertEqual(features.fwd_packet_length_max, 20.0)
        self.assertEqual(features.bwd_packet_length_min, 80.0)
        self.assertEqual(features.bwd_packet_length_mean, 80.0)
        self.assertEqual(features.avg_fwd_segment_size, 20.0)

        for field_name in FlowFeaturesInput.model_fields.keys():
            val = getattr(features, field_name)
            self.assertTrue(math.isfinite(val), f"Field {field_name} is not finite: {val}")

        self.assertEqual(provenance.src_ip, "192.168.1.50")
        self.assertEqual(provenance.dst_ip, "10.0.0.1")
        self.assertEqual(provenance.src_port, 54321)
        self.assertEqual(provenance.dst_port, 80)
        self.assertEqual(provenance.protocol_name, "TCP")
        self.assertEqual(provenance.total_packets, 2)

    def test_zero_payload_ack_packet_has_zero_packet_length(self):
        """Pure TCP ACK with 0 payload has packet length 0 matching CICFlowMeter."""
        p1 = RawPacket(100.0, 100000000, "10.0.0.1", "10.0.0.2", 1234, 80, 6, 40, 40, 0, dpkt.tcp.TH_ACK, 65535, 20)
        key = BidirectionalFlowKey.from_endpoints(6, "10.0.0.1", 1234, "10.0.0.2", 80)
        flow = FlowAccumulator(key, p1)
        flow.close()

        features, prov = PcapFeatureAdapter.adapt(flow)
        self.assertEqual(features.min_packet_length, 0.0)
        self.assertEqual(features.max_packet_length, 0.0)
        self.assertEqual(features.fwd_packet_length_min, 0.0)
        self.assertEqual(features.fwd_packet_length_max, 0.0)
        self.assertEqual(features.packet_length_mean, 0.0)
        self.assertEqual(features.act_data_pkt_fwd, 0.0)

    def test_single_packet_flow_has_zero_variances_and_rates(self):
        p1 = RawPacket(100.0, 100000000, "192.168.1.50", "8.8.8.8", 12345, 53, 17, 45, 28, 17, 0, -1, 0)
        key = BidirectionalFlowKey.from_endpoints(17, "192.168.1.50", 12345, "8.8.8.8", 53)
        flow = FlowAccumulator(key, p1)
        flow.close()

        features, prov = PcapFeatureAdapter.adapt(flow)
        self.assertEqual(features.packet_length_variance, 0.0)
        self.assertEqual(features.flow_bytes_per_sec, 0.0)
        self.assertEqual(features.fwd_packets_per_sec, 0.0)
        self.assertEqual(features.init_win_bytes_fwd, -1.0)
        self.assertEqual(features.init_win_bytes_bwd, -1.0)
