import io
import sys
import socket
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import dpkt
from app.services.pcap.flow_state import BidirectionalFlowKey, FlowAccumulator
from app.services.pcap.flow_reconstructor import FlowReconstructor
from app.services.pcap.pcap_reader import RawPacket

class FlowReconstructorTests(unittest.TestCase):
    """Tests for bidirectional flow key correctness, directionality, and timeout eviction."""

    def test_bidirectional_key_preserves_endpoint_pairing(self):
        """Verify endpoint pairing is preserved and unrelated flows do not collide."""
        k1 = BidirectionalFlowKey.from_endpoints(6, "10.0.0.1", 80, "10.0.0.2", 90)
        k2 = BidirectionalFlowKey.from_endpoints(6, "10.0.0.2", 90, "10.0.0.1", 80)
        self.assertEqual(k1, k2)

        # Unrelated flow with flipped ports: (10.0.0.1, 90) and (10.0.0.2, 80)
        k3 = BidirectionalFlowKey.from_endpoints(6, "10.0.0.1", 90, "10.0.0.2", 80)
        self.assertNotEqual(k1, k3)

    def test_forward_direction_locked_to_first_packet(self):
        pkt1 = RawPacket(
            timestamp_sec=100.0, timestamp_us=100000000,
            src_ip="192.168.1.10", dst_ip="10.0.0.1",
            src_port=44444, dst_port=80,
            ip_proto=6, ip_length=60, header_length=40, payload_length=20,
            tcp_flags=dpkt.tcp.TH_SYN, tcp_window=65535, tcp_header_len=20
        )
        key = BidirectionalFlowKey.from_endpoints(6, pkt1.src_ip, pkt1.src_port, pkt1.dst_ip, pkt1.dst_port)
        flow = FlowAccumulator(key, pkt1)

        self.assertEqual(flow.forward_endpoint, ("192.168.1.10", 44444))
        self.assertEqual(flow.backward_endpoint, ("10.0.0.1", 80))
        self.assertEqual(flow.fwd_packet_count, 1)
        self.assertEqual(flow.bwd_packet_count, 0)
        self.assertEqual(flow.init_win_bytes_fwd, 65535.0)
        self.assertEqual(flow.init_win_bytes_bwd, -1.0)

        pkt2 = RawPacket(
            timestamp_sec=100.01, timestamp_us=100010000,
            src_ip="10.0.0.1", dst_ip="192.168.1.10",
            src_port=80, dst_port=44444,
            ip_proto=6, ip_length=60, header_length=40, payload_length=20,
            tcp_flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, tcp_window=28960, tcp_header_len=20
        )
        flow.add_packet(pkt2)
        self.assertEqual(flow.fwd_packet_count, 1)
        self.assertEqual(flow.bwd_packet_count, 1)
        self.assertEqual(flow.init_win_bytes_bwd, 28960.0)

    def test_tcp_fin_terminates_flow_immediately(self):
        buf = io.BytesIO()
        writer = dpkt.pcap.Writer(buf)

        ip = dpkt.ip.IP(src=socket.inet_aton("1.1.1.1"), dst=socket.inet_aton("2.2.2.2"), p=6)
        tcp1 = dpkt.tcp.TCP(sport=1000, dport=80, flags=dpkt.tcp.TH_SYN)
        ip.data = tcp1
        ip.len = len(ip)
        writer.writepkt(dpkt.ethernet.Ethernet(data=ip), ts=100.0)

        tcp2 = dpkt.tcp.TCP(sport=1000, dport=80, flags=dpkt.tcp.TH_FIN)
        ip.data = tcp2
        ip.len = len(ip)
        writer.writepkt(dpkt.ethernet.Ethernet(data=ip), ts=100.1)

        buf.seek(0)
        reconstructor = FlowReconstructor()
        flows = reconstructor.extract_flows(buf)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].fin_flag_count, 1)
