import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import dpkt
from app.services.pcap.flow_state import BidirectionalFlowKey, FlowAccumulator
from app.services.pcap.pcap_reader import RawPacket

class FlowTimingsTests(unittest.TestCase):
    """Tests for microsecond IAT dynamics and 5-second active/idle state machine."""

    def test_microsecond_iat_calculations(self):
        p1 = RawPacket(0.0, 0, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)
        p2 = RawPacket(0.001, 1000, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)
        p3 = RawPacket(0.0025, 2500, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)

        key = BidirectionalFlowKey.from_endpoints(6, "1.1.1.1", 100, "2.2.2.2", 80)
        flow = FlowAccumulator(key, p1)
        flow.add_packet(p2)
        flow.add_packet(p3)

        self.assertEqual(flow.fwd_iats, [1000, 1500])
        self.assertEqual(flow.flow_iats, [1000, 1500])
        self.assertEqual(flow.bwd_iats, [])

    def test_active_idle_state_machine_with_5s_gap(self):
        p1 = RawPacket(0.0, 0, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)
        p2 = RawPacket(1.0, 1_000_000, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)
        p3 = RawPacket(7.0, 7_000_000, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)
        p4 = RawPacket(7.5, 7_500_000, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)

        key = BidirectionalFlowKey.from_endpoints(6, "1.1.1.1", 100, "2.2.2.2", 80)
        flow = FlowAccumulator(key, p1)
        flow.add_packet(p2)
        flow.add_packet(p3)
        flow.add_packet(p4)
        flow.close()

        self.assertEqual(flow.idle_durations, [6_000_000])
        self.assertEqual(flow.active_durations, [1_000_000, 500_000])

    def test_short_flow_without_idle_gap_evaluates_to_zero(self):
        p1 = RawPacket(0.0, 0, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)
        p2 = RawPacket(0.5, 500_000, "1.1.1.1", "2.2.2.2", 100, 80, 6, 60, 40, 20, 0, -1, 20)

        key = BidirectionalFlowKey.from_endpoints(6, "1.1.1.1", 100, "2.2.2.2", 80)
        flow = FlowAccumulator(key, p1)
        flow.add_packet(p2)
        flow.close()

        self.assertEqual(flow.idle_durations, [])
        self.assertEqual(flow.active_durations, [])
