import math
from dataclasses import dataclass, field
from typing import List, Tuple
import dpkt
from app.services.pcap.pcap_reader import RawPacket

FlowEndpoint = Tuple[str, int]  # (ip_address, port)

@dataclass(frozen=True, slots=True)
class BidirectionalFlowKey:
    """Canonical bidirectional 5-tuple key preserving (ip, port) endpoint pairing.
    Key structure: (proto, min(endpoint_a, endpoint_b), max(endpoint_a, endpoint_b))
    """
    proto: int
    endpoint_min: FlowEndpoint
    endpoint_max: FlowEndpoint

    @classmethod
    def from_endpoints(cls, proto: int, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> 'BidirectionalFlowKey':
        ep_a = (src_ip, src_port)
        ep_b = (dst_ip, dst_port)
        if ep_a <= ep_b:
            return cls(proto=proto, endpoint_min=ep_a, endpoint_max=ep_b)
        else:
            return cls(proto=proto, endpoint_min=ep_b, endpoint_max=ep_a)

class FlowAccumulator:
    """Stateful bidirectional flow accumulator.
    Forward direction is strictly determined by the first packet observed in the flow.
    """
    __slots__ = (
        'key', 'forward_endpoint', 'backward_endpoint', 'proto',
        'start_ts_us', 'last_ts_us',
        'fwd_packet_count', 'bwd_packet_count',
        'fwd_bytes_total', 'bwd_bytes_total',
        'fwd_lengths', 'bwd_lengths', 'all_lengths',
        'fwd_hdr_lengths_total', 'bwd_hdr_lengths_total',
        'min_seg_size_fwd',
        'init_win_bytes_fwd', 'init_win_bytes_bwd',
        'act_data_pkt_fwd',
        'fin_flag_count', 'syn_flag_count', 'rst_flag_count',
        'psh_flag_count', 'ack_flag_count', 'urg_flag_count',
        'ece_flag_count', 'cwr_flag_count', 'fwd_urg_flags',
        'last_fwd_ts_us', 'last_bwd_ts_us',
        'fwd_iats', 'bwd_iats', 'flow_iats',
        'active_durations', 'idle_durations',
        'current_active_start_us', 'current_active_last_us',
        'is_closed'
    )

    ACTIVE_IDLE_THRESHOLD_US = 5_000_000  # 5.0 seconds in microseconds

    def __init__(self, key: BidirectionalFlowKey, first_packet: RawPacket):
        self.key = key
        self.proto = first_packet.ip_proto
        self.forward_endpoint = (first_packet.src_ip, first_packet.src_port)
        self.backward_endpoint = (first_packet.dst_ip, first_packet.dst_port)

        self.start_ts_us = first_packet.timestamp_us
        self.last_ts_us = first_packet.timestamp_us

        self.fwd_packet_count = 0
        self.bwd_packet_count = 0
        self.fwd_bytes_total = 0
        self.bwd_bytes_total = 0

        self.fwd_lengths: List[int] = []
        self.bwd_lengths: List[int] = []
        self.all_lengths: List[int] = []

        self.fwd_hdr_lengths_total = 0
        self.bwd_hdr_lengths_total = 0
        self.min_seg_size_fwd = first_packet.tcp_header_len if self.proto == 6 else 8

        self.init_win_bytes_fwd = -1.0
        self.init_win_bytes_bwd = -1.0
        self.act_data_pkt_fwd = 0

        # TCP Flag counters
        self.fin_flag_count = 0
        self.syn_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.ece_flag_count = 0
        self.cwr_flag_count = 0
        self.fwd_urg_flags = 0

        # IAT timings
        self.last_fwd_ts_us: Optional[int] = None
        self.last_bwd_ts_us: Optional[int] = None
        self.fwd_iats: List[int] = []
        self.bwd_iats: List[int] = []
        self.flow_iats: List[int] = []

        # Active / Idle state machine
        self.active_durations: List[int] = []
        self.idle_durations: List[int] = []
        self.current_active_start_us = first_packet.timestamp_us
        self.current_active_last_us = first_packet.timestamp_us

        self.is_closed = False

        # Ingest the first packet
        self.add_packet(first_packet)

    def add_packet(self, pkt: RawPacket) -> None:
        """Process an incoming packet belonging to this flow."""
        is_fwd = (pkt.src_ip, pkt.src_port) == self.forward_endpoint
        ts = pkt.timestamp_us

        # Update flow-wide IAT
        if self.last_ts_us is not None and self.all_lengths:
            iat = ts - self.last_ts_us
            if iat < 0:
                iat = 0
            self.flow_iats.append(iat)

            # Active / Idle State Machine Transition
            if iat >= self.ACTIVE_IDLE_THRESHOLD_US:
                # An idle gap of >= 5 seconds occurred
                active_burst = self.current_active_last_us - self.current_active_start_us
                self.active_durations.append(max(0, active_burst))
                self.idle_durations.append(iat)
                self.current_active_start_us = ts
                self.current_active_last_us = ts
            else:
                self.current_active_last_us = ts
        else:
            self.current_active_last_us = ts

        self.last_ts_us = ts
        pkt_len = pkt.payload_length
        self.all_lengths.append(pkt_len)

        # Flag accumulators
        if pkt.tcp_flags:
            if pkt.tcp_flags & dpkt.tcp.TH_FIN: self.fin_flag_count += 1
            if pkt.tcp_flags & dpkt.tcp.TH_SYN: self.syn_flag_count += 1
            if pkt.tcp_flags & dpkt.tcp.TH_RST: self.rst_flag_count += 1
            if pkt.tcp_flags & dpkt.tcp.TH_PUSH: self.psh_flag_count += 1
            if pkt.tcp_flags & dpkt.tcp.TH_ACK: self.ack_flag_count += 1
            if pkt.tcp_flags & dpkt.tcp.TH_URG:
                self.urg_flag_count += 1
                if is_fwd: self.fwd_urg_flags += 1
            if pkt.tcp_flags & dpkt.tcp.TH_ECE: self.ece_flag_count += 1
            if pkt.tcp_flags & dpkt.tcp.TH_CWR: self.cwr_flag_count += 1

        if is_fwd:
            self.fwd_packet_count += 1
            self.fwd_bytes_total += pkt.payload_length
            self.fwd_lengths.append(pkt_len)
            self.fwd_hdr_lengths_total += pkt.header_length

            if pkt.payload_length > 0:
                self.act_data_pkt_fwd += 1

            if self.proto == 6 and pkt.tcp_header_len > 0:
                if self.min_seg_size_fwd == 0 or pkt.tcp_header_len < self.min_seg_size_fwd:
                    self.min_seg_size_fwd = pkt.tcp_header_len
                if self.init_win_bytes_fwd == -1.0 and pkt.tcp_window >= 0:
                    self.init_win_bytes_fwd = float(pkt.tcp_window)

            if self.last_fwd_ts_us is not None:
                fwd_iat = ts - self.last_fwd_ts_us
                self.fwd_iats.append(max(0, fwd_iat))
            self.last_fwd_ts_us = ts

        else:
            self.bwd_packet_count += 1
            self.bwd_bytes_total += pkt.payload_length
            self.bwd_lengths.append(pkt_len)
            self.bwd_hdr_lengths_total += pkt.header_length

            if self.proto == 6 and pkt.tcp_window >= 0 and self.init_win_bytes_bwd == -1.0:
                self.init_win_bytes_bwd = float(pkt.tcp_window)

            if self.last_bwd_ts_us is not None:
                bwd_iat = ts - self.last_bwd_ts_us
                self.bwd_iats.append(max(0, bwd_iat))
            self.last_bwd_ts_us = ts

    def close(self) -> None:
        """Finalize active/idle calculations on flow termination."""
        if not self.is_closed:
            # If idle gaps were recorded, close the final active burst
            if len(self.idle_durations) > 0:
                final_active = self.current_active_last_us - self.current_active_start_us
                self.active_durations.append(max(0, final_active))
            self.is_closed = True
