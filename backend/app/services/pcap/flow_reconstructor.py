import logging
from typing import BinaryIO, Dict, Generator, List, Optional
import dpkt
from app.services.pcap.pcap_reader import PcapReader, RawPacket
from app.services.pcap.flow_state import BidirectionalFlowKey, FlowAccumulator

logger = logging.getLogger(__name__)

class FlowReconstructor:
    """Stateful bidirectional flow reconstructor with bounded memory and timeout eviction."""

    FLOW_TIMEOUT_US = 120_000_000  # 120 seconds in microseconds
    MAX_CONCURRENT_FLOWS = 50_000   # Guardrail against memory exhaustion

    def __init__(self, flow_timeout_sec: float = 120.0, max_flows: int = 50_000):
        self.flow_timeout_us = int(flow_timeout_sec * 1_000_000.0)
        self.max_flows = max_flows
        self.active_flows: Dict[BidirectionalFlowKey, FlowAccumulator] = {}

    def _evict_timed_out_flows(self, current_ts_us: int) -> List[FlowAccumulator]:
        """Evict flows that have been inactive for more than flow_timeout_us."""
        expired: List[FlowAccumulator] = []
        keys_to_delete = []

        for key, flow in self.active_flows.items():
            if current_ts_us - flow.last_ts_us >= self.flow_timeout_us:
                flow.close()
                expired.append(flow)
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self.active_flows[key]

        return expired

    def process_pcap_stream(self, file_obj: BinaryIO) -> Generator[FlowAccumulator, None, None]:
        """Stream closed FlowAccumulator objects from a PCAP file."""
        self.active_flows.clear()
        last_check_ts_us = 0

        for pkt in PcapReader.iter_packets(file_obj):
            key = BidirectionalFlowKey.from_endpoints(
                proto=pkt.ip_proto,
                src_ip=pkt.src_ip,
                src_port=pkt.src_port,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
            )

            # Periodically evict timed-out flows every 10 seconds of capture time
            if pkt.timestamp_us - last_check_ts_us >= 10_000_000:
                for expired_flow in self._evict_timed_out_flows(pkt.timestamp_us):
                    yield expired_flow
                last_check_ts_us = pkt.timestamp_us

            # Enforce max concurrency limit via oldest flow eviction
            if len(self.active_flows) >= self.max_flows and key not in self.active_flows:
                oldest_key = min(self.active_flows.keys(), key=lambda k: self.active_flows[k].last_ts_us)
                oldest_flow = self.active_flows.pop(oldest_key)
                oldest_flow.close()
                yield oldest_flow

            if key not in self.active_flows:
                self.active_flows[key] = FlowAccumulator(key, pkt)
            else:
                flow = self.active_flows[key]
                flow.add_packet(pkt)

                # TCP Teardown check (FIN or RST flag terminates flow immediately)
                if pkt.ip_proto == 6 and (pkt.tcp_flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST)):
                    flow.close()
                    del self.active_flows[key]
                    yield flow

        # Flush remaining active flows at EOF
        for flow in self.active_flows.values():
            flow.close()
            yield flow
        self.active_flows.clear()

    def extract_flows(self, file_obj: BinaryIO) -> List[FlowAccumulator]:
        """Collect all reconstructed flows into a list."""
        return list(self.process_pcap_stream(file_obj))
