import socket
import logging
from dataclasses import dataclass
from typing import BinaryIO, Generator, Optional, Tuple
import dpkt

logger = logging.getLogger(__name__)

@dataclass(frozen=True, slots=True)
class RawPacket:
    """Decoded packet header and payload metadata extracted from PCAP stream."""
    timestamp_sec: float
    timestamp_us: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_proto: int          # 6 for TCP, 17 for UDP
    ip_length: int         # Total length of IP packet in bytes
    header_length: int     # Total IP header + transport header length in bytes
    payload_length: int    # Transport payload length in bytes
    tcp_flags: int         # Bitwise TCP flags (0 if UDP/other)
    tcp_window: int        # TCP window size (-1 if UDP/other)
    tcp_header_len: int    # TCP header length (0 if UDP/other)

class PcapReader:
    """Streaming binary parser for PCAP and PCAPNG capture formats."""

    @staticmethod
    def _ip_to_str(inet_bytes: bytes) -> str:
        if len(inet_bytes) == 4:
            return socket.inet_ntop(socket.AF_INET, inet_bytes)
        elif len(inet_bytes) == 16:
            return socket.inet_ntop(socket.AF_INET6, inet_bytes)
        return ""

    @classmethod
    def iter_packets(cls, file_obj: BinaryIO) -> Generator[RawPacket, None, None]:
        """Stream decoded RawPacket records from an open binary file-like object."""
        header = file_obj.read(4)
        file_obj.seek(0)

        reader: dpkt.pcap.Reader
        if header == b'\n\r\r\n':  # PCAPNG magic
            reader = dpkt.pcapng.Reader(file_obj)
        else:
            try:
                reader = dpkt.pcap.Reader(file_obj)
            except ValueError:
                file_obj.seek(0)
                reader = dpkt.pcapng.Reader(file_obj)

        datalink = getattr(reader, 'datalink', lambda: 1)()

        try:
            for ts_sec, buf in reader:
                ts_us = int(round(float(ts_sec) * 1_000_000.0))
                try:
                    ip_pkt = None
                    if datalink == dpkt.pcap.DLT_EN10MB or datalink == 1:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                            ip_pkt = eth.data
                    elif datalink == dpkt.pcap.DLT_LINUX_SLL or datalink == 113:
                        sll = dpkt.sll.SLL(buf)
                        if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                            ip_pkt = sll.data
                    elif datalink == dpkt.pcap.DLT_RAW or datalink == 101 or datalink == 12:
                        ip_pkt = dpkt.ip.IP(buf)
                    else:
                        try:
                            ip_pkt = dpkt.ip.IP(buf)
                        except Exception:
                            continue

                    if ip_pkt is None or not isinstance(ip_pkt, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue

                    src_ip = cls._ip_to_str(ip_pkt.src)
                    dst_ip = cls._ip_to_str(ip_pkt.dst)
                    if not src_ip or not dst_ip:
                        continue

                    ip_proto = ip_pkt.p
                    total_ip_len = len(ip_pkt)

                    if ip_proto == 6:  # TCP
                        if not isinstance(ip_pkt.data, dpkt.tcp.TCP):
                            try:
                                tcp_layer = dpkt.tcp.TCP(ip_pkt.data)
                            except Exception:
                                continue
                        else:
                            tcp_layer = ip_pkt.data

                        src_port = tcp_layer.sport
                        dst_port = tcp_layer.dport
                        tcp_hdr_len = tcp_layer.off * 4
                        ip_hdr_len = (ip_pkt.hl * 4) if hasattr(ip_pkt, 'hl') else 40
                        tot_hdr_len = ip_hdr_len + tcp_hdr_len
                        payload_len = max(0, len(tcp_layer.data))
                        tcp_flags = tcp_layer.flags
                        tcp_win = tcp_layer.win

                        yield RawPacket(
                            timestamp_sec=float(ts_sec),
                            timestamp_us=ts_us,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            ip_proto=6,
                            ip_length=total_ip_len,
                            header_length=tot_hdr_len,
                            payload_length=payload_len,
                            tcp_flags=tcp_flags,
                            tcp_window=tcp_win,
                            tcp_header_len=tcp_hdr_len,
                        )

                    elif ip_proto == 17:  # UDP
                        if not isinstance(ip_pkt.data, dpkt.udp.UDP):
                            try:
                                udp_layer = dpkt.udp.UDP(ip_pkt.data)
                            except Exception:
                                continue
                        else:
                            udp_layer = ip_pkt.data

                        src_port = udp_layer.sport
                        dst_port = udp_layer.dport
                        ip_hdr_len = (ip_pkt.hl * 4) if hasattr(ip_pkt, 'hl') else 40
                        udp_hdr_len = 8
                        tot_hdr_len = ip_hdr_len + udp_hdr_len
                        payload_len = max(0, len(udp_layer.data))

                        yield RawPacket(
                            timestamp_sec=float(ts_sec),
                            timestamp_us=ts_us,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            ip_proto=17,
                            ip_length=total_ip_len,
                            header_length=tot_hdr_len,
                            payload_length=payload_len,
                            tcp_flags=0,
                            tcp_window=-1,
                            tcp_header_len=0,
                        )

                    else:
                        logger.debug("Skipping non-TCP/UDP IP protocol %d between %s and %s", ip_proto, src_ip, dst_ip)
                        continue

                except Exception as e:
                    logger.debug("Packet decode error at ts %f: %s", float(ts_sec), e)
                    continue
        except (dpkt.NeedData, StopIteration, EOFError):
            pass
