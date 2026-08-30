import io
import sys
import socket
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import dpkt
from app.services.pcap.pcap_reader import PcapReader, RawPacket

class PcapReaderTests(unittest.TestCase):
    """Unit tests for low-level PCAP packet parsing."""

    def _create_synthetic_pcap(self) -> io.BytesIO:
        """Create an in-memory PCAP with TCP, UDP, and ICMP packets."""
        buf = io.BytesIO()
        writer = dpkt.pcap.Writer(buf)

        # 1. TCP SYN Packet (Client -> Server)
        ip1 = dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.50"),
            dst=socket.inet_aton("192.168.1.1"),
            p=dpkt.ip.IP_PROTO_TCP,
        )
        tcp1 = dpkt.tcp.TCP(
            sport=54321,
            dport=80,
            flags=dpkt.tcp.TH_SYN,
            win=64240,
            seq=1000,
        )
        ip1.data = tcp1
        ip1.len = len(ip1)
        eth1 = dpkt.ethernet.Ethernet(
            src=b'\x00\x11\x22\x33\x44\x55',
            dst=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip1,
        )
        writer.writepkt(eth1, ts=1499427000.100000)

        # 2. TCP SYN-ACK Packet (Server -> Client)
        ip2 = dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.1"),
            dst=socket.inet_aton("192.168.1.50"),
            p=dpkt.ip.IP_PROTO_TCP,
        )
        tcp2 = dpkt.tcp.TCP(
            sport=80,
            dport=54321,
            flags=dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
            win=29200,
            seq=2000,
            ack=1001,
        )
        ip2.data = tcp2
        ip2.len = len(ip2)
        eth2 = dpkt.ethernet.Ethernet(
            src=b'\x66\x77\x88\x99\xaa\xbb',
            dst=b'\x00\x11\x22\x33\x44\x55',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip2,
        )
        writer.writepkt(eth2, ts=1499427000.105000)

        # 3. UDP Packet
        ip3 = dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.50"),
            dst=socket.inet_aton("8.8.8.8"),
            p=dpkt.ip.IP_PROTO_UDP,
        )
        udp3 = dpkt.udp.UDP(
            sport=53535,
            dport=53,
            data=b"\x00\x01\x01\x00DNS_QUERY",
        )
        ip3.data = udp3
        ip3.len = len(ip3)
        eth3 = dpkt.ethernet.Ethernet(
            src=b'\x00\x11\x22\x33\x44\x55',
            dst=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip3,
        )
        writer.writepkt(eth3, ts=1499427000.200000)

        # 4. ICMP Packet (Protocol 1 - should be gracefully skipped)
        ip4 = dpkt.ip.IP(
            src=socket.inet_aton("192.168.1.50"),
            dst=socket.inet_aton("8.8.8.8"),
            p=dpkt.ip.IP_PROTO_ICMP,
        )
        icmp4 = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"ping"))
        ip4.data = icmp4
        ip4.len = len(ip4)
        eth4 = dpkt.ethernet.Ethernet(
            src=b'\x00\x11\x22\x33\x44\x55',
            dst=b'\x66\x77\x88\x99\xaa\xbb',
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip4,
        )
        writer.writepkt(eth4, ts=1499427000.300000)

        buf.seek(0)
        return buf

    def test_parse_synthetic_pcap(self):
        pcap_buf = self._create_synthetic_pcap()
        packets = list(PcapReader.iter_packets(pcap_buf))

        self.assertEqual(len(packets), 3)

        p1 = packets[0]
        self.assertEqual(p1.src_ip, "192.168.1.50")
        self.assertEqual(p1.dst_ip, "192.168.1.1")
        self.assertEqual(p1.src_port, 54321)
        self.assertEqual(p1.dst_port, 80)
        self.assertEqual(p1.ip_proto, 6)
        self.assertTrue(p1.tcp_flags & dpkt.tcp.TH_SYN)
        self.assertEqual(p1.tcp_window, 64240)

        p2 = packets[1]
        self.assertEqual(p2.src_ip, "192.168.1.1")
        self.assertEqual(p2.dst_ip, "192.168.1.50")
        self.assertEqual(p2.src_port, 80)
        self.assertEqual(p2.dst_port, 54321)
        self.assertTrue(p2.tcp_flags & dpkt.tcp.TH_SYN)
        self.assertTrue(p2.tcp_flags & dpkt.tcp.TH_ACK)
        self.assertEqual(p2.tcp_window, 29200)

        p3 = packets[2]
        self.assertEqual(p3.src_ip, "192.168.1.50")
        self.assertEqual(p3.dst_ip, "8.8.8.8")
        self.assertEqual(p3.src_port, 53535)
        self.assertEqual(p3.dst_port, 53)
        self.assertEqual(p3.ip_proto, 17)
        self.assertEqual(p3.tcp_window, -1)
