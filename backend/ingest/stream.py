from dataclasses import dataclass
from typing import Iterator, Optional

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, PcapReader


@dataclass
class PacketRecord:
    timestamp: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]
    packet_size: int
    tcp_flags: Optional[str]
    dns_query: Optional[str]


class PacketStream:
    """
    Read-only packet stream.

    The stream only observes packets and converts them into
    normalized PacketRecord objects. It does not transmit,
    modify, block, or respond to traffic.
    """

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def packets(self) -> Iterator[PacketRecord]:
        with PcapReader(self.pcap_path) as reader:
            for packet in reader:
                record = self._parse_packet(packet)

                if record is not None:
                    yield record

    @staticmethod
    def _parse_packet(packet) -> Optional[PacketRecord]:
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]

        protocol = "OTHER"
        src_port = None
        dst_port = None
        tcp_flags = None
        dns_query = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp = packet[TCP]

            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = str(tcp.flags)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp = packet[UDP]

            src_port = int(udp.sport)
            dst_port = int(udp.dport)

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                dns_query = packet[DNSQR].qname.decode(
                    "utf-8",
                    errors="ignore"
                ).rstrip(".")
            except Exception:
                dns_query = None

        return PacketRecord(
            timestamp=float(packet.time),
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            packet_size=len(packet),
            tcp_flags=tcp_flags,
            dns_query=dns_query,
        )