from collections import Counter, deque
from dataclasses import dataclass
from math import log2
from typing import Iterable

from backend.ingest.stream import PacketRecord


@dataclass
class WindowFeatures:
    start_time: float
    end_time: float

    packet_count: int
    byte_count: int

    packets_per_second: float
    bytes_per_second: float

    syn_count: int
    syns_per_second: float
    syn_ratio: float

    unique_src_ips: int
    unique_dst_ips: int
    unique_dst_ports: int

    dominant_dst_ip: str | None
    dominant_dst_port: int | None

    source_ip_entropy: float


class SlidingWindow:
    def __init__(self, window_size: float = 1.0):
        if window_size <= 0:
            raise ValueError("window_size must be greater than zero")

        self.window_size = window_size
        self._packets = deque()

    def add(self, packet: PacketRecord) -> WindowFeatures:
        self._packets.append(packet)
        self._expire(packet.timestamp)

        return self.features()

    def process(self, packets: Iterable[PacketRecord]) -> list[WindowFeatures]:
        results = []

        for packet in packets:
            results.append(self.add(packet))

        return results

    def _expire(self, current_time: float) -> None:
        cutoff = current_time - self.window_size

        while self._packets and self._packets[0].timestamp < cutoff:
            self._packets.popleft()

    def features(self) -> WindowFeatures:
        if not self._packets:
            return WindowFeatures(
                start_time=0.0,
                end_time=0.0,
                packet_count=0,
                byte_count=0,
                packets_per_second=0.0,
                bytes_per_second=0.0,
                syn_count=0,
                syns_per_second=0.0,
                syn_ratio=0.0,
                unique_src_ips=0,
                unique_dst_ips=0,
                unique_dst_ports=0,
                dominant_dst_ip=None,
                dominant_dst_port=None,
                source_ip_entropy=0.0,
            )

        packets = list(self._packets)

        start_time = packets[0].timestamp
        end_time = packets[-1].timestamp

        packet_count = len(packets)
        byte_count = sum(packet.packet_size for packet in packets)

        duration = max(
            min(self.window_size, end_time - start_time),
            0.000001,
        )

        packets_per_second = packet_count / duration
        bytes_per_second = byte_count / duration

        syn_count = sum(
            1
            for packet in packets
            if packet.protocol == "TCP"
            and "S" in (packet.tcp_flags or "")
            and "A" not in (packet.tcp_flags or "")
        )

        syns_per_second = syn_count / duration

        syn_ratio = (
            syn_count / packet_count
            if packet_count > 0
            else 0.0
        )

        unique_src_ips = len(
            {packet.src_ip for packet in packets}
        )

        unique_dst_ips = len(
            {packet.dst_ip for packet in packets}
        )

        unique_dst_ports = len(
            {
                packet.dst_port
                for packet in packets
                if packet.dst_port is not None
            }
        )

        destination_counts = Counter(
            packet.dst_ip for packet in packets
        )

        dominant_dst_ip = destination_counts.most_common(1)[0][0]

        destination_port_counts = Counter(
            packet.dst_port
            for packet in packets
            if packet.dst_port is not None
        )

        dominant_dst_port = (
            destination_port_counts.most_common(1)[0][0]
            if destination_port_counts
            else None
        )

        source_ip_entropy = self._entropy(
            packet.src_ip for packet in packets
        )

        return WindowFeatures(
            start_time=start_time,
            end_time=end_time,

            packet_count=packet_count,
            byte_count=byte_count,

            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,

            syn_count=syn_count,
            syns_per_second=syns_per_second,
            syn_ratio=syn_ratio,

            unique_src_ips=unique_src_ips,
            unique_dst_ips=unique_dst_ips,
            unique_dst_ports=unique_dst_ports,

            dominant_dst_ip=dominant_dst_ip,
            dominant_dst_port=dominant_dst_port,

            source_ip_entropy=source_ip_entropy,
        )

    @staticmethod
    def _entropy(values: Iterable[str]) -> float:
        counts = Counter(values)
        total = sum(counts.values())

        if total == 0:
            return 0.0

        entropy = 0.0

        for count in counts.values():
            probability = count / total
            entropy -= probability * log2(probability)

        return entropy