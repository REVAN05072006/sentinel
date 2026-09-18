from dataclasses import dataclass
from typing import Dict, Iterator, Tuple

from backend.ingest.stream import PacketRecord


@dataclass
class FlowRecord:
    flow_id: Tuple[str, str, int, int, str]

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    start_time: float
    end_time: float

    packet_count: int
    byte_count: int

    syn_count: int


class FlowTracker:
    """
    Stateful flow reconstruction from a one-way packet stream.

    A flow is identified using the standard 5-tuple:
        source IP
        destination IP
        source port
        destination port
        protocol

    This component is strictly read-only. It observes packets and
    aggregates statistics without modifying or transmitting traffic.
    """

    def __init__(self):
        self._flows: Dict[
            Tuple[str, str, int, int, str],
            FlowRecord
        ] = {}

    def process_packet(self, packet: PacketRecord) -> None:
        """
        Add one observed packet to its corresponding flow.
        """

        if packet.src_ip is None or packet.dst_ip is None:
            return

        if packet.src_port is None or packet.dst_port is None:
            return

        flow_id = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
        )

        if flow_id not in self._flows:
            self._flows[flow_id] = FlowRecord(
                flow_id=flow_id,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
                packet_count=0,
                byte_count=0,
                syn_count=0,
            )

        flow = self._flows[flow_id]

        flow.end_time = packet.timestamp
        flow.packet_count += 1
        flow.byte_count += packet.packet_size

        if packet.protocol == "TCP" and packet.tcp_flags is not None:
            if "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
                flow.syn_count += 1

    def process_stream(
        self,
        packets: Iterator[PacketRecord],
    ) -> None:
        """
        Process an entire packet stream.
        """

        for packet in packets:
            self.process_packet(packet)

    def get_flows(self) -> Iterator[FlowRecord]:
        """
        Return all currently reconstructed flows.
        """

        yield from self._flows.values()

    def flow_count(self) -> int:
        """
        Return the number of unique flows currently tracked.
        """

        return len(self._flows)

    def clear(self) -> None:
        """
        Clear all tracked flow state.
        """

        self._flows.clear()