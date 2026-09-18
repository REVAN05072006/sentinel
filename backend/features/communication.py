from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from backend.ingest.stream import PacketRecord


@dataclass
class CommunicationGroup:
    """
    Represents repeated communication between a source and destination.
    """

    source_ip: str
    destination_ip: str
    destination_port: int | None
    protocol: str

    timestamps: list[float]
    source_ports: list[int]


class CommunicationTracker:
    """
    Groups passively observed packets into behavioral communication
    sequences.

    Communication identity is based on:
        source IP
        destination IP
        destination port
        protocol

    Source ports are retained as metadata but do not define a group.
    This allows repeated connections using changing ephemeral source
    ports to be analyzed as one communication pattern.

    The tracker does not transmit, modify, block, or respond to traffic.
    It only maintains observations required for behavioral analysis.
    """

    def __init__(self):
        self._groups: dict[tuple, list[tuple[float, int | None]]] = (
            defaultdict(list)
        )

    def process_packet(self, packet: PacketRecord) -> None:
        """
        Add an observed packet to its behavioral communication group.
        """

        if packet.src_ip is None or packet.dst_ip is None:
            return

        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.dst_port,
            packet.protocol,
        )

        self._groups[key].append(
            (
                packet.timestamp,
                packet.src_port,
            )
        )

    def process_stream(
        self,
        packets: Iterable[PacketRecord],
    ) -> None:
        """
        Process a passive packet stream.
        """

        for packet in packets:
            self.process_packet(packet)

    def get_groups(self) -> list[CommunicationGroup]:
        """
        Return all currently observed behavioral communication groups.
        """

        groups = []

        for (
            source_ip,
            destination_ip,
            destination_port,
            protocol,
        ), observations in self._groups.items():
            timestamps = [
                timestamp
                for timestamp, _ in observations
            ]

            source_ports = [
                source_port
                for _, source_port in observations
                if source_port is not None
            ]

            groups.append(
                CommunicationGroup(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    protocol=protocol,
                    timestamps=timestamps,
                    source_ports=source_ports,
                )
            )

        return groups

    def group_count(self) -> int:
        """
        Return the number of unique behavioral communication groups.
        """

        return len(self._groups)

    def clear(self) -> None:
        """
        Clear all communication observations.
        """

        self._groups.clear()