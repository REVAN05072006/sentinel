from collections import defaultdict
from dataclasses import dataclass

from backend.ingest.stream import PacketRecord


@dataclass
class ScanGroup:
    """
    Behavioral statistics for traffic originating from one source IP.

    The group keeps destination-host and destination-port fan-out
    information so downstream detectors can distinguish port scanning
    from host reconnaissance.
    """

    source_ip: str

    timestamps: list[float]

    destination_ips: list[str]
    destination_ports: list[int]

    total_packets: int
    unique_destination_ips: int
    unique_destination_ports: int

    host_port_pairs: int


class ScanTracker:
    """
    Tracks destination fan-out from each source IP.

    A source IP is grouped independently, while destination IPs and
    destination ports are tracked as behavioral dimensions.

    This component is passive and analytical. It does not probe,
    connect to, or otherwise interact with observed destinations.
    """

    def __init__(self):
        self._groups: dict[
            str,
            list[tuple[float, str, int]],
        ] = defaultdict(list)

    def process_packet(
        self,
        packet: PacketRecord,
    ) -> None:
        """
        Add an observed packet to its source-IP group.
        """

        if packet.src_ip is None:
            return

        if packet.dst_ip is None:
            return

        if packet.dst_port is None:
            return

        self._groups[packet.src_ip].append(
            (
                packet.timestamp,
                packet.dst_ip,
                packet.dst_port,
            )
        )

    def process_stream(
        self,
        packets: list[PacketRecord],
    ) -> None:
        """
        Process a sequence of passively observed packets.
        """

        for packet in packets:
            self.process_packet(packet)

    def get_groups(self) -> list[ScanGroup]:
        """
        Return behavioral statistics for all observed sources.
        """

        groups = []

        for source_ip, observations in self._groups.items():
            timestamps = [
                timestamp
                for timestamp, _, _ in observations
            ]

            destination_ips = [
                destination_ip
                for _, destination_ip, _ in observations
            ]

            destination_ports = [
                destination_port
                for _, _, destination_port in observations
            ]

            host_port_pairs = len(
                {
                    (destination_ip, destination_port)
                    for _, destination_ip, destination_port
                    in observations
                }
            )

            groups.append(
                ScanGroup(
                    source_ip=source_ip,
                    timestamps=timestamps,
                    destination_ips=destination_ips,
                    destination_ports=destination_ports,
                    total_packets=len(observations),
                    unique_destination_ips=len(
                        set(destination_ips)
                    ),
                    unique_destination_ports=len(
                        set(destination_ports)
                    ),
                    host_port_pairs=host_port_pairs,
                )
            )

        return groups

    def group_count(self) -> int:
        """
        Return the number of tracked source-IP groups.
        """

        return len(self._groups)

    def clear(self) -> None:
        """
        Clear all tracked scan state.
        """

        self._groups.clear()