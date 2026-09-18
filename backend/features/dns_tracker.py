from collections import defaultdict
from dataclasses import dataclass

from backend.ingest.stream import PacketRecord


@dataclass
class DNSQueryGroup:
    """
    Stateful collection of passively observed DNS queries
    associated with one source and destination DNS server.
    """

    source_ip: str
    destination_ip: str

    timestamps: list[float]
    queries: list[str]

    total_queries: int
    unique_queries: int

    total_query_bytes: int


class DNSTracker:
    """
    Tracks DNS query sequences from a passive packet stream.

    The tracker groups queries by source IP and destination DNS
    server. It does not perform DNS lookups or any network activity.
    """

    def __init__(self):
        self._groups: dict[
            tuple[str, str],
            list[tuple[float, str, int]],
        ] = defaultdict(list)

    def process_packet(
        self,
        packet: PacketRecord,
    ) -> None:
        """
        Add an observed DNS query to its behavioral group.
        """

        if packet.src_ip is None or packet.dst_ip is None:
            return

        if packet.dns_query is None:
            return

        key = (
            packet.src_ip,
            packet.dst_ip,
        )

        self._groups[key].append(
            (
                packet.timestamp,
                packet.dns_query,
                packet.packet_size,
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

    def get_groups(self) -> list[DNSQueryGroup]:
        """
        Return all currently tracked DNS query groups.
        """

        groups = []

        for (
            source_ip,
            destination_ip,
        ), observations in self._groups.items():

            timestamps = [
                timestamp
                for timestamp, _, _ in observations
            ]

            queries = [
                query
                for _, query, _ in observations
            ]

            total_query_bytes = sum(
                packet_size
                for _, _, packet_size in observations
            )

            groups.append(
                DNSQueryGroup(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    timestamps=timestamps,
                    queries=queries,
                    total_queries=len(queries),
                    unique_queries=len(set(queries)),
                    total_query_bytes=total_query_bytes,
                )
            )

        return groups

    def group_count(self) -> int:
        """
        Return the number of tracked source/DNS-server groups.
        """

        return len(self._groups)

    def clear(self) -> None:
        """
        Clear all tracked DNS state.
        """

        self._groups.clear()