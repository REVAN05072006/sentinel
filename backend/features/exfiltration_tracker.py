from collections import defaultdict
from dataclasses import dataclass

from backend.ingest.stream import PacketRecord


@dataclass
class ExfiltrationGroup:
    source_ip: str
    destination_ip: str
    protocol: str

    outbound_bytes: int
    inbound_bytes: int

    outbound_packets: int
    inbound_packets: int


class ExfiltrationTracker:
    """
    Tracks bidirectional communication for passive
    data-exfiltration analysis.

    The tracker normalizes both directions into a single
    communication pair so outbound and inbound volumes can
    be compared.

    No traffic is transmitted, modified, decrypted, or blocked.
    """

    def __init__(
        self,
        internal_networks: tuple[str, ...] = (
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
        ),
    ):
        self.internal_networks = internal_networks

        self._groups: dict[
            tuple[str, str, str],
            dict[str, int],
        ] = defaultdict(
            lambda: {
                "outbound_bytes": 0,
                "inbound_bytes": 0,
                "outbound_packets": 0,
                "inbound_packets": 0,
            }
        )

    def _is_internal(
        self,
        ip: str,
    ) -> bool:
        """
        Determine whether an IP belongs to an
        observed internal/private network.
        """

        return any(
            ip.startswith(prefix)
            for prefix in self.internal_networks
        )

    def _conversation_key(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
    ) -> tuple[str, str, str]:
        """
        Normalize traffic into:

            internal_ip
            external_ip
            protocol

        regardless of packet direction.
        """

        if self._is_internal(src_ip):
            return (
                src_ip,
                dst_ip,
                protocol,
            )

        return (
            dst_ip,
            src_ip,
            protocol,
        )

    def process_packet(
        self,
        packet: PacketRecord,
    ) -> None:
        """
        Process one passively observed packet.

        Internal -> external traffic is counted as outbound.

        External -> internal traffic is counted as inbound.

        Traffic where neither endpoint is internal is ignored.
        """

        if packet.src_ip is None:
            return

        if packet.dst_ip is None:
            return

        source_is_internal = self._is_internal(
            packet.src_ip
        )

        destination_is_internal = self._is_internal(
            packet.dst_ip
        )

        if (
            not source_is_internal
            and not destination_is_internal
        ):
            return

        key = self._conversation_key(
            packet.src_ip,
            packet.dst_ip,
            packet.protocol,
        )

        stats = self._groups[key]

        if source_is_internal:
            stats["outbound_bytes"] += packet.packet_size
            stats["outbound_packets"] += 1
        else:
            stats["inbound_bytes"] += packet.packet_size
            stats["inbound_packets"] += 1

    def get_groups(
        self,
    ) -> list[ExfiltrationGroup]:
        """
        Return all normalized communication groups.
        """

        groups = []

        for (
            source_ip,
            destination_ip,
            protocol,
        ), stats in self._groups.items():

            groups.append(
                ExfiltrationGroup(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol=protocol,
                    outbound_bytes=(
                        stats["outbound_bytes"]
                    ),
                    inbound_bytes=(
                        stats["inbound_bytes"]
                    ),
                    outbound_packets=(
                        stats["outbound_packets"]
                    ),
                    inbound_packets=(
                        stats["inbound_packets"]
                    ),
                )
            )

        return groups

    def group_count(
        self,
    ) -> int:
        """
        Return the number of tracked communication groups.
        """

        return len(self._groups)

    def clear(
        self,
    ) -> None:
        """
        Clear all tracked communication state.
        """

        self._groups.clear()
