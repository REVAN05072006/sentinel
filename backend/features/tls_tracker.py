from collections import defaultdict
from dataclasses import dataclass

from backend.ingest.stream import PacketRecord


@dataclass
class TLSSessionGroup:
    session_id: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str

    timestamps: list[float]
    packet_sizes: list[int]

    client_fingerprint: str | None
    server_fingerprint: str | None


class TLSTracker:
    """
    Passively groups TLS and QUIC traffic into observable sessions.

    Only metadata is retained:
        timestamps
        packet sizes
        endpoints
        protocol
        optional fingerprints

    No encrypted payload is decrypted or inspected.
    """

    ENCRYPTED_PORTS = {443, 8443}

    def __init__(self):
        self._groups: dict[
            tuple[str, str, int, str],
            TLSSessionGroup,
        ] = defaultdict(
            lambda: None
        )

    def process_packet(
        self,
        packet: PacketRecord,
    ) -> None:

        if (
            packet.src_ip is None
            or packet.dst_ip is None
            or packet.dst_port is None
        ):
            return

        if packet.dst_port not in self.ENCRYPTED_PORTS:
            return

        if packet.protocol not in {"TCP", "UDP"}:
            return

        protocol = (
            "QUIC"
            if packet.protocol == "UDP"
            else "TLS"
        )

        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.dst_port,
            protocol,
        )

        if self._groups[key] is None:
            self._groups[key] = TLSSessionGroup(
                session_id=(
                    f"{packet.src_ip}:"
                    f"{packet.src_port}->"
                    f"{packet.dst_ip}:"
                    f"{packet.dst_port}/"
                    f"{protocol}"
                ),
                source_ip=packet.src_ip,
                destination_ip=packet.dst_ip,
                destination_port=packet.dst_port,
                protocol=protocol,
                timestamps=[],
                packet_sizes=[],
                client_fingerprint=None,
                server_fingerprint=None,
            )

        group = self._groups[key]

        group.timestamps.append(
            packet.timestamp
        )

        group.packet_sizes.append(
            packet.packet_size
        )

    def get_groups(self) -> list[TLSSessionGroup]:
        return list(self._groups.values())

    def group_count(self) -> int:
        return len(self._groups)

    def clear(self) -> None:
        self._groups.clear()