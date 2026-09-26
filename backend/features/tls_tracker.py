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

    Bidirectional tracking: port 443/8443 is recognised as the
    encrypted endpoint regardless of whether it appears as the
    source port (server → client response) or the destination port
    (client → server request).  Both directions are normalised onto
    the same canonical (client_ip, server_ip, server_port, protocol)
    session key so that a single TLSSessionGroup accumulates the
    complete observed flow.
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
        ):
            return

        if packet.protocol not in {"TCP", "UDP"}:
            return

        # Determine which endpoint is the encrypted server.
        # Prefer dst_port (client→server) over src_port (server→client)
        # so that the two cases below are mutually exclusive.
        if packet.dst_port in self.ENCRYPTED_PORTS:
            # Client → Server direction (request / handshake)
            client_ip = packet.src_ip
            server_ip = packet.dst_ip
            server_port = packet.dst_port
            client_port = packet.src_port
        elif (
            packet.src_port is not None
            and packet.src_port in self.ENCRYPTED_PORTS
        ):
            # Server → Client direction (response packets)
            client_ip = packet.dst_ip
            server_ip = packet.src_ip
            server_port = packet.src_port
            client_port = packet.dst_port
        else:
            return

        protocol = (
            "QUIC"
            if packet.protocol == "UDP"
            else "TLS"
        )

        # Canonical key: always from the client's perspective so that
        # both traffic directions map to the same session group.
        key = (
            client_ip,
            server_ip,
            server_port,
            protocol,
        )

        if self._groups[key] is None:
            self._groups[key] = TLSSessionGroup(
                session_id=(
                    f"{client_ip}:"
                    f"{client_port}->"
                    f"{server_ip}:"
                    f"{server_port}/"
                    f"{protocol}"
                ),
                source_ip=client_ip,
                destination_ip=server_ip,
                destination_port=server_port,
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