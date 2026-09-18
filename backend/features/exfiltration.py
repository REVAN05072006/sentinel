from dataclasses import dataclass


@dataclass
class ExfiltrationFeatures:
    source_ip: str
    destination_ip: str
    protocol: str

    outbound_bytes: int
    inbound_bytes: int
    total_bytes: int

    outbound_packets: int
    inbound_packets: int
    total_packets: int

    outbound_inbound_byte_ratio: float
    outbound_byte_ratio: float
    outbound_packet_ratio: float


class ExfiltrationFeatureExtractor:
    @staticmethod
    def extract(
        source_ip: str,
        destination_ip: str,
        protocol: str,
        outbound_bytes: int,
        inbound_bytes: int,
        outbound_packets: int,
        inbound_packets: int,
    ) -> ExfiltrationFeatures:

        outbound_bytes = max(int(outbound_bytes), 0)
        inbound_bytes = max(int(inbound_bytes), 0)
        outbound_packets = max(int(outbound_packets), 0)
        inbound_packets = max(int(inbound_packets), 0)

        total_bytes = outbound_bytes + inbound_bytes
        total_packets = outbound_packets + inbound_packets

        if inbound_bytes > 0:
            outbound_inbound_byte_ratio = (
                outbound_bytes / inbound_bytes
            )
        elif outbound_bytes > 0:
            outbound_inbound_byte_ratio = float("inf")
        else:
            outbound_inbound_byte_ratio = 0.0

        outbound_byte_ratio = (
            outbound_bytes / total_bytes
            if total_bytes > 0
            else 0.0
        )

        outbound_packet_ratio = (
            outbound_packets / total_packets
            if total_packets > 0
            else 0.0
        )

        return ExfiltrationFeatures(
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            outbound_bytes=outbound_bytes,
            inbound_bytes=inbound_bytes,
            total_bytes=total_bytes,
            outbound_packets=outbound_packets,
            inbound_packets=inbound_packets,
            total_packets=total_packets,
            outbound_inbound_byte_ratio=round(
                outbound_inbound_byte_ratio, 3
            )
            if outbound_inbound_byte_ratio != float("inf")
            else float("inf"),
            outbound_byte_ratio=round(
                outbound_byte_ratio, 3
            ),
            outbound_packet_ratio=round(
                outbound_packet_ratio, 3
            ),
        )