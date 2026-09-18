from dataclasses import dataclass
from statistics import mean, pstdev


@dataclass
class TLSSessionFeatures:
    """
    Metadata-only features derived from an observed encrypted session.

    No encrypted payload is decrypted or inspected.
    """

    session_id: str

    packet_count: int
    total_bytes: int

    mean_packet_size: float
    packet_size_stddev: float

    mean_interarrival: float
    interarrival_stddev: float

    burstiness: float

    client_fingerprint: str | None
    server_fingerprint: str | None


class TLSFeatureExtractor:
    """
    Extract statistical features from encrypted-session metadata.

    The extractor operates only on observable packet sizes,
    timestamps, and optional TLS/QUIC fingerprints.
    """

    @staticmethod
    def extract(
        session_id: str,
        timestamps: list[float],
        packet_sizes: list[int],
        client_fingerprint: str | None = None,
        server_fingerprint: str | None = None,
    ) -> TLSSessionFeatures:

        if len(timestamps) != len(packet_sizes):
            raise ValueError(
                "timestamps and packet_sizes must have equal length"
            )

        if not packet_sizes:
            return TLSSessionFeatures(
                session_id=session_id,
                packet_count=0,
                total_bytes=0,
                mean_packet_size=0.0,
                packet_size_stddev=0.0,
                mean_interarrival=0.0,
                interarrival_stddev=0.0,
                burstiness=0.0,
                client_fingerprint=client_fingerprint,
                server_fingerprint=server_fingerprint,
            )

        sizes = [
            max(int(size), 0)
            for size in packet_sizes
        ]

        ordered_times = sorted(timestamps)

        intervals = [
            current - previous
            for previous, current in zip(
                ordered_times,
                ordered_times[1:],
            )
            if current >= previous
        ]

        mean_packet_size = mean(sizes)

        if len(sizes) > 1:
            packet_size_stddev = pstdev(sizes)
        else:
            packet_size_stddev = 0.0

        if intervals:
            mean_interarrival = mean(intervals)
        else:
            mean_interarrival = 0.0

        if len(intervals) > 1:
            interarrival_stddev = pstdev(intervals)
        else:
            interarrival_stddev = 0.0

        if mean_interarrival > 0:
            burstiness = min(
                1.0,
                interarrival_stddev
                / mean_interarrival,
            )
        else:
            burstiness = 0.0

        return TLSSessionFeatures(
            session_id=session_id,

            packet_count=len(sizes),
            total_bytes=sum(sizes),

            mean_packet_size=round(
                mean_packet_size,
                3,
            ),
            packet_size_stddev=round(
                packet_size_stddev,
                3,
            ),

            mean_interarrival=round(
                mean_interarrival,
                6,
            ),
            interarrival_stddev=round(
                interarrival_stddev,
                6,
            ),

            burstiness=round(
                burstiness,
                3,
            ),

            client_fingerprint=client_fingerprint,
            server_fingerprint=server_fingerprint,
        )