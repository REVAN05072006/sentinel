from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.window import WindowFeatures


class UDPReflectionDetector:
    """
    Detects passive indicators consistent with UDP reflection
    or amplification attacks.

    Detection uses only observed one-way traffic. It does not
    attempt to prove spoofing or reconstruct unseen request traffic.
    """

    def __init__(
        self,
        udp_rate_threshold: float = 100.0,
        source_count_threshold: int = 10,
        entropy_threshold: float = 2.5,
        byte_rate_threshold: float = 10000.0,
    ):
        self.udp_rate_threshold = udp_rate_threshold
        self.source_count_threshold = source_count_threshold
        self.entropy_threshold = entropy_threshold
        self.byte_rate_threshold = byte_rate_threshold

    def detect(
        self,
        features: WindowFeatures,
    ) -> ThreatAlert | None:
        if features.packet_count == 0:
            return None

        if features.dominant_dst_ip is None:
            return None

        signals = []

        if features.packets_per_second >= self.udp_rate_threshold:
            signals.append("high_udp_packet_rate")

        if features.unique_src_ips >= self.source_count_threshold:
            signals.append("high_source_count")

        if features.source_ip_entropy >= self.entropy_threshold:
            signals.append("high_source_ip_entropy")

        if features.bytes_per_second >= self.byte_rate_threshold:
            signals.append("high_udp_byte_rate")

        if features.dominant_dst_port is None:
            return None

        # Reflection/amplification should exhibit distributed
        # sources sending substantial traffic toward one destination.
        distributed_sources = (
            features.unique_src_ips >= self.source_count_threshold
            and features.source_ip_entropy >= self.entropy_threshold
        )

        high_volume = (
            features.packets_per_second >= self.udp_rate_threshold
            or features.bytes_per_second >= self.byte_rate_threshold
        )

        if not (distributed_sources and high_volume):
            return None

        signal_count = len(signals)

        confidence = min(
            1.0,
            0.35
            + 0.15 * min(signal_count, 4)
            + 0.20
            * min(
                features.packets_per_second
                / self.udp_rate_threshold,
                1.0,
            )
            + 0.10
            * min(
                features.bytes_per_second
                / self.byte_rate_threshold,
                1.0,
            ),
        )

        if confidence >= 0.90:
            severity = "CRITICAL"
        elif confidence >= 0.75:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        evidence = {
            "udp_packet_rate": round(
                features.packets_per_second,
                2,
            ),
            "udp_byte_rate": round(
                features.bytes_per_second,
                2,
            ),
            "unique_source_ips": features.unique_src_ips,
            "source_ip_entropy": round(
                features.source_ip_entropy,
                3,
            ),
            "dominant_destination_ip": features.dominant_dst_ip,
            "dominant_destination_port": features.dominant_dst_port,
            "window_packets": features.packet_count,
            "window_bytes": features.byte_count,
            "observed_indicators": signals,
            "signal_count": signal_count,
        }

        return ThreatAlert(
            timestamp=datetime.fromtimestamp(
                features.end_time,
                tz=timezone.utc,
            ),
            threat_class="UDP_REFLECTION_AMPLIFICATION",
            confidence=round(confidence, 3),
            severity=severity,
            destination_ip=features.dominant_dst_ip,
            destination_port=features.dominant_dst_port,
            protocol="UDP",
            evidence=evidence,
        )