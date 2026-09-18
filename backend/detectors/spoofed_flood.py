from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.window import WindowFeatures


class SpoofedSourceFloodDetector:
    """
    Detects passive indicators consistent with a spoofed-source flood.

    Detection relies only on observed traffic characteristics such as
    high packet rate, large source-IP diversity, and high source-IP
    entropy. It does not attempt to actively verify source addresses.
    """

    def __init__(
        self,
        packet_rate_threshold: float = 100.0,
        source_count_threshold: int = 20,
        entropy_threshold: float = 4.0,
    ):
        self.packet_rate_threshold = packet_rate_threshold
        self.source_count_threshold = source_count_threshold
        self.entropy_threshold = entropy_threshold

    def detect(
        self,
        features: WindowFeatures,
    ) -> ThreatAlert | None:
        if features.packet_count == 0:
            return None

        signals = 0

        if (
            features.packets_per_second
            >= self.packet_rate_threshold
        ):
            signals += 1

        if (
            features.unique_src_ips
            >= self.source_count_threshold
        ):
            signals += 1

        if (
            features.source_ip_entropy
            >= self.entropy_threshold
        ):
            signals += 1

        if signals < 2:
            return None

        confidence = min(
            1.0,
            0.30 * signals
            + 0.20
            * min(
                features.packets_per_second
                / self.packet_rate_threshold,
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
            "packet_rate": round(
                features.packets_per_second,
                2,
            ),
            "unique_source_ips": features.unique_src_ips,
            "source_ip_entropy": round(
                features.source_ip_entropy,
                3,
            ),
            "window_packets": features.packet_count,
            "window_bytes": features.byte_count,
            "observed_indicators": signals,
        }

        return ThreatAlert(
            timestamp=datetime.fromtimestamp(
                features.end_time,
                tz=timezone.utc,
            ),
            threat_class="SPOOFED_SOURCE_FLOOD",
            confidence=round(confidence, 3),
            severity=severity,
            destination_ip=features.dominant_dst_ip,
            destination_port=features.dominant_dst_port,
            protocol=None,
            evidence=evidence,
        )