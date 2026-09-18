from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.exfiltration import ExfiltrationFeatures


class DataExfiltrationDetector:
    """
    Detects passive traffic patterns consistent with data exfiltration.

    The detector relies only on observable flow-volume asymmetry.
    It does not inspect or decrypt payload contents.
    """

    def __init__(
        self,
        byte_ratio_threshold: float = 10.0,
        outbound_byte_ratio_threshold: float = 0.90,
        minimum_outbound_bytes: int = 100_000,
    ):
        self.byte_ratio_threshold = byte_ratio_threshold
        self.outbound_byte_ratio_threshold = (
            outbound_byte_ratio_threshold
        )
        self.minimum_outbound_bytes = minimum_outbound_bytes

    def detect(
        self,
        features: ExfiltrationFeatures,
    ) -> ThreatAlert | None:

        if features.outbound_bytes < self.minimum_outbound_bytes:
            return None

        signals = []

        if (
            features.outbound_inbound_byte_ratio
            >= self.byte_ratio_threshold
        ):
            signals.append("high_outbound_inbound_byte_ratio")

        if (
            features.outbound_byte_ratio
            >= self.outbound_byte_ratio_threshold
        ):
            signals.append("high_outbound_byte_ratio")

        if features.outbound_packet_ratio >= 0.90:
            signals.append("high_outbound_packet_ratio")

        if len(signals) < 2:
            return None

        ratio_score = min(
            features.outbound_inbound_byte_ratio
            / self.byte_ratio_threshold,
            1.0,
        )

        confidence = min(
            1.0,
            0.30
            + 0.20 * len(signals)
            + 0.20 * ratio_score
            + 0.15 * features.outbound_byte_ratio
            + 0.15 * features.outbound_packet_ratio,
        )

        if confidence >= 0.90:
            severity = "CRITICAL"
        elif confidence >= 0.75:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        evidence = {
            "source_ip": features.source_ip,
            "destination_ip": features.destination_ip,
            "protocol": features.protocol,
            "outbound_bytes": features.outbound_bytes,
            "inbound_bytes": features.inbound_bytes,
            "total_bytes": features.total_bytes,
            "outbound_packets": features.outbound_packets,
            "inbound_packets": features.inbound_packets,
            "outbound_inbound_byte_ratio": (
                features.outbound_inbound_byte_ratio
            ),
            "outbound_byte_ratio": features.outbound_byte_ratio,
            "outbound_packet_ratio": features.outbound_packet_ratio,
            "signals": signals,
            "signal_count": len(signals),
        }

        return ThreatAlert(
            timestamp=datetime.now(timezone.utc),
            threat_class="DATA_EXFILTRATION",
            confidence=round(confidence, 3),
            severity=severity,
            source_ip=features.source_ip,
            destination_ip=features.destination_ip,
            protocol=features.protocol,
            evidence=evidence,
        )