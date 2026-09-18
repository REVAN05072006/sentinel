from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.window import WindowFeatures


class DDoSDetector:
    def __init__(
        self,
        syn_rate_threshold: float = 50.0,
        syn_ratio_threshold: float = 0.8,
        source_count_threshold: int = 5,
        entropy_threshold: float = 2.0,
    ):
        self.syn_rate_threshold = syn_rate_threshold
        self.syn_ratio_threshold = syn_ratio_threshold
        self.source_count_threshold = source_count_threshold
        self.entropy_threshold = entropy_threshold

    def detect(self, features: WindowFeatures) -> ThreatAlert | None:
        if features.packet_count == 0:
            return None

        signals = 0

        if features.syns_per_second >= self.syn_rate_threshold:
            signals += 1

        if features.syn_ratio >= self.syn_ratio_threshold:
            signals += 1

        if features.unique_src_ips >= self.source_count_threshold:
            signals += 1

        if features.source_ip_entropy >= self.entropy_threshold:
            signals += 1

        if signals < 2:
            return None

        confidence = min(
            1.0,
            0.25 * signals
            + 0.25
            * min(
                features.syns_per_second / self.syn_rate_threshold,
                1.0,
            ),
        )

        if confidence >= 0.85:
            severity = "CRITICAL"
        elif confidence >= 0.65:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        evidence = {
            "syn_rate": round(features.syns_per_second, 2),
            "syn_ratio": round(features.syn_ratio, 3),
            "unique_source_ips": features.unique_src_ips,
            "source_ip_entropy": round(
                features.source_ip_entropy,
                3,
            ),
            "window_packets": features.packet_count,
            "window_bytes": features.byte_count,
        }

        return ThreatAlert(
            timestamp=datetime.fromtimestamp(
                features.end_time,
                tz=timezone.utc,
            ),
            threat_class="SYN_FLOOD",
            confidence=round(confidence, 3),
            severity=severity,
            destination_ip=features.dominant_dst_ip,
            destination_port=features.dominant_dst_port,
            protocol="TCP",
            evidence=evidence,
        )