from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.dns_features import DNSFeatures


class DGADetector:
    """
    Detects domain names exhibiting statistical characteristics
    commonly associated with Domain Generation Algorithms (DGA).

    Detection uses only passively observed DNS query metadata.
    No DNS lookups or active network interaction are performed.
    """

    def __init__(
        self,
        entropy_threshold: float = 4.0,
        query_length_threshold: int = 20,
        digit_ratio_threshold: float = 0.20,
        vowel_ratio_threshold: float = 0.30,
        unique_char_ratio_threshold: float = 0.75,
    ):
        self.entropy_threshold = entropy_threshold
        self.query_length_threshold = query_length_threshold
        self.digit_ratio_threshold = digit_ratio_threshold
        self.vowel_ratio_threshold = vowel_ratio_threshold
        self.unique_char_ratio_threshold = (
            unique_char_ratio_threshold
        )

    def detect(
        self,
        features: DNSFeatures,
    ) -> ThreatAlert | None:
        if not features.query:
            return None

        signals = []

        if features.entropy >= self.entropy_threshold:
            signals.append("high_entropy")

        if (
            features.query_length
            >= self.query_length_threshold
        ):
            signals.append("long_query")

        if (
            features.digit_ratio
            >= self.digit_ratio_threshold
        ):
            signals.append("high_digit_ratio")

        if (
            features.vowel_ratio
            <= self.vowel_ratio_threshold
        ):
            signals.append("low_vowel_ratio")

        if (
            features.unique_char_ratio
            >= self.unique_char_ratio_threshold
        ):
            signals.append("high_character_diversity")

        if len(signals) < 3:
            return None

        confidence = min(
            1.0,
            0.15 * len(signals)
            + 0.15 * min(
                features.entropy
                / self.entropy_threshold,
                1.0,
            )
            + 0.10 * min(
                features.query_length
                / self.query_length_threshold,
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
            "query": features.query,
            "query_length": features.query_length,
            "entropy": features.entropy,
            "digit_ratio": features.digit_ratio,
            "unique_char_ratio": features.unique_char_ratio,
            "vowel_ratio": features.vowel_ratio,
            "consonant_ratio": features.consonant_ratio,
            "max_label_length": features.max_label_length,
            "subdomain_depth": features.subdomain_depth,
            "signals": signals,
            "signal_count": len(signals),
        }

        return ThreatAlert(
            timestamp=datetime.now(timezone.utc),
            threat_class="DGA_DOMAIN",
            confidence=round(confidence, 3),
            severity=severity,
            evidence=evidence,
        )