from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.dns_features import DNSFeatureExtractor
from backend.features.dns_tracker import DNSQueryGroup


class DNSTunnellingDetector:
    """
    Detects passive behavioral indicators consistent with DNS tunnelling.

    Detection considers repeated DNS queries with long, high-entropy,
    frequently changing query names and unusually high query volume.

    No DNS lookups or active network interaction are performed.
    """

    def __init__(
        self,
        minimum_queries: int = 10,
        long_query_threshold: int = 30,
        entropy_threshold: float = 3.8,
        unique_ratio_threshold: float = 0.70,
        average_query_length_threshold: float = 25.0,
    ):
        self.minimum_queries = minimum_queries
        self.long_query_threshold = long_query_threshold
        self.entropy_threshold = entropy_threshold
        self.unique_ratio_threshold = unique_ratio_threshold
        self.average_query_length_threshold = (
            average_query_length_threshold
        )

    def detect(
        self,
        group: DNSQueryGroup,
    ) -> ThreatAlert | None:
        if group.total_queries < self.minimum_queries:
            return None

        features = [
            DNSFeatureExtractor.extract(query)
            for query in group.queries
            if query
        ]

        if not features:
            return None

        long_query_count = sum(
            feature.query_length
            >= self.long_query_threshold
            for feature in features
        )

        high_entropy_count = sum(
            feature.entropy
            >= self.entropy_threshold
            for feature in features
        )

        average_query_length = (
            sum(
                feature.query_length
                for feature in features
            )
            / len(features)
        )

        long_query_ratio = (
            long_query_count / len(features)
        )

        high_entropy_ratio = (
            high_entropy_count / len(features)
        )

        unique_query_ratio = (
            group.unique_queries
            / group.total_queries
        )

        signals = []

        if long_query_ratio >= 0.60:
            signals.append("long_query_names")

        if high_entropy_ratio >= 0.60:
            signals.append("high_entropy_queries")

        if unique_query_ratio >= self.unique_ratio_threshold:
            signals.append("high_unique_query_ratio")

        if (
            average_query_length
            >= self.average_query_length_threshold
        ):
            signals.append("high_average_query_length")

        if len(signals) < 2:
            return None

        confidence = min(
            1.0,
            0.20 * len(signals)
            + 0.20 * long_query_ratio
            + 0.20 * high_entropy_ratio
            + 0.20 * unique_query_ratio
            + 0.20 * min(
                average_query_length
                / self.average_query_length_threshold,
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
            "source_ip": group.source_ip,
            "dns_server": group.destination_ip,
            "total_queries": group.total_queries,
            "unique_queries": group.unique_queries,
            "unique_query_ratio": round(
                unique_query_ratio,
                3,
            ),
            "average_query_length": round(
                average_query_length,
                3,
            ),
            "long_query_ratio": round(
                long_query_ratio,
                3,
            ),
            "high_entropy_ratio": round(
                high_entropy_ratio,
                3,
            ),
            "total_query_bytes": group.total_query_bytes,
            "signals": signals,
            "signal_count": len(signals),
        }

        return ThreatAlert(
            timestamp=datetime.fromtimestamp(
                max(group.timestamps),
                tz=timezone.utc,
            ),
            threat_class="DNS_TUNNELLING",
            confidence=round(confidence, 3),
            severity=severity,
            source_ip=group.source_ip,
            destination_ip=group.destination_ip,
            destination_port=53,
            protocol="UDP",
            evidence=evidence,
        )