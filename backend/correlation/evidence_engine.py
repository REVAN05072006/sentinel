from dataclasses import dataclass
from datetime import datetime

from backend.alerts.deduplicator import ActiveAlert
from backend.correlation.stages import AttackStageModel


@dataclass
class CorrelatedEvidence:
    source_ip: str
    threat_classes: list[str]
    first_seen: datetime
    last_seen: datetime
    correlation_confidence: float
    progression_score: float
    correlation_quality: float
    progression_pairs: list[dict]
    evidence_chain: list[dict]


class EvidenceCorrelationEngine:
    """
    Correlates deduplicated threat alerts that belong to the
    same source host within a bounded time window.

    The engine evaluates:
        - detector confidence
        - attack-stage progression
        - threat diversity

    These signals are combined into a correlation quality score
    that represents how meaningful the observed correlation is.

    This component is purely analytical and read-only.
    It does not modify alerts, incidents, or network traffic.
    """

    def __init__(self, correlation_window: float = 300.0):
        self.correlation_window = correlation_window

    def correlate(
        self,
        active_alerts: list[ActiveAlert],
    ) -> list[CorrelatedEvidence]:
        grouped: dict[str, list[ActiveAlert]] = {}

        for active in active_alerts:
            source_ip = active.alert.source_ip

            if source_ip is None:
                continue

            grouped.setdefault(
                source_ip,
                [],
            ).append(active)

        correlated = []

        for source_ip, alerts in grouped.items():
            alerts.sort(
                key=lambda item: item.alert.timestamp
            )

            if len(alerts) < 2:
                continue

            clusters = self._build_clusters(alerts)

            for cluster in clusters:
                if len(cluster) < 2:
                    continue

                threat_classes = list(
                    dict.fromkeys(
                        active.alert.threat_class
                        for active in cluster
                    )
                )

                first_seen = min(
                    active.alert.timestamp
                    for active in cluster
                )

                last_seen = max(
                    active.alert.timestamp
                    for active in cluster
                )

                correlation_confidence = (
                    self._calculate_confidence(
                        cluster
                    )
                )

                progression_score, progression_pairs = (
                    self._calculate_progression(
                        cluster
                    )
                )

                correlation_quality = (
                    self._calculate_quality(
                        cluster,
                        progression_score,
                    )
                )

                evidence_chain = [
                    {
                        "threat_class": active.alert.threat_class,
                        "timestamp": active.alert.timestamp,
                        "confidence": active.alert.confidence,
                        "severity": active.alert.severity,
                        "destination_ip": active.alert.destination_ip,
                        "destination_port": active.alert.destination_port,
                        "protocol": active.alert.protocol,
                        "evidence": dict(active.alert.evidence),
                    }
                    for active in cluster
                ]

                correlated.append(
                    CorrelatedEvidence(
                        source_ip=source_ip,
                        threat_classes=threat_classes,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        correlation_confidence=round(
                            correlation_confidence,
                            3,
                        ),
                        progression_score=round(
                            progression_score,
                            3,
                        ),
                        correlation_quality=round(
                            correlation_quality,
                            3,
                        ),
                        progression_pairs=progression_pairs,
                        evidence_chain=evidence_chain,
                    )
                )

        return correlated

    def _build_clusters(
        self,
        alerts: list[ActiveAlert],
    ) -> list[list[ActiveAlert]]:
        clusters = []
        current = [alerts[0]]

        for alert in alerts[1:]:
            elapsed = (
                alert.alert.timestamp
                - current[-1].alert.timestamp
            ).total_seconds()

            if elapsed <= self.correlation_window:
                current.append(alert)
            else:
                clusters.append(current)
                current = [alert]

        clusters.append(current)

        return clusters

    @staticmethod
    def _calculate_confidence(
        alerts: list[ActiveAlert],
    ) -> float:
        confidences = [
            active.alert.confidence
            for active in alerts
        ]

        base_confidence = max(confidences)

        correlation_bonus = min(
            0.15,
            0.05 * (len(alerts) - 1),
        )

        return min(
            1.0,
            base_confidence + correlation_bonus,
        )

    @staticmethod
    def _calculate_progression(
        alerts: list[ActiveAlert],
    ) -> tuple[float, list[dict]]:
        if len(alerts) < 2:
            return 0.0, []

        progression_pairs = []
        progression_scores = []

        for previous, current in zip(
            alerts,
            alerts[1:],
        ):
            previous_threat = (
                previous.alert.threat_class
            )

            current_threat = (
                current.alert.threat_class
            )

            score = AttackStageModel.progression_score(
                previous_threat,
                current_threat,
            )

            if score > 0.0:
                progression_scores.append(score)

                progression_pairs.append(
                    {
                        "from": previous_threat,
                        "to": current_threat,
                        "score": score,
                        "timestamp_from": (
                            previous.alert.timestamp
                        ),
                        "timestamp_to": (
                            current.alert.timestamp
                        ),
                    }
                )

        if not progression_scores:
            return 0.0, []

        progression_score = sum(
            progression_scores
        ) / len(progression_scores)

        return progression_score, progression_pairs

    @staticmethod
    def _calculate_quality(
        alerts: list[ActiveAlert],
        progression_score: float,
    ) -> float:
        """
        Calculate the overall quality of a correlation.

        Components:
            50% detector confidence
            35% attack-stage progression
            15% threat diversity
        """

        confidences = [
            active.alert.confidence
            for active in alerts
        ]

        detector_confidence = (
            sum(confidences) / len(confidences)
        )

        threat_classes = {
            active.alert.threat_class
            for active in alerts
        }

        diversity_score = min(
            1.0,
            len(threat_classes) / 4.0,
        )

        quality = (
            0.50 * detector_confidence
            + 0.35 * progression_score
            + 0.15 * diversity_score
        )

        return min(
            1.0,
            quality,
        )
