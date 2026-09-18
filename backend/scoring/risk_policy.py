from dataclasses import dataclass

from backend.scoring.threat_score import ThreatScore


@dataclass(frozen=True)
class RiskDecision:
    risk_level: str
    requires_alert: bool
    analyst_priority: int
    rationale: str


class RiskPolicy:
    """
    Converts the unified threat score into an analyst-facing
    risk decision.

    This policy does not perform mitigation. Sentinel is a
    passive and read-only monitoring system.
    """

    PRIORITY = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
    }

    def __init__(
        self,
        alert_threshold: float = 0.50,
    ):
        if not 0.0 <= alert_threshold <= 1.0:
            raise ValueError(
                "alert_threshold must be between 0 and 1"
            )

        self.alert_threshold = alert_threshold

    def evaluate(
        self,
        threat_score: ThreatScore,
    ) -> RiskDecision:
        score = threat_score.unified_score
        risk_level = threat_score.risk_level

        requires_alert = (
            score >= self.alert_threshold
        )

        analyst_priority = self.PRIORITY[
            risk_level
        ]

        rationale = self._build_rationale(
            threat_score
        )

        return RiskDecision(
            risk_level=risk_level,
            requires_alert=requires_alert,
            analyst_priority=analyst_priority,
            rationale=rationale,
        )

    @staticmethod
    def _build_rationale(
        threat_score: ThreatScore,
    ) -> str:
        components = [
            (
                "detector",
                threat_score.detector_score,
            ),
            (
                "ML anomaly",
                threat_score.ml_score,
            ),
            (
                "correlation",
                threat_score.correlation_score,
            ),
            (
                "progression",
                threat_score.progression_score,
            ),
        ]

        significant = [
            f"{name}={score:.2f}"
            for name, score in components
            if score >= 0.70
        ]

        if significant:
            evidence = ", ".join(
                significant
            )

            return (
                f"Unified threat score "
                f"{threat_score.unified_score:.2f}; "
                f"strong evidence from {evidence}."
            )

        return (
            f"Unified threat score "
            f"{threat_score.unified_score:.2f}; "
            f"no individual supporting component "
            f"exceeded 0.70."
        )