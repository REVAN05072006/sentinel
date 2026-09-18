from dataclasses import dataclass

from backend.alerts.deduplicator import ActiveAlert
from backend.correlation.evidence_engine import CorrelatedEvidence
from backend.scoring.pipeline_intelligence import (
    IntelligenceResult,
    PipelineIntelligenceEngine,
)


@dataclass(frozen=True)
class SentinelIntelligenceResult:
    """
    Final analytical intelligence produced from one Sentinel
    processing cycle.
    """

    results: list[IntelligenceResult]
    highest_score: float
    highest_risk: str
    alert_count: int
    correlated_chain_count: int


class SentinelIntelligence:
    """
    Coordinates ML, detector, and correlation evidence.

    This class does not inspect payloads, transmit packets,
    probe systems, or perform mitigation.
    """

    RISK_ORDER = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    def __init__(
        self,
        intelligence_engine: PipelineIntelligenceEngine | None = None,
    ):
        self.engine = (
            intelligence_engine
            if intelligence_engine is not None
            else PipelineIntelligenceEngine()
        )

    def evaluate(
        self,
        alerts: list[ActiveAlert],
        correlated_evidence: list[CorrelatedEvidence],
        ml_scores: dict[str, float] | None = None,
    ) -> SentinelIntelligenceResult:
        """
        Evaluate the current detector alerts.

        ml_scores maps source IP addresses to the ML anomaly score
        associated with the same observation context.
        """

        if ml_scores is None:
            ml_scores = {}

        results = []

        evidence_by_source = {
            evidence.source_ip: evidence
            for evidence in correlated_evidence
        }

        for alert in alerts:
            source_ip = alert.alert.source_ip

            ml_score = float(
                ml_scores.get(
                    source_ip,
                    0.0,
                )
            )

            evidence = evidence_by_source.get(
                source_ip
            )

            correlation_score = 0.0
            progression_score = 0.0

            if evidence is not None:
                correlation_score = (
                    evidence.correlation_quality
                )

                progression_score = (
                    evidence.progression_score
                )

            result = self.engine.score_alert(
                alert=alert,
                ml_anomaly_score=ml_score,
                correlation_score=correlation_score,
                progression_score=progression_score,
            )

            results.append(result)

        highest_score = 0.0
        highest_risk = "LOW"

        for result in results:
            score = result.threat_score.unified_score
            risk = result.threat_score.risk_level

            if score > highest_score:
                highest_score = score

            if (
                self.RISK_ORDER[risk]
                > self.RISK_ORDER[highest_risk]
            ):
                highest_risk = risk

        return SentinelIntelligenceResult(
            results=results,
            highest_score=round(
                highest_score,
                4,
            ),
            highest_risk=highest_risk,
            alert_count=len(results),
            correlated_chain_count=len(
                correlated_evidence
            ),
        )