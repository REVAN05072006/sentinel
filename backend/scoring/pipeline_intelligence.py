from dataclasses import dataclass
from typing import Iterable

from backend.alerts.deduplicator import ActiveAlert
from backend.correlation.evidence_engine import CorrelatedEvidence
from backend.scoring.risk_policy import RiskDecision, RiskPolicy
from backend.scoring.threat_score import ThreatScore, ThreatScoreEngine


@dataclass(frozen=True)
class IntelligenceResult:
    source_ip: str | None
    threat_class: str | None
    threat_score: ThreatScore
    risk_decision: RiskDecision
    ml_anomaly_score: float
    supporting_alerts: int


class PipelineIntelligenceEngine:
    """
    Converts Sentinel detector alerts, ML anomaly scores, and
    correlation evidence into unified analyst-facing intelligence.

    This layer performs analytical scoring only.

    It does not:
        - transmit traffic
        - probe systems
        - modify packets
        - block traffic
        - issue mitigation commands
    """

    def __init__(
        self,
        score_engine: ThreatScoreEngine | None = None,
        risk_policy: RiskPolicy | None = None,
    ):
        self.score_engine = (
            score_engine
            if score_engine is not None
            else ThreatScoreEngine()
        )

        self.risk_policy = (
            risk_policy
            if risk_policy is not None
            else RiskPolicy()
        )

    def score_alert(
        self,
        alert: ActiveAlert,
        ml_anomaly_score: float = 0.0,
        correlation_score: float = 0.0,
        progression_score: float = 0.0,
    ) -> IntelligenceResult:
        """
        Score a single active detector alert.
        """

        threat_score = self.score_engine.calculate(
            detector_score=alert.alert.confidence,
            ml_score=ml_anomaly_score,
            correlation_score=correlation_score,
            progression_score=progression_score,
        )

        risk_decision = self.risk_policy.evaluate(
            threat_score
        )

        return IntelligenceResult(
            source_ip=alert.alert.source_ip,
            threat_class=alert.alert.threat_class,
            threat_score=threat_score,
            risk_decision=risk_decision,
            ml_anomaly_score=ml_anomaly_score,
            supporting_alerts=alert.detection_count,
        )

    def score_alerts(
        self,
        alerts: Iterable[ActiveAlert],
        ml_anomaly_score: float = 0.0,
        correlated_evidence: Iterable[
            CorrelatedEvidence
        ] | None = None,
    ) -> list[IntelligenceResult]:
        """
        Score all active alerts.

        Correlation evidence is matched by source IP.
        """

        evidence_by_source = {}

        if correlated_evidence is not None:
            for evidence in correlated_evidence:
                evidence_by_source[
                    evidence.source_ip
                ] = evidence

        results = []

        for alert in alerts:
            source_ip = alert.alert.source_ip

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

            results.append(
                self.score_alert(
                    alert=alert,
                    ml_anomaly_score=ml_anomaly_score,
                    correlation_score=correlation_score,
                    progression_score=progression_score,
                )
            )

        return results

    def score_correlated_chain(
        self,
        evidence: CorrelatedEvidence,
        detector_score: float,
        ml_anomaly_score: float = 0.0,
    ) -> IntelligenceResult:
        """
        Produce one unified score for a correlated attack chain.
        """

        threat_class = (
            evidence.threat_classes[-1]
            if evidence.threat_classes
            else None
        )

        threat_score = self.score_engine.calculate(
            detector_score=detector_score,
            ml_score=ml_anomaly_score,
            correlation_score=evidence.correlation_quality,
            progression_score=evidence.progression_score,
        )

        risk_decision = self.risk_policy.evaluate(
            threat_score
        )

        return IntelligenceResult(
            source_ip=evidence.source_ip,
            threat_class=threat_class,
            threat_score=threat_score,
            risk_decision=risk_decision,
            ml_anomaly_score=ml_anomaly_score,
            supporting_alerts=len(
                evidence.evidence_chain
            ),
        )