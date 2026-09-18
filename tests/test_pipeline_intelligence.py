from datetime import datetime, timedelta, timezone

from backend.alerts.deduplicator import ActiveAlert
from backend.alerts.schema import ThreatAlert
from backend.correlation.evidence_engine import (
    CorrelatedEvidence,
)
from backend.scoring.pipeline_intelligence import (
    PipelineIntelligenceEngine,
)


now = datetime.now(timezone.utc)


def create_alert(
    threat_class: str,
    confidence: float,
) -> ActiveAlert:
    alert = ThreatAlert(
        timestamp=now,
        flow_id=None,
        threat_class=threat_class,
        confidence=confidence,
        severity="HIGH",
        source_ip="10.0.0.70",
        destination_ip="10.0.0.20",
        destination_port=443,
        protocol="TCP",
        evidence={
            "test": True,
        },
    )

    return ActiveAlert(
        alert=alert,
        detection_count=1,
        first_seen=now,
        last_seen=now,
    )


alert = create_alert(
    "ENCRYPTED_MALWARE",
    0.95,
)


evidence = CorrelatedEvidence(
    source_ip="10.0.0.70",
    threat_classes=[
        "DGA_DOMAIN",
        "C2_BEACONING",
        "ENCRYPTED_MALWARE",
        "DATA_EXFILTRATION",
    ],
    first_seen=now,
    last_seen=now + timedelta(seconds=20),
    correlation_confidence=1.0,
    progression_score=1.0,
    correlation_quality=0.966,
    progression_pairs=[
        {
            "from": "DGA_DOMAIN",
            "to": "C2_BEACONING",
            "score": 1.0,
        },
        {
            "from": "C2_BEACONING",
            "to": "ENCRYPTED_MALWARE",
            "score": 1.0,
        },
        {
            "from": "ENCRYPTED_MALWARE",
            "to": "DATA_EXFILTRATION",
            "score": 1.0,
        },
    ],
    evidence_chain=[
        {
            "threat_class": threat,
            "confidence": 0.95,
        }
        for threat in [
            "DGA_DOMAIN",
            "C2_BEACONING",
            "ENCRYPTED_MALWARE",
            "DATA_EXFILTRATION",
        ]
    ],
)


engine = PipelineIntelligenceEngine()


results = engine.score_alerts(
    alerts=[alert],
    ml_anomaly_score=0.91,
    correlated_evidence=[evidence],
)


assert len(results) == 1


result = results[0]


print(
    "SOURCE:",
    result.source_ip,
)

print(
    "THREAT:",
    result.threat_class,
)

print(
    "DETECTOR SCORE:",
    result.threat_score.detector_score,
)

print(
    "ML SCORE:",
    result.threat_score.ml_score,
)

print(
    "CORRELATION SCORE:",
    result.threat_score.correlation_score,
)

print(
    "PROGRESSION SCORE:",
    result.threat_score.progression_score,
)

print(
    "UNIFIED SCORE:",
    result.threat_score.unified_score,
)

print(
    "RISK LEVEL:",
    result.threat_score.risk_level,
)

print(
    "ALERT REQUIRED:",
    result.risk_decision.requires_alert,
)

print(
    "RATIONALE:",
    result.risk_decision.rationale,
)


assert (
    result.threat_score.detector_score
    == 0.95
)

assert (
    result.threat_score.ml_score
    == 0.91
)

assert (
    result.threat_score.correlation_score
    == 0.966
)

assert (
    result.threat_score.progression_score
    == 1.0
)

assert (
    result.threat_score.unified_score
    > 0.90
)

assert (
    result.threat_score.risk_level
    == "CRITICAL"
)

assert (
    result.risk_decision.requires_alert
    is True
)

print(
    "PIPELINE INTELLIGENCE TEST: PASSED"
)