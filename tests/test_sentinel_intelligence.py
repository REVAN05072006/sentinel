from datetime import datetime, timezone

from backend.alerts.deduplicator import ActiveAlert
from backend.alerts.schema import ThreatAlert
from backend.correlation.evidence_engine import CorrelatedEvidence
from backend.scoring.sentinel_intelligence import SentinelIntelligence


timestamp = datetime.now(timezone.utc)


def create_alert(
    threat_class: str,
    confidence: float,
) -> ActiveAlert:
    alert = ThreatAlert(
        timestamp=timestamp,
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
        first_seen=timestamp,
        last_seen=timestamp,
    )


alerts = [
    create_alert(
        "DGA_DOMAIN",
        0.92,
    ),
    create_alert(
        "C2_BEACONING",
        0.94,
    ),
    create_alert(
        "ENCRYPTED_MALWARE",
        0.96,
    ),
]


evidence = CorrelatedEvidence(
    source_ip="10.0.0.70",
    threat_classes=[
        "DGA_DOMAIN",
        "C2_BEACONING",
        "ENCRYPTED_MALWARE",
    ],
    first_seen=timestamp,
    last_seen=timestamp,
    correlation_confidence=1.0,
    progression_score=1.0,
    correlation_quality=0.95,
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
    ],
    evidence_chain=[
        {
            "threat_class": "DGA_DOMAIN",
            "confidence": 0.92,
        },
        {
            "threat_class": "C2_BEACONING",
            "confidence": 0.94,
        },
        {
            "threat_class": "ENCRYPTED_MALWARE",
            "confidence": 0.96,
        },
    ],
)


engine = SentinelIntelligence()


result = engine.evaluate(
    alerts=alerts,
    correlated_evidence=[evidence],
    ml_scores={
        "10.0.0.70": 0.91,
    },
)


print(
    "INTELLIGENCE ALERTS:",
    result.alert_count,
)

print(
    "CORRELATED CHAINS:",
    result.correlated_chain_count,
)

print(
    "HIGHEST SCORE:",
    result.highest_score,
)

print(
    "HIGHEST RISK:",
    result.highest_risk,
)


for intelligence in result.results:
    print(
        intelligence.threat_class,
        "=>",
        intelligence.threat_score.unified_score,
        intelligence.threat_score.risk_level,
    )


assert result.alert_count == 3

assert result.correlated_chain_count == 1

assert result.highest_score > 0.85

assert result.highest_risk == "CRITICAL"

assert all(
    item.threat_score.unified_score > 0.85
    for item in result.results
)

assert all(
    item.threat_score.risk_level == "CRITICAL"
    for item in result.results
)


print(
    "SENTINEL INTELLIGENCE TEST: PASSED"
)