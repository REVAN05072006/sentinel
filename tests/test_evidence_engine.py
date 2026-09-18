from datetime import datetime, timezone, timedelta

from backend.alerts.schema import ThreatAlert
from backend.alerts.deduplicator import ActiveAlert
from backend.correlation.evidence_engine import EvidenceCorrelationEngine


base_time = datetime(
    2026,
    1,
    1,
    0,
    0,
    0,
    tzinfo=timezone.utc,
)


def active_alert(
    source_ip,
    threat_class,
    seconds,
    confidence,
):
    alert = ThreatAlert(
        timestamp=base_time + timedelta(seconds=seconds),
        threat_class=threat_class,
        confidence=confidence,
        severity="CRITICAL",
        source_ip=source_ip,
        destination_ip="203.0.113.70",
        destination_port=443,
        protocol="TCP",
        evidence={
            "test": True,
        },
    )

    return ActiveAlert(
        alert=alert,
        detection_count=1,
        first_seen=alert.timestamp,
        last_seen=alert.timestamp,
    )


alerts = [
    active_alert(
        "10.0.0.70",
        "DGA_DOMAIN",
        0,
        0.95,
    ),
    active_alert(
        "10.0.0.70",
        "C2_BEACONING",
        10,
        0.90,
    ),
    active_alert(
        "10.0.0.70",
        "ENCRYPTED_MALWARE",
        20,
        0.92,
    ),
    active_alert(
        "10.0.0.70",
        "DATA_EXFILTRATION",
        30,
        0.96,
    ),
]


engine = EvidenceCorrelationEngine(
    correlation_window=300.0,
)

correlated = engine.correlate(alerts)

print("CORRELATED CHAINS:", len(correlated))

for chain in correlated:
    print("SOURCE:", chain.source_ip)
    print("THREATS:", chain.threat_classes)
    print(
        "CORRELATION CONFIDENCE:",
        chain.correlation_confidence,
    )
    print(
        "PROGRESSION SCORE:",
        chain.progression_score,
    )
    print(
        "PROGRESSION PAIRS:",
        len(chain.progression_pairs),
    )

    for pair in chain.progression_pairs:
        print(
            "  -",
            pair["from"],
            "->",
            pair["to"],
            "| SCORE:",
            pair["score"],
        )

    print(
        "EVIDENCE COUNT:",
        len(chain.evidence_chain),
    )


expected_threats = [
    "DGA_DOMAIN",
    "C2_BEACONING",
    "ENCRYPTED_MALWARE",
    "DATA_EXFILTRATION",
]

if (
    len(correlated) == 1
    and correlated[0].source_ip == "10.0.0.70"
    and correlated[0].threat_classes == expected_threats
    and len(correlated[0].evidence_chain) == 4
    and correlated[0].correlation_confidence == 1.0
    and correlated[0].progression_score == 1.0
    and len(correlated[0].progression_pairs) == 3
):
    print("STAGED EVIDENCE CORRELATION TEST: PASSED")
else:
    print("STAGED EVIDENCE CORRELATION TEST: FAILED")
