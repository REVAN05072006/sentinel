from datetime import datetime, timezone, timedelta

from backend.alerts.schema import ThreatAlert
from backend.alerts.deduplicator import ActiveAlert
from backend.correlation.evidence_engine import EvidenceCorrelationEngine


base_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def active_alert(
    source_ip,
    threat_class,
    seconds,
    confidence=0.9,
):
    alert = ThreatAlert(
        timestamp=base_time + timedelta(seconds=seconds),
        threat_class=threat_class,
        confidence=confidence,
        severity="HIGH",
        source_ip=source_ip,
        destination_ip="203.0.113.10",
        destination_port=443,
        protocol="TCP",
        evidence={
            "test": True
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
    ),
    active_alert(
        "10.0.0.71",
        "C2_BEACONING",
        10,
    ),
    active_alert(
        "10.0.0.70",
        "DATA_EXFILTRATION",
        400,
    ),
]


engine = EvidenceCorrelationEngine(
    correlation_window=300.0
)

correlated = engine.correlate(alerts)

print("CORRELATED CHAINS:", len(correlated))

for chain in correlated:
    print(
        "SOURCE:",
        chain.source_ip,
        "| THREATS:",
        chain.threat_classes,
    )

if (
    len(correlated) == 0
):
    print("NEGATIVE CORRELATION TEST: PASSED")
else:
    print("NEGATIVE CORRELATION TEST: FAILED")
