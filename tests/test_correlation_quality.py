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
            "test": True,
        },
    )

    return ActiveAlert(
        alert=alert,
        detection_count=1,
        first_seen=alert.timestamp,
        last_seen=alert.timestamp,
    )


staged_alerts = [
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


unrelated_alerts = [
    active_alert(
        "10.0.0.80",
        "PORT_SCANNING",
        0,
        0.90,
    ),
    active_alert(
        "10.0.0.80",
        "RECONNAISSANCE",
        10,
        0.90,
    ),
]


engine = EvidenceCorrelationEngine(
    correlation_window=300.0,
)


staged = engine.correlate(
    staged_alerts
)

unrelated = engine.correlate(
    unrelated_alerts
)


print("STAGED CHAINS:", len(staged))

if staged:
    print(
        "STAGED QUALITY:",
        staged[0].correlation_quality,
    )

    print(
        "STAGED PROGRESSION:",
        staged[0].progression_score,
    )


print("UNRELATED CHAINS:", len(unrelated))

if unrelated:
    print(
        "UNRELATED QUALITY:",
        unrelated[0].correlation_quality,
    )

    print(
        "UNRELATED PROGRESSION:",
        unrelated[0].progression_score,
    )


if (
    len(staged) == 1
    and len(unrelated) == 1
    and staged[0].correlation_quality
    > unrelated[0].correlation_quality
    and staged[0].progression_score == 1.0
    and unrelated[0].progression_score == 0.0
):
    print("CORRELATION QUALITY TEST: PASSED")
else:
    print("CORRELATION QUALITY TEST: FAILED")
