from datetime import datetime, timezone, timedelta

from backend.alerts.schema import ThreatAlert
from backend.pipeline import SentinelPipeline


base_time = datetime(
    2026,
    1,
    1,
    0,
    0,
    0,
    tzinfo=timezone.utc,
)


def make_alert(
    source_ip,
    threat_class,
    seconds,
    confidence,
):
    return ThreatAlert(
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
            "threat_class": threat_class,
        },
    )


pipeline = SentinelPipeline(
    evidence_correlation_window=300.0,
)

alerts = [
    make_alert(
        "10.0.0.70",
        "DGA_DOMAIN",
        0,
        0.95,
    ),
    make_alert(
        "10.0.0.70",
        "C2_BEACONING",
        10,
        0.90,
    ),
    make_alert(
        "10.0.0.70",
        "ENCRYPTED_MALWARE",
        20,
        0.92,
    ),
    make_alert(
        "10.0.0.70",
        "DATA_EXFILTRATION",
        30,
        0.96,
    ),
]


for alert in alerts:
    pipeline.alert_deduplicator.process(alert)


correlated = pipeline.get_correlated_evidence()


print("CORRELATED CHAINS:", len(correlated))

for chain in correlated:
    print("SOURCE:", chain.source_ip)
    print("THREATS:", chain.threat_classes)
    print("CONFIDENCE:", chain.correlation_confidence)
    print("EVIDENCE COUNT:", len(chain.evidence_chain))

if (
    len(correlated) == 1
    and correlated[0].source_ip == "10.0.0.70"
    and correlated[0].threat_classes == [
        "DGA_DOMAIN",
        "C2_BEACONING",
        "ENCRYPTED_MALWARE",
        "DATA_EXFILTRATION",
    ]
    and len(correlated[0].evidence_chain) == 4
    and correlated[0].correlation_confidence == 1.0
):
    print("PIPELINE CORRELATION TEST: PASSED")
else:
    print("PIPELINE CORRELATION TEST: FAILED")
