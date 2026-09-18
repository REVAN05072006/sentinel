from backend.ingest.stream import PacketRecord
from backend.pipeline import SentinelPipeline


def beacon_packet(timestamp: float) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip="10.0.0.70",
        dst_ip="203.0.113.70",
        protocol="TCP",
        src_port=51000,
        dst_port=443,
        packet_size=180,
        tcp_flags="A",
        dns_query=None,
    )


packets = []

for index in range(10):
    packets.append(
        beacon_packet(
            timestamp=1000.0 + index * 5.0,
        )
    )


pipeline = SentinelPipeline()

result = pipeline.process_packets(packets)

print("ACTIVE ALERTS:", len(result.alerts))
print("INCIDENTS:", len(result.incidents))

for alert in result.alerts:
    print(
        "ALERT:",
        alert.alert.threat_class,
        "| SOURCE:",
        alert.alert.source_ip,
        "| DESTINATION:",
        alert.alert.destination_ip,
        "| CONF:",
        alert.alert.confidence,
        "| SEVERITY:",
        alert.alert.severity,
        "| COUNT:",
        alert.detection_count,
    )

    print(
        "EVIDENCE:",
        alert.alert.evidence,
    )

for incident in result.incidents:
    print(
        "INCIDENT:",
        incident.incident_id,
        "| THREAT:",
        incident.threat_class,
        "| CONF:",
        incident.confidence,
        "| SEVERITY:",
        incident.severity,
        "| DETECTIONS:",
        incident.detection_count,
    )
