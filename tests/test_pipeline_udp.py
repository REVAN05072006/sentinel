from backend.ingest.stream import PacketRecord
from backend.pipeline import SentinelPipeline


packets = []

source_ips = [
    "192.0.2.1",
    "192.0.2.2",
    "192.0.2.3",
    "192.0.2.4",
    "192.0.2.5",
    "192.0.2.6",
    "192.0.2.7",
    "192.0.2.8",
    "192.0.2.9",
    "192.0.2.10",
    "192.0.2.11",
    "192.0.2.12",
]

for index in range(120):
    packets.append(
        PacketRecord(
            timestamp=1000.0 + index * 0.005,
            src_ip=source_ips[index % len(source_ips)],
            dst_ip="10.0.0.20",
            protocol="UDP",
            src_port=40000 + index,
            dst_port=443,
            packet_size=1200,
            tcp_flags=None,
            dns_query=None,
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
        "| CONF:",
        alert.alert.confidence,
        "| SEVERITY:",
        alert.alert.severity,
        "| COUNT:",
        alert.detection_count,
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