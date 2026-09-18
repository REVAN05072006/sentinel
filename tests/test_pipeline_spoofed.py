from backend.pipeline import SentinelPipeline
from backend.ingest.stream import PacketRecord


pipeline = SentinelPipeline()

packets = []

for i in range(200):
    packets.append(
        PacketRecord(
            timestamp=1000.0 + (i * 0.004),
            src_ip=f"192.168.1.{(i % 80) + 1}",
            dst_ip="10.0.0.20",
            protocol="TCP",
            src_port=40000 + i,
            dst_port=443,
            packet_size=600,
            tcp_flags="S",
            dns_query=None,
        )
    )

result = pipeline.process_packets(packets)

print("ACTIVE ALERTS:", len(result.alerts))
print("INCIDENTS:", len(result.incidents))

for active in result.alerts:
    print(
        "ALERT:",
        active.alert.threat_class,
        "| CONF:",
        active.alert.confidence,
        "| SEVERITY:",
        active.alert.severity,
        "| COUNT:",
        active.detection_count,
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