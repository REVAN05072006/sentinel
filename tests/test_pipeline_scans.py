from backend.ingest.stream import PacketRecord
from backend.pipeline import SentinelPipeline


def tcp_packet(
    timestamp: float,
    source_ip: str,
    destination_ip: str,
    destination_port: int,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=source_ip,
        dst_ip=destination_ip,
        protocol="TCP",
        src_port=50000,
        dst_port=destination_port,
        packet_size=64,
        tcp_flags="A",
        dns_query=None,
    )


packets = []

for index, port in enumerate(
    [21, 22, 23, 25, 53, 80, 110, 135, 139, 443]
):
    packets.append(
        tcp_packet(
            timestamp=1000.0 + index * 0.1,
            source_ip="10.0.0.50",
            destination_ip="10.0.0.20",
            destination_port=port,
        )
    )


for index in range(10):
    packets.append(
        tcp_packet(
            timestamp=1002.0 + index * 0.1,
            source_ip="10.0.0.60",
            destination_ip=f"10.0.1.{index + 1}",
            destination_port=443,
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