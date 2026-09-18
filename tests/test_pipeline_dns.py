from backend.ingest.stream import PacketRecord
from backend.pipeline import SentinelPipeline


def dns_packet(
    timestamp: float,
    query: str,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip="10.0.0.50",
        dst_ip="8.8.8.8",
        protocol="UDP",
        src_port=50000,
        dst_port=53,
        packet_size=150,
        tcp_flags=None,
        dns_query=query,
    )


packets = []

queries = [
    "xq7mz91k2p8v4n6b.example.com",
    "ajd83kq91mz7x2p9v4.example.com",
    "p8v2m9x4q7z1k6n3.example.com",
    "z7q2m8v4x9p1k5n6.example.com",
    "k9x3m7q2v8z1p6n4.example.com",
    "m4z8q2x7v9p3k1n6.example.com",
    "q6v1m9x3z8p2k7n4.example.com",
    "x8k2m7q9v3z1p6n5.example.com",
    "v5z9q2m8x1p7k3n6.example.com",
    "n7x3q8m1z6p2k9v4.example.com",
    "p2m9x4z7q1v8k3n6.example.com",
    "z4q7m1x8v3p9k2n6.example.com",
]

for index, query in enumerate(queries):
    packets.append(
        dns_packet(
            timestamp=1000.0 + index * 0.5,
            query=query,
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