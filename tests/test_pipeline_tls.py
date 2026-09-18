from backend.pipeline import SentinelPipeline
from backend.ingest.stream import PacketRecord


pipeline = SentinelPipeline()

packets = [
    PacketRecord(
        timestamp=1000.0,
        src_ip="10.0.0.30",
        dst_ip="203.0.113.30",
        protocol="TCP",
        src_port=53000,
        dst_port=443,
        packet_size=1500,
        tcp_flags="A",
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1000.1,
        src_ip="10.0.0.30",
        dst_ip="203.0.113.30",
        protocol="TCP",
        src_port=53000,
        dst_port=443,
        packet_size=200,
        tcp_flags="A",
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1000.7,
        src_ip="10.0.0.30",
        dst_ip="203.0.113.30",
        protocol="TCP",
        src_port=53000,
        dst_port=443,
        packet_size=1400,
        tcp_flags="A",
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1000.8,
        src_ip="10.0.0.30",
        dst_ip="203.0.113.30",
        protocol="TCP",
        src_port=53000,
        dst_port=443,
        packet_size=180,
        tcp_flags="A",
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1001.5,
        src_ip="10.0.0.30",
        dst_ip="203.0.113.30",
        protocol="TCP",
        src_port=53000,
        dst_port=443,
        packet_size=1450,
        tcp_flags="A",
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1001.6,
        src_ip="10.0.0.30",
        dst_ip="203.0.113.30",
        protocol="TCP",
        src_port=53000,
        dst_port=443,
        packet_size=150,
        tcp_flags="A",
        dns_query=None,
    ),
]


result = pipeline.process_packets(packets)

assert len(result.alerts) == 1
assert len(result.incidents) == 1

active_alert = result.alerts[0]
alert = active_alert.alert

assert alert.threat_class == "ENCRYPTED_MALWARE"
assert alert.source_ip == "10.0.0.30"
assert alert.destination_ip == "203.0.113.30"
assert alert.destination_port == 443
assert alert.protocol == "TLS"

assert alert.confidence >= 0.75
assert alert.severity == "HIGH"

assert "high_packet_size_variability" in alert.evidence["signals"]
assert "bursty_timing" in alert.evidence["signals"]
assert "high_timing_variability" in alert.evidence["signals"]

incident = result.incidents[0]

assert incident.threat_class == "ENCRYPTED_MALWARE"
assert incident.destination_ip == "203.0.113.30"
assert incident.destination_port == 443
assert incident.protocol == "TLS"
assert incident.confidence >= 0.75
assert incident.severity == "HIGH"

print("TLS PIPELINE TEST: PASSED")
print("ACTIVE ALERTS:", len(result.alerts))
print("INCIDENTS:", len(result.incidents))
print("THREAT:", alert.threat_class)
print("CONFIDENCE:", alert.confidence)
print("SEVERITY:", alert.severity)
print("SIGNALS:", alert.evidence["signals"])