from backend.detectors.spoofed_flood import SpoofedSourceFloodDetector
from backend.features.window import WindowFeatures


detector = SpoofedSourceFloodDetector()


attack = WindowFeatures(
    start_time=1000.0,
    end_time=1001.0,
    packet_count=200,
    byte_count=120000,
    packets_per_second=200.0,
    bytes_per_second=120000.0,
    syn_count=0,
    syns_per_second=0.0,
    syn_ratio=0.0,
    unique_src_ips=80,
    unique_dst_ips=1,
    unique_dst_ports=1,
    dominant_dst_ip="10.0.0.20",
    dominant_dst_port=443,
    source_ip_entropy=6.1,
)

normal = WindowFeatures(
    start_time=1000.0,
    end_time=1001.0,
    packet_count=20,
    byte_count=12000,
    packets_per_second=20.0,
    bytes_per_second=12000.0,
    syn_count=2,
    syns_per_second=2.0,
    syn_ratio=0.1,
    unique_src_ips=3,
    unique_dst_ips=1,
    unique_dst_ports=1,
    dominant_dst_ip="10.0.0.20",
    dominant_dst_port=443,
    source_ip_entropy=1.2,
)


attack_result = detector.detect(attack)
normal_result = detector.detect(normal)

print("ATTACK:", attack_result.model_dump_json(indent=2))
print("NORMAL:", normal_result)