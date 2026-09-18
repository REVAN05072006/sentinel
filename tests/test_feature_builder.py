from backend.features.window import WindowFeatures
from backend.models.feature_builder import TrafficFeatureBuilder


window = WindowFeatures(
    start_time=1000.0,
    end_time=1001.0,
    packet_count=100,
    byte_count=50000,
    packets_per_second=100.0,
    bytes_per_second=50000.0,
    syn_count=80,
    syns_per_second=80.0,
    syn_ratio=0.8,
    unique_src_ips=10,
    unique_dst_ips=1,
    unique_dst_ports=1,
    dominant_dst_ip="10.0.0.20",
    dominant_dst_port=443,
    source_ip_entropy=3.2,
)


features = TrafficFeatureBuilder.from_window(window)
feature_names = TrafficFeatureBuilder.feature_names()


print("FEATURE SHAPE:", features.shape)
print("FEATURE VECTOR:", features[0])
print("FEATURE COUNT:", len(feature_names))
print("FEATURE NAMES:", feature_names)


if (
    features.shape == (1, 11)
    and len(feature_names) == 11
    and features[0][0] == 100
    and features[0][1] == 50000
    and features[0][6] == 0.8
    and features[0][10] == 3.2
):
    print("FEATURE BUILDER TEST: PASSED")
else:
    print("FEATURE BUILDER TEST: FAILED")