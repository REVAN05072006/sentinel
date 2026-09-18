from backend.features.window import WindowFeatures
from backend.models.ml_pipeline import TrafficMLPipeline


normal_windows = [
    WindowFeatures(
        start_time=float(index),
        end_time=float(index) + 1.0,
        packet_count=100 + (index % 5),
        byte_count=50000 + (index * 100),
        packets_per_second=100.0 + (index % 5),
        bytes_per_second=50000.0 + (index * 100),
        syn_count=5 + (index % 2),
        syns_per_second=5.0 + (index % 2),
        syn_ratio=0.05,
        unique_src_ips=3 + (index % 2),
        unique_dst_ips=2,
        unique_dst_ports=2,
        dominant_dst_ip="10.0.0.20",
        dominant_dst_port=443,
        source_ip_entropy=1.5,
    )
    for index in range(30)
]


anomalous_window = WindowFeatures(
    start_time=100.0,
    end_time=101.0,
    packet_count=5000,
    byte_count=5000000,
    packets_per_second=5000.0,
    bytes_per_second=5000000.0,
    syn_count=4500,
    syns_per_second=4500.0,
    syn_ratio=0.90,
    unique_src_ips=100,
    unique_dst_ips=1,
    unique_dst_ports=1,
    dominant_dst_ip="10.0.0.20",
    dominant_dst_port=443,
    source_ip_entropy=6.5,
)


ml_pipeline = TrafficMLPipeline(
    contamination=0.05,
    random_state=42,
)


ml_pipeline.fit(normal_windows)

normal_results = ml_pipeline.predict_windows(
    normal_windows
)

anomalous_result = ml_pipeline.predict(
    anomalous_window
)


normal_average_score = sum(
    result.anomaly_score
    for result in normal_results
) / len(normal_results)


print(
    "NORMAL WINDOWS:",
    len(normal_results),
)

print(
    "NORMAL AVERAGE SCORE:",
    round(
        normal_average_score,
        4,
    ),
)

print(
    "ANOMALOUS SCORE:",
    anomalous_result.anomaly_score,
)

print(
    "ANOMALOUS FLAG:",
    anomalous_result.is_anomaly,
)

print(
    "FEATURE VECTOR LENGTH:",
    len(
        anomalous_result.feature_vector
    ),
)

print(
    "FEATURE NAMES:",
    ml_pipeline.feature_names(),
)


if (
    len(normal_results) == 30
    and len(anomalous_result.feature_vector) == 11
    and 0.0 <= anomalous_result.anomaly_score <= 1.0
    and anomalous_result.anomaly_score
    > normal_average_score
):
    print("ML PIPELINE TEST: PASSED")
else:
    print("ML PIPELINE TEST: FAILED")