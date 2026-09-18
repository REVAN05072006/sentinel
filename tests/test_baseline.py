from backend.features.window import WindowFeatures
from backend.models.baseline import TrafficBaselineManager


def create_normal_window(index: int) -> WindowFeatures:
    return WindowFeatures(
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


normal_windows = [
    create_normal_window(index)
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


manager = TrafficBaselineManager(
    minimum_samples=20,
    contamination=0.05,
    random_state=42,
)


print(
    "INITIAL FITTED:",
    manager.is_fitted(),
)

print(
    "INITIAL SAMPLES:",
    manager.sample_count(),
)


manager.add_windows(
    normal_windows
)


print(
    "BASELINE SAMPLES:",
    manager.sample_count(),
)


status_before_fit = manager.status()

print(
    "STATUS BEFORE FIT:",
    status_before_fit,
)


manager.fit()


status_after_fit = manager.status()

print(
    "STATUS AFTER FIT:",
    status_after_fit,
)


normal_results = manager.predict_windows(
    normal_windows
)

anomalous_result = manager.predict(
    anomalous_window
)


normal_average_score = sum(
    result.anomaly_score
    for result in normal_results
) / len(normal_results)


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


if (
    status_before_fit.fitted is False
    and status_before_fit.sample_count == 30
    and status_after_fit.fitted is True
    and status_after_fit.sample_count == 30
    and anomalous_result.anomaly_score
    > normal_average_score
):
    print("BASELINE MANAGER TEST: PASSED")
else:
    print("BASELINE MANAGER TEST: FAILED")