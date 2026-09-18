from backend.features.window import WindowFeatures
from backend.ingest.stream import PacketStream
from backend.ingest.stream_processor import (
    SentinelStreamProcessor,
)


def make_normal_window(index: int) -> WindowFeatures:
    return WindowFeatures(
        start_time=float(index),
        end_time=float(index + 1),
        packet_count=20 + (index % 3),
        byte_count=2000 + (index * 20),
        packets_per_second=20.0 + (index % 3),
        bytes_per_second=2000.0 + (index * 20),
        syn_count=2,
        syns_per_second=2.0,
        syn_ratio=0.10,
        unique_src_ips=2,
        unique_dst_ips=2,
        unique_dst_ports=2,
        dominant_dst_ip="10.0.0.20",
        dominant_dst_port=443,
        source_ip_entropy=1.0,
    )


processor = SentinelStreamProcessor()

normal_windows = [
    make_normal_window(index)
    for index in range(30)
]

processor.fit_baseline(
    normal_windows
)

assert processor.pipeline.is_ml_ready()

packets = list(
    PacketStream(
        "datasets/test_traffic.pcap"
    ).packets()
)

assert packets

results = []

for result in processor.process_packets(
    packets
):
    results.append(result)

print(
    "PACKETS PROCESSED:",
    len(results)
)

print(
    "FIRST TIMESTAMP:",
    results[0].packet_timestamp
)

print(
    "LAST TIMESTAMP:",
    results[-1].packet_timestamp
)

print(
    "FINAL ML SCORE:",
    results[-1].ml_anomaly_score
)

print(
    "FINAL ML ANOMALY:",
    results[-1].ml_is_anomaly
)

print(
    "FINAL ACTIVE ALERTS:",
    len(
        results[-1].active_alerts
    )
)

print(
    "FINAL CORRELATED CHAINS:",
    len(
        results[-1].correlated_evidence
    )
)

print(
    "FINAL INTELLIGENCE RESULTS:",
    len(
        results[-1].intelligence
    )
)


assert len(results) == len(
    packets
)

assert (
    results[0].packet_timestamp
    <=
    results[-1].packet_timestamp
)

assert 0.0 <= (
    results[-1].ml_anomaly_score
) <= 1.0

assert len(
    results[-1].intelligence
) == len(
    results[-1].active_alerts
)


print(
    "STREAMING PROCESSOR TEST: PASSED"
)