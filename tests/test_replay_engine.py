from backend.features.window import WindowFeatures
from backend.ingest.replay_engine import (
    TrafficReplayEngine,
)
from backend.ingest.stream import PacketStream


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


processor_engine = TrafficReplayEngine()

processor_engine.processor.fit_baseline(
    [
        make_normal_window(index)
        for index in range(30)
    ]
)


packets = list(
    PacketStream(
        "datasets/test_traffic.pcap"
    ).packets()
)


results, metrics = (
    processor_engine.replay(
        packets,
        mode="maximum",
    )
)


print(
    "PACKETS PROCESSED:",
    metrics.packets_processed,
)

print(
    "REPLAY DURATION:",
    round(
        metrics.replay_duration,
        6,
    ),
    "seconds",
)

print(
    "PROCESSING DURATION:",
    round(
        metrics.processing_duration,
        6,
    ),
    "seconds",
)

print(
    "AVERAGE LATENCY:",
    metrics.average_latency_ms,
    "ms",
)

print(
    "MAXIMUM LATENCY:",
    metrics.maximum_latency_ms,
    "ms",
)

print(
    "PROCESSING THROUGHPUT:",
    metrics.packets_per_second,
    "packets/sec",
)

print(
    "FINAL ML SCORE:",
    results[-1].ml_anomaly_score,
)

print(
    "FINAL ACTIVE ALERTS:",
    len(
        results[-1].active_alerts
    ),
)

print(
    "FINAL INTELLIGENCE:",
    len(
        results[-1].intelligence
    ),
)


assert (
    metrics.packets_processed
    == len(packets)
)

assert (
    metrics.processing_duration
    >= 0.0
)

assert (
    metrics.average_latency_ms
    >= 0.0
)

assert (
    metrics.maximum_latency_ms
    >= 0.0
)

assert (
    metrics.packets_per_second
    > 0.0
)

assert len(results) == len(
    packets
)


print(
    "REPLAY ENGINE TEST: PASSED"
)
