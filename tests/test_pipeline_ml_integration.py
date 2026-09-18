from backend.ingest.stream import PacketStream
from backend.pipeline import SentinelPipeline
from backend.features.window import WindowFeatures


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


pipeline = SentinelPipeline()

normal_windows = [
    make_normal_window(index)
    for index in range(30)
]

pipeline.fit_baseline(
    normal_windows
)

status = pipeline.baseline_status()

print(
    "BASELINE FITTED:",
    status.fitted
)

print(
    "BASELINE SAMPLES:",
    status.sample_count
)

assert status.fitted is True
assert status.sample_count == 30


packets = list(
    PacketStream(
        "datasets/test_traffic.pcap"
    ).packets()
)

print(
    "PCAP PACKETS:",
    len(packets)
)

assert len(packets) > 0


result = pipeline.process_packets(
    packets
)

print(
    "ACTIVE ALERTS:",
    len(result.alerts)
)

print(
    "INCIDENTS:",
    len(result.incidents)
)

print(
    "CORRELATED CHAINS:",
    len(result.correlated_evidence)
)

print(
    "INTELLIGENCE RESULTS:",
    len(result.intelligence)
)

print(
    "ML SCORE:",
    result.ml_anomaly_score
)

print(
    "ML ANOMALY:",
    result.ml_is_anomaly
)


if result.intelligence:
    for intelligence in result.intelligence:
        print(
            intelligence.threat_class,
            "=>",
            intelligence.threat_score.unified_score,
            intelligence.threat_score.risk_level,
        )


assert result.ml_anomaly_score >= 0.0
assert result.ml_anomaly_score <= 1.0

assert result.ml_is_anomaly in (
    True,
    False,
)

assert len(result.intelligence) == len(
    result.alerts
)

print(
    "PIPELINE ML INTEGRATION TEST: PASSED"
)