from backend.features.tls_features import TLSFeatureExtractor


normal_timestamps = [
    1000.0,
    1000.2,
    1000.4,
    1000.6,
    1000.8,
    1001.0,
]

normal_packet_sizes = [
    1200,
    1180,
    1210,
    1190,
    1205,
    1195,
]


suspicious_timestamps = [
    2000.0,
    2000.01,
    2000.02,
    2000.50,
    2000.51,
    2002.00,
]

suspicious_packet_sizes = [
    64,
    1500,
    72,
    1400,
    60,
    1450,
]


normal = TLSFeatureExtractor.extract(
    session_id="NORMAL-001",
    timestamps=normal_timestamps,
    packet_sizes=normal_packet_sizes,
    client_fingerprint="JA4-NORMAL",
    server_fingerprint="JA4-SERVER",
)


suspicious = TLSFeatureExtractor.extract(
    session_id="SUSPICIOUS-001",
    timestamps=suspicious_timestamps,
    packet_sizes=suspicious_packet_sizes,
    client_fingerprint="JA4-UNKNOWN",
    server_fingerprint="JA4-SERVER",
)


print("NORMAL SESSION:")
print(normal)


print("\nSUSPICIOUS SESSION:")
print(suspicious)