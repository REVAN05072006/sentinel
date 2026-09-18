from backend.detectors.dns_tunnel import DNSTunnellingDetector
from backend.features.dns_tracker import DNSQueryGroup


detector = DNSTunnellingDetector()


normal_queries = [
    "www.google.com",
    "api.github.com",
    "mail.microsoft.com",
    "www.wikipedia.org",
    "login.microsoft.com",
    "cdn.example.com",
    "images.example.com",
    "accounts.google.com",
    "docs.google.com",
    "update.microsoft.com",
]


tunnel_queries = [
    "xq7mz91k2p8v4n6b3r5t8y1.example.com",
    "a8k3m9q2z7p4x6v1.example.com",
    "q9w2e7r4t1y8u5i3.example.com",
    "m4n8b2v7c1x9z5k3.example.com",
    "p7q3w9e2r8t4y6u1.example.com",
    "z5x8c2v9b4n7m1k6.example.com",
    "k2j8h4g9f1d7s3a6.example.com",
    "r6t2y9u4i8o1p5a7.example.com",
    "b3n7m2v8c5x1z9k4.example.com",
    "w8e3r7t2y9u5i1o6.example.com",
    "f4g9h2j7k1l8z3x5.example.com",
    "n6m3b8v2c9x4z1k7.example.com",
]


short_queries = [
    "a.example.com",
    "b.example.com",
    "c.example.com",
]


normal_group = DNSQueryGroup(
    source_ip="10.0.0.10",
    destination_ip="8.8.8.8",
    timestamps=[
        1000.0 + i
        for i in range(len(normal_queries))
    ],
    queries=normal_queries,
    total_queries=len(normal_queries),
    unique_queries=len(set(normal_queries)),
    total_query_bytes=900,
)


tunnel_group = DNSQueryGroup(
    source_ip="10.0.0.50",
    destination_ip="8.8.8.8",
    timestamps=[
        2000.0 + i * 0.5
        for i in range(len(tunnel_queries))
    ],
    queries=tunnel_queries,
    total_queries=len(tunnel_queries),
    unique_queries=len(set(tunnel_queries)),
    total_query_bytes=1800,
)


short_group = DNSQueryGroup(
    source_ip="10.0.0.20",
    destination_ip="8.8.8.8",
    timestamps=[
        3000.0 + i
        for i in range(len(short_queries))
    ],
    queries=short_queries,
    total_queries=len(short_queries),
    unique_queries=len(set(short_queries)),
    total_query_bytes=200,
)


normal_result = detector.detect(normal_group)
tunnel_result = detector.detect(tunnel_group)
short_result = detector.detect(short_group)


print("NORMAL:", normal_result)

if tunnel_result is not None:
    print("\nTUNNELLING:")
    print(tunnel_result.model_dump_json(indent=2))
else:
    print("\nTUNNELLING: NOT DETECTED")

print("\nSHORT:", short_result)