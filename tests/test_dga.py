from backend.detectors.dga import DGADetector
from backend.features.dns_features import DNSFeatureExtractor


detector = DGADetector()

queries = [
    "www.google.com",
    "api.github.com",
    "mail.microsoft.com",
    "xq7mz91k2p8v4n6b.example.com",
    "ajd83kq91mz7x2p9v4.example.net",
]


for query in queries:
    features = DNSFeatureExtractor.extract(query)
    result = detector.detect(features)

    print(f"\nQUERY: {query}")

    if result is None:
        print("RESULT: NORMAL")
    else:
        print(
            f"RESULT: {result.threat_class}"
            f" | CONFIDENCE: {result.confidence}"
            f" | SEVERITY: {result.severity}"
        )

        print("EVIDENCE:")
        for key, value in result.evidence.items():
            print(f"  {key}: {value}")