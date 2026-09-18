from backend.detectors.exfiltration import DataExfiltrationDetector
from backend.features.exfiltration import ExfiltrationFeatureExtractor


normal = ExfiltrationFeatureExtractor.extract(
    source_ip="10.0.0.10",
    destination_ip="10.0.0.20",
    protocol="TCP",
    outbound_bytes=5000,
    inbound_bytes=4500,
    outbound_packets=50,
    inbound_packets=45,
)

suspicious = ExfiltrationFeatureExtractor.extract(
    source_ip="10.0.0.50",
    destination_ip="203.0.113.10",
    protocol="TCP",
    outbound_bytes=950000,
    inbound_bytes=12000,
    outbound_packets=900,
    inbound_packets=30,
)

detector = DataExfiltrationDetector()

normal_alert = detector.detect(normal)
suspicious_alert = detector.detect(suspicious)

print("NORMAL RESULT:")
print(normal_alert)

print("\nSUSPICIOUS RESULT:")
print(suspicious_alert)

if suspicious_alert is not None:
    print("\nSUSPICIOUS EVIDENCE:")
    for key, value in suspicious_alert.evidence.items():
        print(f"{key}: {value}")