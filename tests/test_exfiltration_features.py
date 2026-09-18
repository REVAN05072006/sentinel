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

print("NORMAL TRAFFIC:")
print(normal)

print("\nSUSPICIOUS TRAFFIC:")
print(suspicious)