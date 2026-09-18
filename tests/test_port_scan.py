from backend.detectors.port_scan import PortScanDetector
from backend.features.scan_tracker import ScanGroup


detector = PortScanDetector()


port_scan_group = ScanGroup(
    source_ip="10.0.0.50",
    timestamps=[
        1000.0 + i * 0.1
        for i in range(10)
    ],
    destination_ips=[
        "10.0.0.20"
        for _ in range(10)
    ],
    destination_ports=[
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        139,
        443,
        445,
    ],
    total_packets=10,
    unique_destination_ips=1,
    unique_destination_ports=10,
    host_port_pairs=10,
)


host_recon_group = ScanGroup(
    source_ip="10.0.0.60",
    timestamps=[
        2000.0 + i * 0.1
        for i in range(10)
    ],
    destination_ips=[
        f"10.0.1.{i + 1}"
        for i in range(10)
    ],
    destination_ports=[
        443
        for _ in range(10)
    ],
    total_packets=10,
    unique_destination_ips=10,
    unique_destination_ports=1,
    host_port_pairs=10,
)


port_scan_result = detector.detect(
    port_scan_group
)

host_recon_result = detector.detect(
    host_recon_group
)


if port_scan_result is not None:
    print("PORT SCAN:")
    print(
        port_scan_result.model_dump_json(
            indent=2
        )
    )
else:
    print("PORT SCAN: NOT DETECTED")


print("\nHOST RECONNAISSANCE:")
print(host_recon_result)