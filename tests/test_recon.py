from backend.detectors.recon import ReconnaissanceDetector
from backend.features.scan_tracker import ScanGroup


detector = ReconnaissanceDetector()


recon_group = ScanGroup(
    source_ip="10.0.0.60",
    timestamps=[
        1000.0 + i * 0.1
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


port_scan_group = ScanGroup(
    source_ip="10.0.0.50",
    timestamps=[
        2000.0 + i * 0.1
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


normal_group = ScanGroup(
    source_ip="10.0.0.70",
    timestamps=[
        3000.0 + i
        for i in range(5)
    ],
    destination_ips=[
        "10.0.0.20",
        "10.0.0.21",
        "10.0.0.22",
        "10.0.0.23",
        "10.0.0.24",
    ],
    destination_ports=[
        443,
        443,
        443,
        443,
        443,
    ],
    total_packets=5,
    unique_destination_ips=5,
    unique_destination_ports=1,
    host_port_pairs=5,
)


recon_result = detector.detect(recon_group)
port_scan_result = detector.detect(port_scan_group)
normal_result = detector.detect(normal_group)


if recon_result is not None:
    print("RECONNAISSANCE:")
    print(
        recon_result.model_dump_json(
            indent=2
        )
    )
else:
    print("RECONNAISSANCE: NOT DETECTED")


print("\nPORT SCAN:")
print(port_scan_result)


print("\nNORMAL:")
print(normal_result)