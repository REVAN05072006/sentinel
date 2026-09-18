from backend.features.scan_tracker import ScanTracker
from backend.ingest.stream import PacketRecord


tracker = ScanTracker()

packets = []

# Port-scan pattern:
# One source -> one destination -> many ports
for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 443, 445]):
    packets.append(
        PacketRecord(
            timestamp=1000.0 + i * 0.1,
            src_ip="10.0.0.50",
            dst_ip="10.0.0.20",
            protocol="TCP",
            src_port=40000 + i,
            dst_port=port,
            packet_size=60,
            tcp_flags="S",
            dns_query=None,
        )
    )

# Reconnaissance / host-sweep pattern:
# One source -> many destinations
for i in range(10):
    packets.append(
        PacketRecord(
            timestamp=1002.0 + i * 0.1,
            src_ip="10.0.0.60",
            dst_ip=f"10.0.1.{i + 1}",
            protocol="TCP",
            src_port=41000 + i,
            dst_port=443,
            packet_size=60,
            tcp_flags="S",
            dns_query=None,
        )
    )

tracker.process_stream(packets)

print("GROUP COUNT:", tracker.group_count())

for group in tracker.get_groups():
    print("\nSOURCE:", group.source_ip)
    print("TOTAL PACKETS:", group.total_packets)
    print(
        "UNIQUE DESTINATION IPS:",
        group.unique_destination_ips,
    )
    print(
        "UNIQUE DESTINATION PORTS:",
        group.unique_destination_ports,
    )
    print(
        "HOST-PORT PAIRS:",
        group.host_port_pairs,
    )
    print("TIMESTAMPS:", group.timestamps)