from backend.features.tls_tracker import TLSTracker
from backend.ingest.stream import PacketRecord


tracker = TLSTracker()

packets = [
    PacketRecord(
        timestamp=1000.0,
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        protocol="TCP",
        src_port=51000,
        dst_port=443,
        packet_size=1200,
        tcp_flags="A",
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1000.2,
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        protocol="TCP",
        src_port=51000,
        dst_port=443,
        packet_size=1180,
        tcp_flags="A",
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1000.4,
        src_ip="10.0.0.10",
        dst_ip="203.0.113.10",
        protocol="TCP",
        src_port=51001,
        dst_port=443,
        packet_size=1210,
        tcp_flags="A",
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1001.0,
        src_ip="10.0.0.20",
        dst_ip="203.0.113.20",
        protocol="UDP",
        src_port=52000,
        dst_port=443,
        packet_size=1400,
        tcp_flags=None,
        dns_query=None,
    ),
    PacketRecord(
        timestamp=1001.2,
        src_ip="10.0.0.20",
        dst_ip="203.0.113.20",
        protocol="UDP",
        src_port=52000,
        dst_port=443,
        packet_size=1300,
        tcp_flags=None,
        dns_query=None,
    ),
]

for packet in packets:
    tracker.process_packet(packet)

print("SESSION GROUPS:", tracker.group_count())

for group in tracker.get_groups():
    print("\nSESSION:")
    print("ID:", group.session_id)
    print("SOURCE:", group.source_ip)
    print("DESTINATION:", group.destination_ip)
    print("PORT:", group.destination_port)
    print("PROTOCOL:", group.protocol)
    print("TIMESTAMPS:", group.timestamps)
    print("PACKET SIZES:", group.packet_sizes)
    