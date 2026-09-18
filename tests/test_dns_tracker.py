from backend.features.dns_tracker import DNSTracker
from backend.ingest.stream import PacketRecord


tracker = DNSTracker()

packets = [
    PacketRecord(
        timestamp=1000.0,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        protocol="UDP",
        src_port=53000,
        dst_port=53,
        packet_size=80,
        tcp_flags=None,
        dns_query="www.google.com",
    ),
    PacketRecord(
        timestamp=1001.0,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        protocol="UDP",
        src_port=53001,
        dst_port=53,
        packet_size=90,
        tcp_flags=None,
        dns_query="api.github.com",
    ),
    PacketRecord(
        timestamp=1002.0,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        protocol="UDP",
        src_port=53002,
        dst_port=53,
        packet_size=120,
        tcp_flags=None,
        dns_query="xq7mz91k2p8v4n6b.example.com",
    ),
    PacketRecord(
        timestamp=1003.0,
        src_ip="10.0.0.10",
        dst_ip="8.8.8.8",
        protocol="UDP",
        src_port=53003,
        dst_port=53,
        packet_size=125,
        tcp_flags=None,
        dns_query="xq7mz91k2p8v4n6b.example.com",
    ),
]


tracker.process_stream(packets)

print("GROUP COUNT:", tracker.group_count())

for group in tracker.get_groups():
    print("\nSOURCE:", group.source_ip)
    print("DNS SERVER:", group.destination_ip)
    print("TOTAL QUERIES:", group.total_queries)
    print("UNIQUE QUERIES:", group.unique_queries)
    print("TIMESTAMPS:", group.timestamps)
    print("QUERIES:", group.queries)
    print("TOTAL QUERY BYTES:", group.total_query_bytes)