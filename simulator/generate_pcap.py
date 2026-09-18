import random

from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap


def build_packets():
    packets = []

    base_time = 1000.0

    # ---------------------------------------------------------
    # 1. Normal HTTPS traffic
    # ---------------------------------------------------------

    for i in range(10):
        packet = (
            IP(
                src="10.0.0.10",
                dst="10.0.0.20"
            )
            / TCP(
                sport=45000,
                dport=443,
                flags="PA"
            )
        )

        packet.time = base_time + (i * 0.5)
        packets.append(packet)

    # ---------------------------------------------------------
    # 2. Normal DNS traffic
    # ---------------------------------------------------------

    domains = [
        "example.com",
        "openai.com",
        "github.com",
        "python.org",
    ]

    for i, domain in enumerate(domains):
        packet = (
            IP(
                src="10.0.0.12",
                dst="8.8.8.8"
            )
            / UDP(
                sport=53000 + i,
                dport=53
            )
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain)
            )
        )

        packet.time = base_time + (i * 1.0)
        packets.append(packet)

    # ---------------------------------------------------------
    # 3. SYN flood simulation
    # ---------------------------------------------------------

    target_ip = "10.0.0.20"

    source_ips = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
        "192.168.1.14",
        "192.168.1.15",
        "192.168.1.16",
        "192.168.1.17",
    ]

    for i in range(200):
        src_ip = random.choice(source_ips)

        packet = (
            IP(
                src=src_ip,
                dst=target_ip
            )
            / TCP(
                sport=random.randint(30000, 60000),
                dport=443,
                flags="S"
            )
        )

        packet.time = base_time + 5.0 + (i * 0.01)
        packets.append(packet)

    return packets


def main():
    output_path = "datasets\\test_traffic.pcap"

    packets = build_packets()

    # Keep packets chronologically ordered.
    packets.sort(key=lambda packet: float(packet.time))

    wrpcap(output_path, packets)

    print(f"Generated {len(packets)} packets")
    print(f"PCAP: {output_path}")


if __name__ == "__main__":
    main()