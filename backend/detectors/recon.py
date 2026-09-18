from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.scan_tracker import ScanGroup


class ReconnaissanceDetector:
    """
    Detects passive behavioral indicators consistent with
    network reconnaissance or host sweeping.

    Detection focuses on one source contacting many different
    destination hosts within a short observation interval.

    No probes or active network interaction are performed.
    """

    def __init__(
        self,
        minimum_packets: int = 8,
        host_count_threshold: int = 8,
        host_concentration_threshold: float = 0.60,
        scan_rate_threshold: float = 2.0,
    ):
        self.minimum_packets = minimum_packets
        self.host_count_threshold = host_count_threshold
        self.host_concentration_threshold = (
            host_concentration_threshold
        )
        self.scan_rate_threshold = scan_rate_threshold

    def detect(
        self,
        group: ScanGroup,
    ) -> ThreatAlert | None:
        if group.total_packets < self.minimum_packets:
            return None

        if (
            group.unique_destination_ips
            < self.host_count_threshold
        ):
            return None

        if not group.timestamps:
            return None

        duration = max(
            max(group.timestamps)
            - min(group.timestamps),
            0.000001,
        )

        scan_rate = group.total_packets / duration

        if scan_rate < self.scan_rate_threshold:
            return None

        host_concentration = (
            group.unique_destination_ips
            / max(group.total_packets, 1)
        )

        if (
            host_concentration
            < self.host_concentration_threshold
        ):
            return None

        confidence = min(
            1.0,
            0.35
            + 0.25 * min(
                group.unique_destination_ips
                / self.host_count_threshold,
                1.0,
            )
            + 0.20 * min(
                scan_rate / self.scan_rate_threshold,
                1.0,
            )
            + 0.20 * min(
                host_concentration
                / self.host_concentration_threshold,
                1.0,
            ),
        )

        if confidence >= 0.90:
            severity = "CRITICAL"
        elif confidence >= 0.75:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        evidence = {
            "source_ip": group.source_ip,
            "total_packets": group.total_packets,
            "unique_destination_ips": (
                group.unique_destination_ips
            ),
            "unique_destination_ports": (
                group.unique_destination_ports
            ),
            "host_port_pairs": group.host_port_pairs,
            "scan_rate": round(scan_rate, 3),
            "host_concentration": round(
                host_concentration,
                3,
            ),
        }

        return ThreatAlert(
            timestamp=datetime.fromtimestamp(
                max(group.timestamps),
                tz=timezone.utc,
            ),
            threat_class="RECONNAISSANCE",
            confidence=round(confidence, 3),
            severity=severity,
            source_ip=group.source_ip,
            destination_ip=(
                group.destination_ips[0]
                if group.destination_ips
                else None
            ),
            protocol="TCP",
            evidence=evidence,
        )