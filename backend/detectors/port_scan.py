from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.scan_tracker import ScanGroup


class PortScanDetector:
    """
    Detects passive behavioral indicators consistent with
    destination-port scanning.

    Detection focuses on one source contacting many different
    destination ports, particularly within a short observation
    interval.

    No probes or active network interaction are performed.
    """

    def __init__(
        self,
        minimum_packets: int = 8,
        port_count_threshold: int = 8,
        concentration_threshold: float = 0.60,
        scan_rate_threshold: float = 2.0,
    ):
        self.minimum_packets = minimum_packets
        self.port_count_threshold = port_count_threshold
        self.concentration_threshold = concentration_threshold
        self.scan_rate_threshold = scan_rate_threshold

    def detect(
        self,
        group: ScanGroup,
    ) -> ThreatAlert | None:
        if group.total_packets < self.minimum_packets:
            return None

        if (
            group.unique_destination_ports
            < self.port_count_threshold
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

        port_concentration = (
            group.unique_destination_ports
            / max(group.total_packets, 1)
        )

        if (
            port_concentration
            < self.concentration_threshold
        ):
            return None

        confidence = min(
            1.0,
            0.35
            + 0.25 * min(
                group.unique_destination_ports
                / self.port_count_threshold,
                1.0,
            )
            + 0.20 * min(
                scan_rate / self.scan_rate_threshold,
                1.0,
            )
            + 0.20 * min(
                port_concentration
                / self.concentration_threshold,
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
            "unique_destination_ports": (
                group.unique_destination_ports
            ),
            "unique_destination_ips": (
                group.unique_destination_ips
            ),
            "host_port_pairs": group.host_port_pairs,
            "scan_rate": round(scan_rate, 3),
            "port_concentration": round(
                port_concentration,
                3,
            ),
        }

        return ThreatAlert(
            timestamp=datetime.fromtimestamp(
                max(group.timestamps),
                tz=timezone.utc,
            ),
            threat_class="PORT_SCANNING",
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