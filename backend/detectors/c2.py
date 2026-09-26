import ipaddress
from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.timing import TimingFeatureExtractor


def _is_multicast_or_broadcast(ip: str) -> bool:
    """
    Return True for IPv4 addresses that are multicast or broadcast.

    Covered ranges (RFC 1112, RFC 5771):
        224.0.0.0/4   — all IPv4 multicast (includes 239.0.0.0/8)
        255.255.255.255 — limited broadcast

    These addresses are legitimate destinations for mDNS, SSDP, IGMP,
    and other one-to-many protocols.  Periodic traffic to them is normal
    OS/network behaviour and must not trigger C2 beaconing alerts.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_multicast
            or addr == ipaddress.ip_address("255.255.255.255")
        )
    except ValueError:
        return False


class C2BeaconDetector:
    """
    Detects periodic command-and-control beaconing from
    passively observed connection timestamps.

    Detection is based on temporal regularity and repeated
    communication with a destination. No payload inspection
    or active network interaction is performed.

    Multicast and broadcast destinations (224.0.0.0/4, 255.255.255.255)
    are excluded because periodic traffic to those addresses is normal
    OS behaviour (mDNS, SSDP, IGMP) and does not constitute C2.
    """

    def __init__(
        self,
        minimum_observations: int = 5,
        periodicity_threshold: float = 0.75,
        mean_interval_min: float = 2.0,
        mean_interval_max: float = 3600.0,
    ):
        self.minimum_observations = minimum_observations
        self.periodicity_threshold = periodicity_threshold
        self.mean_interval_min = mean_interval_min
        self.mean_interval_max = mean_interval_max

    def detect(
        self,
        timestamps: list[float],
        source_ip: str,
        destination_ip: str,
        source_port: int | None,
        destination_port: int,
        protocol: str,
    ) -> ThreatAlert | None:

        # Multicast and broadcast addresses (224.0.0.0/4, 255.255.255.255)
        # generate inherently periodic traffic for normal protocols such as
        # mDNS, SSDP, and IGMP.  They are never legitimate C2 server
        # destinations.  Skip without further scoring.
        if _is_multicast_or_broadcast(destination_ip):
            return None

        timing = TimingFeatureExtractor.extract(timestamps)

        if timing.observation_count < self.minimum_observations:
            return None

        if not (
            self.mean_interval_min
            <= timing.mean_interval
            <= self.mean_interval_max
        ):
            return None

        if timing.periodicity_score < self.periodicity_threshold:
            return None

        confidence = min(
            1.0,
            0.5 * timing.periodicity_score
            + 0.3 * min(
                timing.observation_count / 10.0,
                1.0,
            )
            + 0.2,
        )

        if confidence >= 0.90:
            severity = "CRITICAL"
        elif confidence >= 0.75:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        evidence = {
            "observation_count": timing.observation_count,
            "mean_interval": round(timing.mean_interval, 3),
            "interval_stddev": round(timing.interval_stddev, 3),
            "periodicity_score": round(timing.periodicity_score, 3),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
        }

        return ThreatAlert(
            timestamp=datetime.fromtimestamp(
                max(timestamps),
                tz=timezone.utc,
            ),
            threat_class="C2_BEACONING",
            confidence=round(confidence, 3),
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            evidence=evidence,
        )