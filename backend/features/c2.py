from datetime import datetime, timezone

from backend.alerts.schema import ThreatAlert
from backend.features.timing import TimingFeatureExtractor


class C2BeaconDetector:
    """
    Detects periodic command-and-control beaconing from
    passively observed connection timestamps.

    Detection is based on temporal regularity and repeated
    communication with a destination. No payload inspection
    or active network interaction is performed.
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