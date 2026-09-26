from dataclasses import dataclass, field
from datetime import datetime

from backend.alerts.schema import ThreatAlert


@dataclass
class Incident:
    incident_id: str
    threat_class: str

    first_seen: datetime
    last_seen: datetime

    confidence: float
    severity: str

    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None

    detection_count: int = 1
    observation_count: int = 1
    evidence: dict = field(default_factory=dict)


class IncidentManager:
    """
    Groups repeated observations of the same threat into one incident.

    detection_count represents distinct incident episodes.

    observation_count represents repeated detector observations
    received while the current incident remains active.
    """

    def __init__(self, correlation_window: float = 5.0):
        self.correlation_window = correlation_window
        self._incidents: dict[str, Incident] = {}
        self._counter = 0

    def process(self, alert: ThreatAlert) -> Incident:
        """
        Process one threat alert.

        If the same threat is observed again within the correlation
        window, update the existing incident without incrementing
        detection_count.

        A new detection episode is created only after the previous
        incident has expired.
        """

        key = self._incident_key(alert)

        existing = self._incidents.get(key)

        if existing is not None:
            elapsed = (
                alert.timestamp - existing.last_seen
            ).total_seconds()

            if elapsed <= self.correlation_window:
                existing.last_seen = alert.timestamp

                existing.observation_count += 1

                existing.confidence = max(
                    existing.confidence,
                    alert.confidence,
                )

                existing.severity = self._max_severity(
                    existing.severity,
                    alert.severity,
                )

                existing.destination_ip = (
                    alert.destination_ip
                    or existing.destination_ip
                )

                existing.destination_port = (
                    alert.destination_port
                    if alert.destination_port is not None
                    else existing.destination_port
                )

                existing.protocol = (
                    alert.protocol
                    or existing.protocol
                )

                existing.evidence.update(
                    alert.evidence
                )

                return existing

        self._counter += 1

        incident = Incident(
            incident_id=f"INC-{self._counter:05d}",
            threat_class=alert.threat_class,
            first_seen=alert.timestamp,
            last_seen=alert.timestamp,
            confidence=alert.confidence,
            severity=alert.severity,
            destination_ip=alert.destination_ip,
            destination_port=alert.destination_port,
            protocol=alert.protocol,
            detection_count=1,
            observation_count=1,
            evidence=dict(alert.evidence),
        )

        self._incidents[key] = incident

        return incident

    def get_incidents(self) -> list[Incident]:
        return list(self._incidents.values())

    @staticmethod
    def _incident_key(alert: ThreatAlert) -> str:
        return "|".join(
            [
                alert.threat_class,
                alert.destination_ip or "",
                str(alert.destination_port or ""),
                alert.protocol or "",
            ]
        )

    @staticmethod
    def _max_severity(
        first: str,
        second: str,
    ) -> str:
        ranking = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        return (
            first
            if ranking.get(first, 0)
            >= ranking.get(second, 0)
            else second
        )