from dataclasses import dataclass, field
from datetime import datetime

from backend.alerts.schema import ThreatAlert


@dataclass
class ActiveAlert:
    """
    Represents one currently active threat alert.

    Repeated observations of the same threat update this object
    instead of creating duplicate analyst-facing alerts.

    detection_count represents distinct detection episodes.
    observation_count represents repeated detector evaluations
    supporting the current active episode.
    """

    alert: ThreatAlert
    detection_count: int = 1
    observation_count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def __post_init__(self):
        if self.first_seen is None:
            self.first_seen = self.alert.timestamp

        if self.last_seen is None:
            self.last_seen = self.alert.timestamp


class AlertDeduplicator:
    """
    Groups repeated detections of the same active threat.

    Alerts are considered the same when their threat class,
    destination, destination port, and protocol match.

    Repeated observations inside the active window do not create
    additional detection episodes.

    The component is purely analytical and does not interact
    with the network.
    """

    def __init__(self, active_window: float = 5.0):
        self.active_window = active_window
        self._active: dict[str, ActiveAlert] = {}

    def process(self, alert: ThreatAlert) -> ActiveAlert:
        """
        Process one detection and update or create an active alert.

        A repeated observation inside the active window updates
        the existing alert but does not increment detection_count.
        """

        key = self._alert_key(alert)
        existing = self._active.get(key)

        if existing is not None:
            elapsed = (
                alert.timestamp - existing.last_seen
            ).total_seconds()

            if elapsed <= self.active_window:
                existing.observation_count += 1
                existing.last_seen = alert.timestamp
                existing.alert = self._merge_alert(
                    existing.alert,
                    alert,
                )

                return existing

        active_alert = ActiveAlert(
            alert=alert,
            detection_count=1,
            observation_count=1,
        )

        self._active[key] = active_alert

        return active_alert

    def get_active_alerts(self) -> list[ActiveAlert]:
        """
        Return all currently active alerts.
        """

        return list(self._active.values())

    def active_count(self) -> int:
        """
        Return the number of active deduplicated alerts.
        """

        return len(self._active)

    def clear(self) -> None:
        """
        Clear all active alert state.
        """

        self._active.clear()

    @staticmethod
    def _alert_key(alert: ThreatAlert) -> str:
        return "|".join(
            [
                alert.threat_class,
                alert.destination_ip or "",
                str(alert.destination_port or ""),
                alert.protocol or "",
            ]
        )

    @staticmethod
    def _merge_alert(
        existing: ThreatAlert,
        current: ThreatAlert,
    ) -> ThreatAlert:
        evidence = dict(existing.evidence)
        evidence.update(current.evidence)

        return existing.model_copy(
            update={
                "timestamp": current.timestamp,
                "confidence": max(
                    existing.confidence,
                    current.confidence,
                ),
                "severity": AlertDeduplicator._max_severity(
                    existing.severity,
                    current.severity,
                ),
                "evidence": evidence,
            }
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
            if ranking.get(first, 0) >= ranking.get(second, 0)
            else second
        )