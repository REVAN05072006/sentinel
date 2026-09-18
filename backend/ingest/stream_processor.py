from dataclasses import dataclass

from backend.alerts.deduplicator import ActiveAlert
from backend.correlation.evidence_engine import CorrelatedEvidence
from backend.features.window import WindowFeatures
from backend.pipeline import SentinelPipeline
from backend.scoring.pipeline_intelligence import IntelligenceResult
from backend.alerts.schema import ThreatAlert


@dataclass(frozen=True)
class StreamingResult:
    packet_timestamp: float
    window_features: WindowFeatures

    new_alerts: list[ThreatAlert]
    active_alerts: list[ActiveAlert]

    correlated_evidence: list[CorrelatedEvidence]
    intelligence: list[IntelligenceResult]

    ml_anomaly_score: float
    ml_is_anomaly: bool


class SentinelStreamProcessor:
    """
    Stateful streaming adapter for SentinelPipeline.

    One packet enters the processor at a time.

    Processing:

        packet
          ↓
        window update
          ↓
        detector evaluation
          ↓
        alert deduplication
          ↓
        incident management
          ↓
        correlation
          ↓
        ML anomaly scoring
          ↓
        unified intelligence

    The processor is strictly passive and read-only.
    It does not transmit, probe, block, modify, or decrypt traffic.
    """

    def __init__(
        self,
        pipeline: SentinelPipeline | None = None,
    ):
        self.pipeline = (
            pipeline
            if pipeline is not None
            else SentinelPipeline()
        )

    def fit_baseline(
        self,
        windows: list[WindowFeatures],
    ) -> None:
        """
        Fit the ML baseline using trusted normal windows.
        """

        self.pipeline.fit_baseline(
            windows
        )

    def process_packet(
        self,
        packet,
    ) -> StreamingResult:
        """
        Process exactly one observed packet and return
        the current intelligence state.
        """

        new_alerts = []

        window_alerts = (
            self.pipeline.process_packet(
                packet
            )
        )

        new_alerts.extend(
            window_alerts
        )

        tracker_alerts = []

        tracker_alerts.extend(
            self.pipeline._detect_dns()
        )

        tracker_alerts.extend(
            self.pipeline._detect_scans()
        )

        tracker_alerts.extend(
            self.pipeline._detect_encrypted_sessions()
        )

        tracker_alerts.extend(
            self.pipeline._detect_exfiltration()
        )

        tracker_alerts.extend(
            self.pipeline._detect_c2()
        )

        for alert in tracker_alerts:
            self.pipeline.alert_deduplicator.process(
                alert
            )

            self.pipeline.incident_manager.process(
                alert
            )

        new_alerts.extend(
            tracker_alerts
        )

        active_alerts = (
            self.pipeline
            .get_active_alerts()
        )

        correlated_evidence = (
            self.pipeline
            .evidence_correlation_engine
            .correlate(
                active_alerts
            )
        )

        ml_anomaly_score = 0.0
        ml_is_anomaly = False

        window_features = (
            self.pipeline
            ._latest_window_features
        )

        if (
            window_features is not None
            and self.pipeline.is_ml_ready()
        ):
            ml_result = (
                self.pipeline.score_window(
                    window_features
                )
            )

            ml_anomaly_score = (
                ml_result.anomaly_score
            )

            ml_is_anomaly = (
                ml_result.is_anomaly
            )

        ml_scores = {}

        for alert in active_alerts:
            source_ip = (
                alert.alert.source_ip
            )

            if source_ip is not None:
                ml_scores[source_ip] = (
                    ml_anomaly_score
                )

        intelligence = (
            self.pipeline
            .intelligence_engine
            .evaluate(
                alerts=active_alerts,
                correlated_evidence=(
                    correlated_evidence
                ),
                ml_scores=ml_scores,
            )
        )

        return StreamingResult(
            packet_timestamp=float(
                packet.timestamp
            ),
            window_features=window_features,
            new_alerts=new_alerts,
            active_alerts=active_alerts,
            correlated_evidence=(
                correlated_evidence
            ),
            intelligence=(
                intelligence.results
            ),
            ml_anomaly_score=(
                ml_anomaly_score
            ),
            ml_is_anomaly=(
                ml_is_anomaly
            ),
        )

    def process_packets(
        self,
        packets,
    ):
        """
        Process an iterable packet stream one packet at a time.

        Results are yielded immediately after each packet.
        """

        for packet in packets:
            yield self.process_packet(
                packet
            )

    def reset(self) -> None:
        """
        Reset the underlying Sentinel pipeline.
        """

        self.pipeline.reset()