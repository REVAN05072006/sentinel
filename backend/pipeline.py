from dataclasses import dataclass, field

from backend.alerts.deduplicator import (
    ActiveAlert,
    AlertDeduplicator,
)
from backend.alerts.schema import ThreatAlert

from backend.correlation.evidence_engine import (
    CorrelatedEvidence,
    EvidenceCorrelationEngine,
)
from backend.correlation.incident import (
    Incident,
    IncidentManager,
)

from backend.detectors.c2 import C2BeaconDetector
from backend.detectors.ddos import DDoSDetector
from backend.detectors.dga import DGADetector
from backend.detectors.dns_tunnel import (
    DNSTunnellingDetector,
)
from backend.detectors.encrypted_malware import (
    EncryptedMalwareDetector,
)
from backend.detectors.exfiltration import (
    DataExfiltrationDetector,
)
from backend.detectors.port_scan import PortScanDetector
from backend.detectors.recon import (
    ReconnaissanceDetector,
)
from backend.detectors.spoofed_flood import (
    SpoofedSourceFloodDetector,
)
from backend.detectors.udp_reflection import (
    UDPReflectionDetector,
)

from backend.features.communication import (
    CommunicationTracker,
)
from backend.features.dns_features import (
    DNSFeatureExtractor,
)
from backend.features.dns_tracker import DNSTracker
from backend.features.exfiltration import (
    ExfiltrationFeatureExtractor,
)
from backend.features.exfiltration_tracker import (
    ExfiltrationTracker,
)
from backend.features.scan_tracker import ScanTracker
from backend.features.tls_features import (
    TLSFeatureExtractor,
)
from backend.features.tls_tracker import TLSTracker
from backend.features.window import (
    SlidingWindow,
    WindowFeatures,
)

from backend.ingest.stream import PacketRecord

from backend.models.baseline import (
    TrafficBaselineManager,
)

from backend.scoring.pipeline_intelligence import (
    IntelligenceResult,
    PipelineIntelligenceEngine,
)
from backend.scoring.sentinel_intelligence import (
    SentinelIntelligence,
)


@dataclass
class PipelineResult:
    alerts: list[ActiveAlert]
    incidents: list[Incident]
    correlated_evidence: list[CorrelatedEvidence]

    intelligence: list[IntelligenceResult] = field(
        default_factory=list
    )

    ml_anomaly_score: float = 0.0
    ml_is_anomaly: bool = False


class SentinelPipeline:
    """
    Central read-only Sentinel detection pipeline.

    Processing stages:

        passive packets
            ↓
        sliding-window features
            ↓
        threat detectors
            ↓
        alert deduplication
            ↓
        incident management
            ↓
        evidence correlation
            ↓
        ML anomaly detection
            ↓
        unified intelligence scoring

    The pipeline never transmits packets, probes hosts,
    modifies traffic, decrypts payloads, blocks traffic,
    or performs mitigation.

    ML baseline traffic must be explicitly supplied through
    fit_baseline() using trusted normal observations.
    """

    def __init__(
        self,
        window_size: float = 1.0,
        correlation_window: float = 5.0,
        alert_active_window: float = 5.0,
        evidence_correlation_window: float = 300.0,
        ml_minimum_samples: int = 20,
        ml_contamination: float = 0.05,
        ml_random_state: int = 42,
    ):
        self.window = SlidingWindow(
            window_size
        )

        self.communication_tracker = (
            CommunicationTracker()
        )

        self.dns_tracker = DNSTracker()

        self.scan_tracker = ScanTracker()

        self.tls_tracker = TLSTracker()

        self.exfiltration_tracker = (
            ExfiltrationTracker()
        )

        self.ddos_detector = DDoSDetector()

        self.spoofed_flood_detector = (
            SpoofedSourceFloodDetector()
        )

        self.udp_reflection_detector = (
            UDPReflectionDetector()
        )

        self.c2_detector = C2BeaconDetector()

        self.dga_detector = DGADetector()

        self.dns_tunnel_detector = (
            DNSTunnellingDetector()
        )

        self.port_scan_detector = (
            PortScanDetector()
        )

        self.recon_detector = (
            ReconnaissanceDetector()
        )

        self.encrypted_malware_detector = (
            EncryptedMalwareDetector()
        )

        self.exfiltration_detector = (
            DataExfiltrationDetector()
        )

        self.alert_deduplicator = (
            AlertDeduplicator(
                active_window=alert_active_window,
            )
        )

        self.incident_manager = (
            IncidentManager(
                correlation_window=correlation_window,
            )
        )

        self.evidence_correlation_engine = (
            EvidenceCorrelationEngine(
                correlation_window=(
                    evidence_correlation_window
                ),
            )
        )

        self.baseline_manager = (
            TrafficBaselineManager(
                minimum_samples=ml_minimum_samples,
                contamination=ml_contamination,
                random_state=ml_random_state,
            )
        )

        self.intelligence_engine = (
            SentinelIntelligence(
                intelligence_engine=(
                    PipelineIntelligenceEngine()
                )
            )
        )

        self._latest_window_features = None

    def process_packet(
        self,
        packet: PacketRecord,
    ) -> list[ThreatAlert]:
        """
        Process one passively observed packet.
        """

        alerts = []

        window_features = self.window.add(
            packet
        )

        self._latest_window_features = (
            window_features
        )

        ddos_alert = None

        if packet.protocol == "TCP":
            ddos_alert = (
                self.ddos_detector.detect(
                    window_features
                )
            )

        if ddos_alert is not None:
            alerts.append(
                ddos_alert
            )

            self.alert_deduplicator.process(
                ddos_alert
            )

            self.incident_manager.process(
                ddos_alert
            )

        spoofed_flood_alert = None

        if packet.protocol == "TCP":
            spoofed_flood_alert = (
                self.spoofed_flood_detector.detect(
                    window_features
                )
            )

        if spoofed_flood_alert is not None:
            alerts.append(
                spoofed_flood_alert
            )

            self.alert_deduplicator.process(
                spoofed_flood_alert
            )

            self.incident_manager.process(
                spoofed_flood_alert
            )

        udp_reflection_alert = None

        if packet.protocol == "UDP":
            udp_reflection_alert = (
                self.udp_reflection_detector.detect(
                    window_features
                )
            )

        if udp_reflection_alert is not None:
            alerts.append(
                udp_reflection_alert
            )

            self.alert_deduplicator.process(
                udp_reflection_alert
            )

            self.incident_manager.process(
                udp_reflection_alert
            )

        self.communication_tracker.process_packet(
            packet
        )

        self.dns_tracker.process_packet(
            packet
        )

        self.scan_tracker.process_packet(
            packet
        )

        self.tls_tracker.process_packet(
            packet
        )

        self.exfiltration_tracker.process_packet(
            packet
        )

        return alerts

    def fit_baseline(
        self,
        windows: list[WindowFeatures],
    ) -> None:
        """
        Fit the ML baseline using trusted normal traffic.

        This method must be called with normal observations
        that are independent from the attack traffic being
        evaluated.
        """

        if not windows:
            raise ValueError(
                "Baseline windows cannot be empty"
            )

        self.baseline_manager.reset()

        self.baseline_manager.add_windows(
            windows
        )

        self.baseline_manager.fit()

    def baseline_status(self):
        """
        Return the current ML baseline status.
        """

        return self.baseline_manager.status()

    def is_ml_ready(self) -> bool:
        """
        Return True when the ML baseline has been fitted.
        """

        return self.baseline_manager.is_fitted()

    def score_window(
        self,
        window_features: WindowFeatures,
    ):
        """
        Score one traffic window with the fitted ML baseline.
        """

        if not self.baseline_manager.is_fitted():
            raise RuntimeError(
                "ML baseline must be fitted before "
                "scoring traffic"
            )

        return self.baseline_manager.predict(
            window_features
        )

    def process_packets(
        self,
        packets: list[PacketRecord],
    ) -> PipelineResult:
        """
        Process a sequence of passively observed packets.

        If a baseline has been fitted, the final traffic window
        is evaluated by the ML anomaly detector and combined
        with detector and correlation evidence.
        """

        latest_window = None

        for packet in packets:
            self.process_packet(
                packet
            )

            latest_window = (
                self._latest_window_features
            )

        dns_alerts = self._detect_dns()

        for alert in dns_alerts:
            self.alert_deduplicator.process(
                alert
            )

            self.incident_manager.process(
                alert
            )

        scan_alerts = self._detect_scans()

        for alert in scan_alerts:
            self.alert_deduplicator.process(
                alert
            )

            self.incident_manager.process(
                alert
            )

        tls_alerts = (
            self._detect_encrypted_sessions()
        )

        for alert in tls_alerts:
            self.alert_deduplicator.process(
                alert
            )

            self.incident_manager.process(
                alert
            )

        exfiltration_alerts = (
            self._detect_exfiltration()
        )

        for alert in exfiltration_alerts:
            self.alert_deduplicator.process(
                alert
            )

            self.incident_manager.process(
                alert
            )

        c2_alerts = self._detect_c2()

        for alert in c2_alerts:
            self.alert_deduplicator.process(
                alert
            )

            self.incident_manager.process(
                alert
            )

        active_alerts = (
            self.alert_deduplicator
            .get_active_alerts()
        )

        correlated_evidence = (
            self.evidence_correlation_engine
            .correlate(
                active_alerts
            )
        )

        ml_anomaly_score = 0.0
        ml_is_anomaly = False

        if (
            latest_window is not None
            and self.baseline_manager.is_fitted()
        ):
            ml_result = self.score_window(
                latest_window
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

        intelligence_result = (
            self.intelligence_engine.evaluate(
                alerts=active_alerts,
                correlated_evidence=(
                    correlated_evidence
                ),
                ml_scores=ml_scores,
            )
        )

        return PipelineResult(
            alerts=active_alerts,
            incidents=(
                self.incident_manager
                .get_incidents()
            ),
            correlated_evidence=(
                correlated_evidence
            ),
            intelligence=(
                intelligence_result.results
            ),
            ml_anomaly_score=(
                ml_anomaly_score
            ),
            ml_is_anomaly=(
                ml_is_anomaly
            ),
        )

    def _detect_dns(
        self,
    ) -> list[ThreatAlert]:
        """
        Evaluate observed DNS traffic for DGA domains
        and DNS tunnelling behavior.
        """

        alerts = []

        for group in (
            self.dns_tracker.get_groups()
        ):

            for query in group.queries:

                features = (
                    DNSFeatureExtractor.extract(
                        query
                    )
                )

                dga_alert = (
                    self.dga_detector.detect(
                        features
                    )
                )

                if dga_alert is not None:
                    dga_alert.source_ip = (
                        group.source_ip
                    )

                    dga_alert.destination_ip = (
                        group.destination_ip
                    )

                    dga_alert.destination_port = 53
                    dga_alert.protocol = "UDP"

                    alerts.append(
                        dga_alert
                    )

            dns_tunnel_alert = (
                self.dns_tunnel_detector.detect(
                    group
                )
            )

            if dns_tunnel_alert is not None:
                dns_tunnel_alert.source_ip = (
                    group.source_ip
                )

                dns_tunnel_alert.destination_ip = (
                    group.destination_ip
                )

                dns_tunnel_alert.destination_port = 53
                dns_tunnel_alert.protocol = "UDP"

                alerts.append(
                    dns_tunnel_alert
                )

        return alerts

    def _detect_scans(
        self,
    ) -> list[ThreatAlert]:
        """
        Evaluate observed source-host behavior for
        port scanning and network reconnaissance.
        """

        alerts = []

        for group in (
            self.scan_tracker.get_groups()
        ):

            port_scan_alert = (
                self.port_scan_detector.detect(
                    group
                )
            )

            if port_scan_alert is not None:
                alerts.append(
                    port_scan_alert
                )

            recon_alert = (
                self.recon_detector.detect(
                    group
                )
            )

            if recon_alert is not None:
                alerts.append(
                    recon_alert
                )

        return alerts

    def _detect_encrypted_sessions(
        self,
    ) -> list[ThreatAlert]:
        """
        Evaluate passive TLS/QUIC metadata for
        suspicious encrypted-session behavior.
        """

        alerts = []

        for group in (
            self.tls_tracker.get_groups()
        ):

            features = (
                TLSFeatureExtractor.extract(
                    session_id=group.session_id,
                    timestamps=group.timestamps,
                    packet_sizes=group.packet_sizes,
                    client_fingerprint=(
                        group.client_fingerprint
                    ),
                    server_fingerprint=(
                        group.server_fingerprint
                    ),
                )
            )

            alert = (
                self.encrypted_malware_detector.detect(
                    features
                )
            )

            if alert is not None:
                alert.source_ip = (
                    group.source_ip
                )

                alert.destination_ip = (
                    group.destination_ip
                )

                alert.destination_port = (
                    group.destination_port
                )

                alert.protocol = (
                    group.protocol
                )

                alerts.append(
                    alert
                )

        return alerts

    def _detect_exfiltration(
        self,
    ) -> list[ThreatAlert]:
        """
        Evaluate directional communication statistics
        for passive data-exfiltration indicators.
        """

        alerts = []

        for group in (
            self.exfiltration_tracker.get_groups()
        ):

            features = (
                ExfiltrationFeatureExtractor.extract(
                    source_ip=group.source_ip,
                    destination_ip=(
                        group.destination_ip
                    ),
                    protocol=group.protocol,
                    outbound_bytes=(
                        group.outbound_bytes
                    ),
                    inbound_bytes=(
                        group.inbound_bytes
                    ),
                    outbound_packets=(
                        group.outbound_packets
                    ),
                    inbound_packets=(
                        group.inbound_packets
                    ),
                )
            )

            alert = (
                self.exfiltration_detector.detect(
                    features
                )
            )

            if alert is not None:
                alert.source_ip = (
                    group.source_ip
                )

                alert.destination_ip = (
                    group.destination_ip
                )

                alert.protocol = (
                    group.protocol
                )

                alerts.append(
                    alert
                )

        return alerts

    def _detect_c2(
        self,
    ) -> list[ThreatAlert]:
        """
        Evaluate all observed communication groups
        for C2 beaconing.
        """

        alerts = []

        for group in (
            self.communication_tracker
            .get_groups()
        ):

            if len(group.timestamps) < 2:
                continue

            source_port = (
                group.source_ports[-1]
                if group.source_ports
                else None
            )

            alert = self.c2_detector.detect(
                timestamps=group.timestamps,
                source_ip=group.source_ip,
                destination_ip=(
                    group.destination_ip
                ),
                source_port=source_port,
                destination_port=(
                    group.destination_port
                ),
                protocol=group.protocol,
            )

            if alert is not None:
                alerts.append(
                    alert
                )

        return alerts

    def get_incidents(
        self,
    ) -> list[Incident]:
        """
        Return all currently correlated incidents.
        """

        return (
            self.incident_manager
            .get_incidents()
        )

    def get_active_alerts(
        self,
    ) -> list[ActiveAlert]:
        """
        Return deduplicated active alerts.
        """

        return (
            self.alert_deduplicator
            .get_active_alerts()
        )

    def get_correlated_evidence(
        self,
    ) -> list[CorrelatedEvidence]:
        """
        Return multi-stage attack chains produced by
        the evidence correlation engine.
        """

        active_alerts = (
            self.alert_deduplicator
            .get_active_alerts()
        )

        return (
            self.evidence_correlation_engine
            .correlate(
                active_alerts
            )
        )

    def get_intelligence(
        self,
    ) -> list[IntelligenceResult]:
        """
        Recalculate intelligence for the current
        active alerts and correlated evidence.
        """

        active_alerts = (
            self.alert_deduplicator
            .get_active_alerts()
        )

        correlated_evidence = (
            self.evidence_correlation_engine
            .correlate(
                active_alerts
            )
        )

        ml_score = 0.0

        if (
            self._latest_window_features
            is not None
            and self.baseline_manager.is_fitted()
        ):
            ml_score = (
                self.score_window(
                    self._latest_window_features
                ).anomaly_score
            )

        ml_scores = {}

        for alert in active_alerts:
            source_ip = (
                alert.alert.source_ip
            )

            if source_ip is not None:
                ml_scores[source_ip] = ml_score

        result = (
            self.intelligence_engine.evaluate(
                alerts=active_alerts,
                correlated_evidence=(
                    correlated_evidence
                ),
                ml_scores=ml_scores,
            )
        )

        return result.results

    def reset(
        self,
    ) -> None:
        """
        Clear all analytical state from the pipeline.

        The ML baseline is also reset because a new pipeline
        session must not accidentally retain an unrelated
        training baseline.
        """

        window_size = (
            self.window.window_size
        )

        self.window = SlidingWindow(
            window_size
        )

        self.communication_tracker.clear()

        self.dns_tracker.clear()

        self.scan_tracker.clear()

        self.tls_tracker.clear()

        self.exfiltration_tracker.clear()

        self.alert_deduplicator.clear()

        correlation_window = (
            self.incident_manager
            .correlation_window
        )

        self.incident_manager = IncidentManager(
            correlation_window=correlation_window
        )

        self.evidence_correlation_engine = (
            EvidenceCorrelationEngine(
                correlation_window=300.0
            )
        )

        self.baseline_manager.reset()

        self._latest_window_features = None