import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from backend.ingest.replay_engine import (
    TrafficReplayEngine,
)
from backend.ingest.stream import PacketStream
from backend.features.window import WindowFeatures


app = FastAPI(
    title="Sentinel",
    description=(
        "AI-based passive cyber-threat detection "
        "for unidirectional IP traffic."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATASET_PATH = Path(
    "datasets/test_traffic.pcap"
)


processor = TrafficReplayEngine()


def make_normal_window(index: int) -> WindowFeatures:
    return WindowFeatures(
        start_time=float(index),
        end_time=float(index + 1),
        packet_count=20 + (index % 3),
        byte_count=2000 + (index * 20),
        packets_per_second=20.0 + (index % 3),
        bytes_per_second=2000.0 + (index * 20),
        syn_count=2,
        syns_per_second=2.0,
        syn_ratio=0.10,
        unique_src_ips=2,
        unique_dst_ips=2,
        unique_dst_ports=2,
        dominant_dst_ip="10.0.0.20",
        dominant_dst_port=443,
        source_ip_entropy=1.0,
    )


def _build_intelligence_response(final, metrics):
    """
    Shared helper that formats a completed pipeline result
    into the standard JSON response structure.
    """
    intelligence = []

    for item in final.intelligence:
        intelligence.append(
            {
                "source_ip": item.source_ip,
                "threat_class": (
                    item.threat_class
                ),
                "unified_score": (
                    item.threat_score
                    .unified_score
                ),
                "risk_level": (
                    item.threat_score
                    .risk_level
                ),
                "detector_score": (
                    item.threat_score
                    .detector_score
                ),
                "ml_score": (
                    item.threat_score
                    .ml_score
                ),
                "correlation_score": (
                    item.threat_score
                    .correlation_score
                ),
                "progression_score": (
                    item.threat_score
                    .progression_score
                ),
                "requires_alert": (
                    item.risk_decision
                    .requires_alert
                ),
                "rationale": (
                    item.risk_decision
                    .rationale
                ),
            }
        )

    return {
        "packets_processed": (
            metrics.packets_processed
        ),
        "replay_duration_seconds": (
            metrics.replay_duration
        ),
        "processing_duration_seconds": (
            metrics.processing_duration
        ),
        "average_latency_ms": (
            metrics.average_latency_ms
        ),
        "maximum_latency_ms": (
            metrics.maximum_latency_ms
        ),
        "packets_per_second": (
            metrics.packets_per_second
        ),
        "ml_anomaly_score": (
            final.ml_anomaly_score
        ),
        "ml_is_anomaly": (
            final.ml_is_anomaly
        ),
        "active_alerts": len(
            final.active_alerts
        ),
        "correlated_chains": len(
            final.correlated_evidence
        ),
        "intelligence": intelligence,
    }


def _run_analysis(pcap_path: str):
    """
    Core analysis logic: reset, refit baseline,
    load packets, run replay, return formatted result.
    """
    processor.processor.reset()

    processor.processor.fit_baseline(
        [
            make_normal_window(index)
            for index in range(30)
        ]
    )

    packets = list(
        PacketStream(pcap_path).packets()
    )

    results, metrics = (
        processor.replay(
            packets,
            mode="maximum",
        )
    )

    if not results:
        raise HTTPException(
            status_code=400,
            detail="No packets found in PCAP.",
        )

    final = results[-1]
    return _build_intelligence_response(final, metrics)


@app.on_event("startup")
def startup():
    """
    Initialize the ML baseline from trusted normal
    traffic before replay begins.
    """

    processor.processor.fit_baseline(
        [
            make_normal_window(index)
            for index in range(30)
        ]
    )


@app.get("/")
def root():
    return {
        "name": "Sentinel",
        "status": "running",
        "mode": "passive",
        "payload_decryption": False,
        "active_mitigation": False,
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "ml_ready": (
            processor.processor.pipeline
            .is_ml_ready()
        ),
    }


@app.get("/status")
def status():
    pipeline = processor.processor.pipeline

    alerts = pipeline.get_active_alerts()
    incidents = pipeline.get_incidents()
    evidence = pipeline.get_correlated_evidence()
    intelligence = pipeline.get_intelligence()

    return {
        "active_alerts": len(alerts),
        "incidents": len(incidents),
        "correlated_chains": len(evidence),
        "intelligence_results": len(
            intelligence
        ),
        "ml_ready": pipeline.is_ml_ready(),
    }


@app.post("/replay")
def replay():
    if not DATASET_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="Test PCAP not found.",
        )

    return _run_analysis(str(DATASET_PATH))


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """
    Accept a user-uploaded PCAP file, run the full
    passive detection pipeline on it, and return the
    intelligence report.

    The uploaded file is written to a temporary location,
    processed, then deleted. The existing detection
    pipeline is unchanged.
    """
    if not file.filename or not file.filename.endswith(".pcap"):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap files are supported.",
        )

    tmp_path = None
    try:
        contents = await file.read()

        with tempfile.NamedTemporaryFile(
            suffix=".pcap",
            delete=False,
        ) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name

        return _run_analysis(tmp_path)

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)