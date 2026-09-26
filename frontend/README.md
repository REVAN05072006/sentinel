# Sentinel Frontend — Backend Integrated

This frontend is wired to the Sentinel FastAPI/WebSocket backend rather than the original mock security dataset.

## Backend expected

Start the Sentinel backend on its configured port (the frontend defaults to `http://127.0.0.1:8001`). The integration uses:

- `GET /status` — backend health
- `GET /interfaces` — available passive capture interfaces
- `POST /analyze` — uploaded PCAP analysis
- `WS /ws/live` — demo, PCAP replay, and live passive streaming

Override the backend URL with:

```powershell
$env:VITE_SENTINEL_API_URL="http://127.0.0.1:8001"
```

## Run

```powershell
npm install
npm run dev
```

## Supported backend features in the UI

- Live Npcap/Scapy passive capture
- Demo scenarios: normal, SYN flood, UDP reflection/amplification, recon/scan, DGA/DNS tunnelling, C2 beaconing, encrypted malware, exfiltration, full-chain
- PCAP upload and analysis
- Flow groups and sliding-window telemetry
- DNS metadata
- TLS/QUIC metadata without decryption
- All ten required threat classes
- ML anomaly score and baseline state
- Unified threat intelligence score
- Correlation/progression evidence
- Detector coverage
- Active alerts and incident episodes
- Read-only posture: no probing, payload decryption, quarantine, blocking, or mitigation commands

The UI does not fabricate accuracy percentages, external IP reputation, mitigation results, or synthetic telemetry.
