import { 
  ThreatEvent, 
  NetworkFlow, 
  MapNode, 
  MapEdge, 
  IpDossier, 
  AlertItem, 
  SecurityReport, 
  FeatureAttribution 
} from '../types/cybersecurity';

export const initialThreats: ThreatEvent[] = [
  {
    id: 'THR-8901',
    severity: 'CRITICAL',
    sourceIp: '10.24.81.19',
    destinationIp: '172.16.2.42',
    protocol: 'TCP',
    flowDuration: '12.4s',
    anomalyScore: 97.8,
    threatType: 'Port Scan',
    status: 'Investigating',
    time: '2026-09-16 23:18:42',
    confidence: 98.4,
    mitigationAdvice: 'Isolate host VLAN-10 and block port scan sweep at Diode Ingress Filter.',
    flowId: 'FL-1001'
  },
  {
    id: 'THR-8902',
    severity: 'CRITICAL',
    sourceIp: '10.42.18.73',
    destinationIp: '185.220.101.42',
    protocol: 'UDP',
    flowDuration: '48.2s',
    anomalyScore: 95.3,
    threatType: 'Data Exfiltration',
    status: 'Active',
    time: '2026-09-16 23:14:10',
    confidence: 96.2,
    mitigationAdvice: 'Terminate active unidirectional pipe and dump egress payload buffer to quarantine.',
    flowId: 'FL-1002'
  },
  {
    id: 'THR-8903',
    severity: 'HIGH',
    sourceIp: '198.51.100.24',
    destinationIp: '10.0.4.12',
    protocol: 'TCP',
    flowDuration: '5.1s',
    anomalyScore: 89.6,
    threatType: 'C2 Beaconing',
    status: 'Investigating',
    time: '2026-09-16 23:09:22',
    confidence: 91.8,
    mitigationAdvice: 'Match jitter intervals against MITRE ATT&CK T1071 (Application Layer Protocol).',
    flowId: 'FL-1003'
  },
  {
    id: 'THR-8904',
    severity: 'HIGH',
    sourceIp: '10.10.33.15',
    destinationIp: '192.168.10.88',
    protocol: 'TCP',
    flowDuration: '1.2s',
    anomalyScore: 86.4,
    threatType: 'SYN Flood',
    status: 'Mitigated',
    time: '2026-09-16 22:58:05',
    confidence: 88.7,
    mitigationAdvice: 'Rate limiter activated automatically at physical tap interface eth1.',
    flowId: 'FL-1004'
  },
  {
    id: 'THR-8905',
    severity: 'HIGH',
    sourceIp: '10.42.18.73',
    destinationIp: '91.108.4.190',
    protocol: 'ICMP',
    flowDuration: '33.8s',
    anomalyScore: 84.1,
    threatType: 'Unidirectional Covert Channel',
    status: 'Active',
    time: '2026-09-16 22:45:18',
    confidence: 89.1,
    mitigationAdvice: 'ICMP payload entropy exceeds 7.8 bits/byte. Inspect payload for embedded base64.',
    flowId: 'FL-1005'
  },
  {
    id: 'THR-8906',
    severity: 'MEDIUM',
    sourceIp: '172.16.50.8',
    destinationIp: '10.200.1.1',
    protocol: 'UDP',
    flowDuration: '115.0s',
    anomalyScore: 68.2,
    threatType: 'DDoS Pattern',
    status: 'Monitoring',
    time: '2026-09-16 22:31:00',
    confidence: 78.5,
    mitigationAdvice: 'Monitor amplification factor on DNS reflection candidates.',
    flowId: 'FL-1006'
  },
  {
    id: 'THR-8907',
    severity: 'MEDIUM',
    sourceIp: '10.5.12.99',
    destinationIp: '172.16.2.100',
    protocol: 'GRE',
    flowDuration: '72.3s',
    anomalyScore: 62.7,
    threatType: 'Unknown Anomaly',
    status: 'Monitoring',
    time: '2026-09-16 22:15:43',
    confidence: 68.9,
    mitigationAdvice: 'Temporal sequence model detected unusual tunneling encapsulation ratio.',
    flowId: 'FL-1007'
  },
  {
    id: 'THR-8908',
    severity: 'LOW',
    sourceIp: '10.0.1.5',
    destinationIp: '10.0.1.254',
    protocol: 'TCP',
    flowDuration: '0.4s',
    anomalyScore: 41.2,
    threatType: 'Unknown Anomaly',
    status: 'Monitoring',
    time: '2026-09-16 21:55:12',
    confidence: 52.3,
    mitigationAdvice: 'Slight timing irregularity in standard heartbeat protocol.',
    flowId: 'FL-1008'
  }
];

export const initialFlows: NetworkFlow[] = [
  {
    id: 'FL-1001',
    sourceIp: '10.24.81.19',
    destinationIp: '172.16.2.42',
    sourcePort: 49152,
    destinationPort: 445,
    protocol: 'TCP',
    duration: 12.4,
    packets: 4890,
    bytes: 312960,
    direction: 'Egress (One-Way)',
    anomalyScore: 97.8,
    aiClassification: 'Port Scan',
    timestamp: '23:18:42',
    flags: ['SYN', 'ECE', 'URG'],
    payloadEntropy: 7.92,
    payloadHexSample: '45 00 00 3c 1a 2b 40 00 40 06 c2 a4 0a 18 51 13 ac 10 02 2a c0 00 01 bd',
    diodeInterface: 'diode-tx-fiber0'
  },
  {
    id: 'FL-1002',
    sourceIp: '10.42.18.73',
    destinationIp: '185.220.101.42',
    sourcePort: 55432,
    destinationPort: 8443,
    protocol: 'UDP',
    duration: 48.2,
    packets: 18450,
    bytes: 14760000,
    direction: 'Egress (One-Way)',
    anomalyScore: 95.3,
    aiClassification: 'Data Exfiltration',
    timestamp: '23:14:10',
    flags: ['PSH', 'ACK'],
    payloadEntropy: 7.98,
    payloadHexSample: '7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 02 00 3e 00 01 00 00 00',
    diodeInterface: 'diode-tx-fiber0'
  },
  {
    id: 'FL-1003',
    sourceIp: '198.51.100.24',
    destinationIp: '10.0.4.12',
    sourcePort: 443,
    destinationPort: 52189,
    protocol: 'TCP',
    duration: 5.1,
    packets: 320,
    bytes: 24500,
    direction: 'Ingress (One-Way)',
    anomalyScore: 89.6,
    aiClassification: 'C2 Beaconing',
    timestamp: '23:09:22',
    flags: ['ACK', 'PUSH'],
    payloadEntropy: 6.42,
    payloadHexSample: '16 03 01 02 00 01 00 01 fc 03 03 a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d',
    diodeInterface: 'tap-rx-optics1'
  },
  {
    id: 'FL-1004',
    sourceIp: '10.10.33.15',
    destinationIp: '192.168.10.88',
    sourcePort: 38291,
    destinationPort: 80,
    protocol: 'TCP',
    duration: 1.2,
    packets: 98000,
    bytes: 5880000,
    direction: 'Egress (One-Way)',
    anomalyScore: 86.4,
    aiClassification: 'SYN Flood',
    timestamp: '22:58:05',
    flags: ['SYN'],
    payloadEntropy: 1.12,
    payloadHexSample: '45 00 00 28 a1 00 00 00 40 06 73 99 0a 0a 21 0f c0 a8 0a 58 95 93 00 50',
    diodeInterface: 'diode-tx-fiber0'
  },
  {
    id: 'FL-1005',
    sourceIp: '10.42.18.73',
    destinationIp: '91.108.4.190',
    sourcePort: 0,
    destinationPort: 0,
    protocol: 'ICMP',
    duration: 33.8,
    packets: 1200,
    bytes: 1800000,
    direction: 'Egress (One-Way)',
    anomalyScore: 84.1,
    aiClassification: 'Unidirectional Covert Channel',
    timestamp: '22:45:18',
    flags: ['ECHO-REQ'],
    payloadEntropy: 7.84,
    payloadHexSample: '08 00 4d 5b 00 01 00 02 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70',
    diodeInterface: 'diode-tx-fiber0'
  },
  {
    id: 'FL-1006',
    sourceIp: '172.16.50.8',
    destinationIp: '10.200.1.1',
    sourcePort: 53,
    destinationPort: 53,
    protocol: 'UDP',
    duration: 115.0,
    packets: 45000,
    bytes: 23400000,
    direction: 'Ingress (One-Way)',
    anomalyScore: 68.2,
    aiClassification: 'DDoS Pattern',
    timestamp: '22:31:00',
    flags: ['UDP-ANY'],
    payloadEntropy: 4.85,
    payloadHexSample: '00 00 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d',
    diodeInterface: 'tap-rx-optics1'
  },
  {
    id: 'FL-1007',
    sourceIp: '10.5.12.99',
    destinationIp: '172.16.2.100',
    sourcePort: 4789,
    destinationPort: 4789,
    protocol: 'GRE',
    duration: 72.3,
    packets: 6200,
    bytes: 4120000,
    direction: 'Tap Buffer',
    anomalyScore: 62.7,
    aiClassification: 'Unknown Anomaly',
    timestamp: '22:15:43',
    flags: ['GRE-KEY'],
    payloadEntropy: 6.10,
    payloadHexSample: '20 00 65 58 00 00 00 00 45 00 00 54 00 00 40 00 40 01 bd 37 0a 05 0c 63',
    diodeInterface: 'diode-tx-fiber0'
  },
  {
    id: 'FL-1008',
    sourceIp: '192.168.1.105',
    destinationIp: '10.0.0.1',
    sourcePort: 51200,
    destinationPort: 443,
    protocol: 'TCP',
    duration: 210.4,
    packets: 1420,
    bytes: 489000,
    direction: 'Egress (One-Way)',
    anomalyScore: 12.4,
    aiClassification: 'Benign Traffic',
    timestamp: '22:10:15',
    flags: ['ACK'],
    payloadEntropy: 3.20,
    payloadHexSample: '45 00 00 34 8b 1c 40 00 40 06 d1 f5 c0 a8 01 69 0a 00 00 01 c8 00 01 bb',
    diodeInterface: 'diode-tx-fiber0'
  },
  {
    id: 'FL-1009',
    sourceIp: '10.0.4.55',
    destinationIp: '10.0.0.5',
    sourcePort: 22,
    destinationPort: 60231,
    protocol: 'TCP',
    duration: 940.0,
    packets: 8400,
    bytes: 1204000,
    direction: 'Tap Buffer',
    anomalyScore: 8.5,
    aiClassification: 'Benign Traffic',
    timestamp: '22:04:30',
    flags: ['ACK', 'PSH'],
    payloadEntropy: 4.12,
    payloadHexSample: '53 53 48 2d 32 2e 30 2d 4f 70 65 6e 53 53 48 5f 39 2e 33 0d 0a 00 00 00',
    diodeInterface: 'tap-rx-optics1'
  },
  {
    id: 'FL-1010',
    sourceIp: '172.16.2.14',
    destinationIp: '10.0.1.1',
    sourcePort: 123,
    destinationPort: 123,
    protocol: 'UDP',
    duration: 0.1,
    packets: 1,
    bytes: 76,
    direction: 'Ingress (One-Way)',
    anomalyScore: 5.1,
    aiClassification: 'Benign Traffic',
    timestamp: '21:59:00',
    flags: ['NTP'],
    payloadEntropy: 2.10,
    payloadHexSample: '24 01 00 e3 00 00 00 00 00 00 00 00 00 00 00 00 e4 78 90 12 34 56 78 90',
    diodeInterface: 'tap-rx-optics1'
  }
];

export const initialMapNodes: MapNode[] = [
  {
    id: 'node-diode',
    ip: '10.0.0.1',
    label: 'Hardware Data Diode (Tx-Fiber)',
    role: 'Core Diode',
    status: 'normal',
    x: 50,
    y: 50,
    riskScore: 12,
    trafficVolume: '1.42 GB/s',
    flowCount: 842190,
    lastSeen: 'Live Now'
  },
  {
    id: 'node-scada',
    ip: '10.42.18.73',
    label: 'OT/SCADA Controller #4',
    role: 'Critical SCADA',
    status: 'threat',
    x: 24,
    y: 28,
    riskScore: 95,
    trafficVolume: '840 MB/s',
    flowCount: 18450,
    lastSeen: '2.4s ago'
  },
  {
    id: 'node-relay',
    ip: '10.24.81.19',
    label: 'Air-Gapped DMZ Relay',
    role: 'DMZ Relay',
    status: 'threat',
    x: 20,
    y: 72,
    riskScore: 98,
    trafficVolume: '312 MB/s',
    flowCount: 4890,
    lastSeen: '18s ago'
  },
  {
    id: 'node-soc',
    ip: '10.0.4.12',
    label: 'Sentinel AI Analytics Cluster',
    role: 'SOC Monitor',
    status: 'normal',
    x: 50,
    y: 18,
    riskScore: 8,
    trafficVolume: '2.10 GB/s',
    flowCount: 1240900,
    lastSeen: 'Live Now'
  },
  {
    id: 'node-threat-ext',
    ip: '185.220.101.42',
    label: 'External C2 Infrastructure',
    role: 'Suspicious Actor',
    status: 'threat',
    x: 80,
    y: 32,
    riskScore: 92,
    trafficVolume: '1.24 GB',
    flowCount: 1284,
    lastSeen: '14m ago',
    country: 'Netherlands'
  },
  {
    id: 'node-edge-gw',
    ip: '198.51.100.24',
    label: 'Egress Border Gateway (Unidirectional Tap)',
    role: 'External Peer',
    status: 'suspicious',
    x: 78,
    y: 70,
    riskScore: 68,
    trafficVolume: '450 MB/s',
    flowCount: 38200,
    lastSeen: '1m ago',
    country: 'United States'
  },
  {
    id: 'node-internal-srv',
    ip: '172.16.2.42',
    label: 'Critical Defense Archive',
    role: 'Critical SCADA',
    status: 'suspicious',
    x: 35,
    y: 50,
    riskScore: 64,
    trafficVolume: '180 MB/s',
    flowCount: 12500,
    lastSeen: '5m ago'
  },
  {
    id: 'node-telemetry',
    ip: '192.168.1.105',
    label: 'Telemetry Optical Receiver',
    role: 'SOC Monitor',
    status: 'normal',
    x: 65,
    y: 50,
    riskScore: 14,
    trafficVolume: '540 MB/s',
    flowCount: 89000,
    lastSeen: 'Live Now'
  }
];

export const initialMapEdges: MapEdge[] = [
  { id: 'edge-1', source: 'node-scada', target: 'node-diode', status: 'threat', trafficRate: '840 MB/s' },
  { id: 'edge-2', source: 'node-relay', target: 'node-diode', status: 'threat', trafficRate: '312 MB/s' },
  { id: 'edge-3', source: 'node-diode', target: 'node-soc', status: 'normal', trafficRate: '2.10 GB/s' },
  { id: 'edge-4', source: 'node-diode', target: 'node-telemetry', status: 'normal', trafficRate: '540 MB/s' },
  { id: 'edge-5', source: 'node-diode', target: 'node-threat-ext', status: 'threat', trafficRate: '14.7 MB' },
  { id: 'edge-6', source: 'node-edge-gw', target: 'node-diode', status: 'suspicious', trafficRate: '450 MB/s' },
  { id: 'edge-7', source: 'node-internal-srv', target: 'node-diode', status: 'normal', trafficRate: '180 MB/s' },
];

export const ipDossiers: Record<string, IpDossier> = {
  '185.220.101.42': {
    ip: '185.220.101.42',
    riskScore: 87,
    threatLevel: 'HIGH',
    reputation: 'Suspicious',
    observedBehavior: 'Abnormal outbound communication and blind byte leakage without TCP handshake acknowledgment',
    associatedFlows: 1284,
    firstSeen: '12 Aug 2026',
    lastSeen: '16 Sep 2026',
    country: 'Netherlands',
    countryCode: 'NL',
    asn: 'AS208323 (Quasi-Networks LTD)',
    organization: 'Tor Exit Node / Darknet Bulletproof Relay',
    trafficDirection: 'Egress',
    tags: ['C2 Beacon', 'Tor Exit Node', 'Exfiltration Target', 'Known Threat Intel Match'],
    timeline: [
      {
        time: '2026-09-16 23:14:10',
        event: 'Bulk Data Exfiltration Ingestion',
        severity: 'CRITICAL',
        details: 'Received 14.7 MB encrypted stream across UDP:8443 from internal SCADA 10.42.18.73.'
      },
      {
        time: '2026-09-16 21:05:00',
        event: 'Periodic Egress Interval Established',
        severity: 'HIGH',
        details: 'Heuristic timing analysis logged heartbeat periodicity with standard deviation < 0.05s.'
      },
      {
        time: '2026-09-15 14:22:45',
        event: 'Initial One-Way Diode Flow Observed',
        severity: 'MEDIUM',
        details: 'First unidirectional packet observed from internal air-gap DMZ relay.'
      },
      {
        time: '2026-08-12 09:11:00',
        event: 'Listed on AlienVault OTX Threat Feed',
        severity: 'HIGH',
        details: 'Flagged by international CERT advisories for state-sponsored scanning.'
      }
    ]
  },
  '10.42.18.73': {
    ip: '10.42.18.73',
    riskScore: 95,
    threatLevel: 'CRITICAL',
    reputation: 'Malicious',
    observedBehavior: 'Compromised SCADA PLC emitting high-frequency covert optical data bursts',
    associatedFlows: 18450,
    firstSeen: '01 Sep 2026',
    lastSeen: '16 Sep 2026',
    country: 'Internal Network',
    countryCode: 'IN',
    asn: 'AS-LOCAL (Isolated Air-Gap Subnet)',
    organization: 'Critical Infrastructure Segment B',
    trafficDirection: 'Egress',
    tags: ['SCADA Subnet', 'Compromised Host', 'Covert Channel Source', 'High Priority'],
    timeline: [
      {
        time: '2026-09-16 23:14:10',
        event: 'Exfiltration Burst Triggered',
        severity: 'CRITICAL',
        details: 'Behavioral deviation jumped to 4.7σ above baseline traffic profile.'
      },
      {
        time: '2026-09-16 22:45:18',
        event: 'ICMP Payload Steganography Detected',
        severity: 'HIGH',
        details: 'Entropy reached 7.84 bits/byte indicating non-standard encrypted payloads.'
      },
      {
        time: '2026-09-16 19:30:10',
        event: 'Baseline Frequency Shift',
        severity: 'MEDIUM',
        details: 'Packet frequency increased 340% compared to rolling 7-day average.'
      }
    ]
  },
  '10.24.81.19': {
    ip: '10.24.81.19',
    riskScore: 92,
    threatLevel: 'CRITICAL',
    reputation: 'Malicious',
    observedBehavior: 'Sequential horizontal port scanning against air-gapped target segment',
    associatedFlows: 4890,
    firstSeen: '10 Sep 2026',
    lastSeen: '16 Sep 2026',
    country: 'Internal Network',
    countryCode: 'IN',
    asn: 'AS-LOCAL (DMZ Segment)',
    organization: 'Air-Gap Ingress Buffer Host',
    trafficDirection: 'Egress',
    tags: ['Port Scan', 'Reconnaissance', 'VLAN Violation'],
    timeline: [
      {
        time: '2026-09-16 23:18:42',
        event: 'High-Speed SYN Scan Fired',
        severity: 'CRITICAL',
        details: 'Attempted connections to 1,024 consecutive ports within 12.4s window.'
      },
      {
        time: '2026-09-16 22:10:00',
        event: 'Abnormal TCP Flag Combination',
        severity: 'HIGH',
        details: 'Discovered SYN+ECE+URG flags without standard three-way handshake initiation.'
      }
    ]
  },
  '198.51.100.24': {
    ip: '198.51.100.24',
    riskScore: 68,
    threatLevel: 'HIGH',
    reputation: 'Suspicious',
    observedBehavior: 'Inbound blind C2 command injection through optical physical tap receiver',
    associatedFlows: 38200,
    firstSeen: '05 Sep 2026',
    lastSeen: '16 Sep 2026',
    country: 'United States',
    countryCode: 'US',
    asn: 'AS15169 (Cloud Egress Gateway)',
    organization: 'External Host / Proxy Provider',
    trafficDirection: 'Ingress',
    tags: ['C2 Beacon', 'Inbound Injection', 'Suspicious ISP'],
    timeline: [
      {
        time: '2026-09-16 23:09:22',
        event: 'Beacon Pattern Identified',
        severity: 'HIGH',
        details: 'Interval rhythm matching known adversarial beacon profiles with 91.8% confidence.'
      }
    ]
  },
  '192.168.1.105': {
    ip: '192.168.1.105',
    riskScore: 12,
    threatLevel: 'LOW',
    reputation: 'Clean',
    observedBehavior: 'Standard telemetry heartbeats conforming strictly to physical diode baseline',
    associatedFlows: 89000,
    firstSeen: '01 Jan 2026',
    lastSeen: '16 Sep 2026',
    country: 'Internal Network',
    countryCode: 'IN',
    asn: 'AS-LOCAL (Sensor Network)',
    organization: 'Optical Telemetry Controller',
    trafficDirection: 'Egress',
    tags: ['Telemetry', 'Verified System', 'Low Risk'],
    timeline: [
      {
        time: '2026-09-16 22:10:15',
        event: 'Automated Status Telemetry',
        severity: 'LOW',
        details: 'Nominal telemetry transmission conforming to zero-loss threshold.'
      }
    ]
  }
};

export const initialAlerts: AlertItem[] = [
  {
    id: 'ALT-101',
    title: 'Possible Data Exfiltration via Unidirectional UDP',
    severity: 'CRITICAL',
    threatType: 'Data Exfiltration',
    sourceIp: '10.42.18.73',
    destinationIp: '185.220.101.42',
    aiConfidence: 96.2,
    timeDetected: '23:14:10 (6 min ago)',
    status: 'Active',
    deviationScore: '4.7σ above baseline',
    description: 'High-volume unidirectional UDP burst transmitting encrypted chunks across data diode interface without return ACK acknowledgment.',
    evidence: [
      'Traffic frequency increased 340% over baseline',
      'Shannon entropy calculated at 7.98 bits/byte',
      'Zero TCP ACK packets received (strictly unidirectional flow)'
    ]
  },
  {
    id: 'ALT-102',
    title: 'High-Density Port Scan Sweep Detected',
    severity: 'CRITICAL',
    threatType: 'Port Scan',
    sourceIp: '10.24.81.19',
    destinationIp: '172.16.2.42',
    aiConfidence: 98.4,
    timeDetected: '23:18:42 (2 min ago)',
    status: 'Investigating',
    deviationScore: '5.2σ above baseline',
    description: 'Rapid sequential probe of air-gapped target ports 21 through 1024 within 12.4 seconds.',
    evidence: [
      'Destination port diversity exceeded anomaly threshold by 450%',
      'Abnormal TCP header flags (SYN+ECE+URG)',
      'Inter-packet delay standard deviation < 0.002s'
    ]
  },
  {
    id: 'ALT-103',
    title: 'Periodic Command & Control (C2) Beaconing',
    severity: 'HIGH',
    threatType: 'C2 Beaconing',
    sourceIp: '198.51.100.24',
    destinationIp: '10.0.4.12',
    aiConfidence: 91.8,
    timeDetected: '23:09:22 (11 min ago)',
    status: 'Investigating',
    deviationScore: '3.8σ above baseline',
    description: 'Regular interval communication pattern characteristic of Cobalt Strike or Empire C2 beacon framework.',
    evidence: [
      'Periodic transmission rhythm with synthetic jitter (15s ± 200ms)',
      'TLS SNI matches known malicious cluster',
      'Unidirectional receiver buffer packet matches signature'
    ]
  },
  {
    id: 'ALT-104',
    title: 'Volumetric SYN Flood Flooding Diode Egress Buffer',
    severity: 'HIGH',
    threatType: 'SYN Flood',
    sourceIp: '10.10.33.15',
    destinationIp: '192.168.10.88',
    aiConfidence: 88.7,
    timeDetected: '22:58:05 (22 min ago)',
    status: 'Resolved',
    deviationScore: '4.1σ above baseline',
    description: 'Saturating half-open connection requests targeting internal web management interface.',
    evidence: [
      '98,000 packets transmitted within 1.2 seconds',
      'Automated rate limiter triggered on interface diode-tx-fiber0'
    ]
  },
  {
    id: 'ALT-105',
    title: 'Unidirectional Covert ICMP Tunneling Suspected',
    severity: 'HIGH',
    threatType: 'Unidirectional Covert Channel',
    sourceIp: '10.42.18.73',
    destinationIp: '91.108.4.190',
    aiConfidence: 89.1,
    timeDetected: '22:45:18 (35 min ago)',
    status: 'Active',
    deviationScore: '3.6σ above baseline',
    description: 'ICMP Echo Request payloads carrying obfuscated non-echo binary structures without echo replies.',
    evidence: [
      'Packet payload entropy 7.84 vs standard ICMP 1.20',
      'Continuous egress stream with zero echo responses'
    ]
  },
  {
    id: 'ALT-106',
    title: 'DNS Amplification Reflection Anomaly',
    severity: 'MEDIUM',
    threatType: 'DDoS Pattern',
    sourceIp: '172.16.50.8',
    destinationIp: '10.200.1.1',
    aiConfidence: 78.5,
    timeDetected: '22:31:00 (49 min ago)',
    status: 'Resolved',
    deviationScore: '2.8σ above baseline',
    description: 'Unusual inbound UDP 53 volume passing through optical tap sensor.',
    evidence: [
      'Amplification ratio 42:1 observed on response sizes',
      'Traffic successfully filtered by border rule #442'
    ]
  }
];

export const mockReports: SecurityReport[] = [
  {
    id: 'REP-2026-0916',
    title: 'Daily Unidirectional Threat Intelligence Report',
    type: 'Daily Threat Report',
    date: '16 Sep 2026',
    threatCount: 38,
    riskScore: 24,
    status: 'Ready',
    executiveSummary: 'During the 24-hour monitoring window across the physical data diode and optical tap interfaces, Sentinel analyzed 2.84 million unidirectional IP flows. The behavioral AI engine flagged 38 active threat events, of which 2 critical exfiltration incidents were quarantined in real time.',
    findings: [
      'Critical exfiltration attempt blocked from SCADA controller 10.42.18.73 targeting external IP 185.220.101.42.',
      'Air-gap DMZ relay 10.24.81.19 initiated a high-speed port scan sweep across 1,024 endpoints.',
      'Average detection latency for unidirectional anomalies was 14.2 milliseconds.',
      'Unidirectional data diode optical links operated at 99.998% packet delivery reliability with zero drop.'
    ],
    topThreats: [
      { type: 'Data Exfiltration', count: 12, maxSeverity: 'CRITICAL' },
      { type: 'Port Scan', count: 9, maxSeverity: 'CRITICAL' },
      { type: 'C2 Beaconing', count: 7, maxSeverity: 'HIGH' },
      { type: 'Covert Channel', count: 6, maxSeverity: 'HIGH' },
      { type: 'DDoS Pattern', count: 4, maxSeverity: 'MEDIUM' }
    ]
  },
  {
    id: 'REP-2026-W37',
    title: 'Weekly Network Behavioral Analysis',
    type: 'Weekly Network Analysis',
    date: '10 Sep - 16 Sep 2026',
    threatCount: 184,
    riskScore: 18,
    status: 'Ready',
    executiveSummary: 'Comprehensive 7-day behavioral baseline review across all optical tap sensors and data diode transmitters. System maintained high fidelity with a 99.2% true positive threat detection rate and a 0.08% false positive rate.',
    findings: [
      '19.4 TB of unidirectional IP traffic scrutinized with zero latency overhead on critical SCADA telemetry.',
      'Isolation Forest and LSTM temporal models adapted to new operational telemetry shifts in VLAN-4.',
      'Identified 3 dormant external C2 server IPs that attempted blind payload reception.'
    ],
    topThreats: [
      { type: 'C2 Beaconing', count: 62, maxSeverity: 'HIGH' },
      { type: 'Data Exfiltration', count: 44, maxSeverity: 'CRITICAL' },
      { type: 'Port Scan', count: 39, maxSeverity: 'CRITICAL' },
      { type: 'SYN Flood', count: 21, maxSeverity: 'HIGH' },
      { type: 'Unknown Anomaly', count: 18, maxSeverity: 'MEDIUM' }
    ]
  },
  {
    id: 'REP-2026-AI-SUM',
    title: 'Sentinel AI Model Accuracy & Explainability Summary',
    type: 'AI Detection Summary',
    date: '16 Sep 2026',
    threatCount: 1284,
    riskScore: 15,
    status: 'Ready',
    executiveSummary: 'Deep technical validation of Sentinel AI detection architectures tailored specifically for unidirectional IP traffic without TCP acknowledgments. Compares baseline reconstruction error vs heuristic signature match.',
    findings: [
      'Autoencoder reconstruction error achieved 0.994 AUC-ROC on synthetic and live test vectors.',
      'Feature attribution analysis highlights Flow Frequency (+340%) and Entropy Deviation (+82%) as primary drivers.',
      'Zero model drift observed over 30 continuous operational days.'
    ],
    topThreats: [
      { type: 'Model Confidence (Port Scan)', count: 95, maxSeverity: 'CRITICAL' },
      { type: 'Model Confidence (Exfiltration)', count: 87, maxSeverity: 'CRITICAL' },
      { type: 'Model Confidence (C2 Beaconing)', count: 82, maxSeverity: 'HIGH' }
    ]
  },
  {
    id: 'REP-2026-INC-404',
    title: 'Incident Forensic Dossier #INC-8902 (SCADA Exfiltration)',
    type: 'Incident Forensic Report',
    date: '16 Sep 2026',
    threatCount: 1,
    riskScore: 95,
    status: 'Ready',
    executiveSummary: 'Forensic breakdown of the high-severity covert channel exfiltration attempt from internal SCADA PLC 10.42.18.73 toward Dutch bulletproof relay 185.220.101.42.',
    findings: [
      'Attacker leveraged blind UDP fragmentation to circumvent unidirectional state tracking.',
      'Sentinel AI detected the payload entropy shift (7.98 bits/byte) within 240 milliseconds of flow commencement.',
      'Automated quarantine rule #DQ-99 was published to hardware diode optical buffer, cutting transmission.'
    ],
    topThreats: [
      { type: 'Data Exfiltration', count: 1, maxSeverity: 'CRITICAL' }
    ]
  }
];

export const xaiFeatureAttributions: FeatureAttribution[] = [
  {
    feature: 'Traffic Burst Frequency',
    importance: 92,
    deviation: '+340% above baseline',
    description: 'Packet arrival rate spiked dramatically within a 2-second sampling interval.'
  },
  {
    feature: 'Destination Port Diversity',
    importance: 88,
    deviation: '+210% entropy deviation',
    description: 'Unidirectional packets targeted randomized high-range ports in rapid succession.'
  },
  {
    feature: 'Payload Shannon Entropy',
    importance: 84,
    deviation: '7.98 bits/byte (High Entropy)',
    description: 'Payload randomness indicates high-density cryptographic or compressed data exfiltration.'
  },
  {
    feature: 'Temporal Beacon Periodicity',
    importance: 79,
    deviation: 'Interval variance < 0.05s',
    description: 'Strict cyclical interval with zero human variation, matching automated C2 beacon scripts.'
  },
  {
    feature: 'Missing Reverse ACK Signature',
    importance: 72,
    deviation: '100% Unidirectional Ratio',
    description: 'Zero bidirectional handshake signals confirm blind unidirectional egress traversal.'
  }
];

export const trafficChartData = {
  '1H': [
    { time: '22:20', inbound: 420, outbound: 890, threats: 2 },
    { time: '22:25', inbound: 460, outbound: 940, threats: 3 },
    { time: '22:30', inbound: 410, outbound: 880, threats: 1 },
    { time: '22:35', inbound: 580, outbound: 1120, threats: 4 },
    { time: '22:40', inbound: 520, outbound: 1040, threats: 2 },
    { time: '22:45', inbound: 690, outbound: 1450, threats: 8 },
    { time: '22:50', inbound: 640, outbound: 1380, threats: 6 },
    { time: '22:55', inbound: 810, outbound: 1890, threats: 14 },
    { time: '23:00', inbound: 750, outbound: 1650, threats: 9 },
    { time: '23:05', inbound: 680, outbound: 1420, threats: 5 },
    { time: '23:10', inbound: 890, outbound: 2150, threats: 18 },
    { time: '23:15', inbound: 940, outbound: 2420, threats: 24 },
    { time: '23:20', inbound: 820, outbound: 1980, threats: 12 },
  ],
  '6H': [
    { time: '17:30', inbound: 310, outbound: 620, threats: 1 },
    { time: '18:30', inbound: 450, outbound: 880, threats: 3 },
    { time: '19:30', inbound: 580, outbound: 1150, threats: 4 },
    { time: '20:30', inbound: 640, outbound: 1320, threats: 7 },
    { time: '21:30', inbound: 720, outbound: 1540, threats: 9 },
    { time: '22:30', inbound: 890, outbound: 1950, threats: 16 },
    { time: '23:20', inbound: 940, outbound: 2420, threats: 24 },
  ],
  '24H': [
    { time: '00:00', inbound: 210, outbound: 450, threats: 1 },
    { time: '04:00', inbound: 180, outbound: 380, threats: 0 },
    { time: '08:00', inbound: 520, outbound: 1100, threats: 4 },
    { time: '12:00', inbound: 840, outbound: 1820, threats: 8 },
    { time: '16:00', inbound: 790, outbound: 1740, threats: 11 },
    { time: '20:00', inbound: 880, outbound: 1990, threats: 19 },
    { time: '23:20', inbound: 940, outbound: 2420, threats: 24 },
  ],
  '7D': [
    { time: 'Thu', inbound: 4800, outbound: 9800, threats: 42 },
    { time: 'Fri', inbound: 5400, outbound: 11200, threats: 58 },
    { time: 'Sat', inbound: 3200, outbound: 6900, threats: 21 },
    { time: 'Sun', inbound: 2900, outbound: 5800, threats: 14 },
    { time: 'Mon', inbound: 6100, outbound: 13400, threats: 64 },
    { time: 'Tue', inbound: 6800, outbound: 14800, threats: 72 },
    { time: 'Wed', inbound: 7200, outbound: 15900, threats: 86 },
  ],
  '30D': [
    { time: 'Week 1', inbound: 32000, outbound: 68000, threats: 280 },
    { time: 'Week 2', inbound: 35000, outbound: 74000, threats: 310 },
    { time: 'Week 3', inbound: 38000, outbound: 81000, threats: 345 },
    { time: 'Week 4', inbound: 42000, outbound: 89000, threats: 382 },
  ]
};

export const threatDistributionData = [
  { name: 'Normal Flows', value: 92.4, color: '#0EA5E9' },
  { name: 'Suspicious (Heuristic)', value: 4.8, color: '#F59E0B' },
  { name: 'Malicious (Confirmed)', value: 2.1, color: '#EF4444' },
  { name: 'Unknown Anomaly', value: 0.7, color: '#8B5CF6' }
];

export const protocolDistributionData = [
  { protocol: 'TCP (Unidirectional)', count: 1840000, percentage: 64.8, color: '#00F0FF' },
  { protocol: 'UDP (High Throughput)', count: 710000, percentage: 25.0, color: '#38BDF8' },
  { protocol: 'ICMP (Telemetry/Ping)', count: 180000, percentage: 6.3, color: '#818CF8' },
  { protocol: 'GRE (Tunneling)', count: 80000, percentage: 2.8, color: '#F59E0B' },
  { protocol: 'ESP / IPsec', count: 30000, percentage: 1.1, color: '#10B981' }
];

export const flowDurationData = [
  { range: '< 1s', count: 1420000 },
  { range: '1-5s', count: 820000 },
  { range: '5-30s', count: 410000 },
  { range: '30s-2m', count: 130000 },
  { range: '2m-10m', count: 45000 },
  { range: '> 10m', count: 15000 }
];

export const packetSizeDistributionData = [
  { range: '64-128B (Control)', count: 980000 },
  { range: '129-512B (Headers)', count: 640000 },
  { range: '513-1024B (Telemetry)', count: 420000 },
  { range: '1025-1460B (Payload)', count: 690000 },
  { range: '1461-1500B (Jumbo/MTU)', count: 110000 }
];
