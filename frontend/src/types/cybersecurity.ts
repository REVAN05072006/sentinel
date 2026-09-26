export type SeverityLevel =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO';

export type ThreatStatus =
  | 'Active'
  | 'Investigating'
  | 'Resolved'
  | 'False Positive'
  | 'Monitoring'
  | 'Mitigated';

export type ProtocolType =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'GRE'
  | 'ESP'
  | 'OTHER';

export const THREAT_CLASSES = [
  'SYN_FLOOD',
  'UDP_REFLECTION_AMPLIFICATION',
  'SPOOFED_SOURCE_FLOOD',
  'C2_BEACONING',
  'DGA_DOMAIN',
  'DNS_TUNNELLING',
  'ENCRYPTED_MALWARE',
  'RECONNAISSANCE',
  'PORT_SCANNING',
  'DATA_EXFILTRATION'
] as const;

export type ThreatClass = typeof THREAT_CLASSES[number];

export interface BackendAlert {
  timestamp?: string;
  flow_id?: unknown;
  threat_class: string;
  confidence: number;
  severity: SeverityLevel;

  source_ip?: string;
  destination_ip?: string;
  source_port?: number | null;
  destination_port?: number | null;
  protocol?: string;

  evidence?: Record<string, unknown>;

  first_seen?: string;
  last_seen?: string;
  detection_count?: number;

  [key: string]: unknown;
}

export interface IntelligenceResult {
  source_ip?: string;
  threat_class: string;

  detector_score: number;
  ml_score: number;
  correlation_score: number;
  progression_score: number;
  unified_score: number;

  risk_level: SeverityLevel;

  rationale?: string;

  [key: string]: unknown;
}

export interface CorrelatedEvidence {
  source_ip: string;
  threat_classes: string[];

  first_seen?: string;
  last_seen?: string;

  correlation_confidence: number;
  progression_score: number;
  correlation_quality: number;

  progression_pairs: {
    from: string;
    to: string;
  }[];

  evidence_chain: unknown[];

  [key: string]: unknown;
}

export interface WindowFeatures {
  start?: string;
  end?: string;

  packet_count: number;
  byte_count: number;

  packets_per_second: number;
  bytes_per_second: number;

  syn_count: number;
  syns_per_second: number;
  syn_ratio: number;

  unique_src_ips: number;
  unique_dst_ips: number;
  unique_dst_ports: number;

  dominant_dst_ip?: string;
  dominant_dst_port?: number;

  source_ip_entropy: number;

  [key: string]: unknown;
}

export interface FlowRecord {
  id?: string;
  flow_id?: string | unknown;

  source_ip: string;
  destination_ip: string;

  source_port?: number | null;
  destination_port?: number | null;

  protocol: string;

  start?: string;
  end?: string;

  first_seen?: string;
  last_seen?: string;

  packet_count?: number;
  packets?: number;

  byte_count?: number;
  bytes?: number;

  syn_count?: number;

  [key: string]: unknown;
}

export interface DnsRecord {
  source_ip?: string;
  destination_ip?: string;
  query?: string;
  timestamp?: string;

  query_length?: number;
  entropy?: number;
  record_type?: string;

  [key: string]: unknown;
}

export interface EncryptedSession {
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;

  packet_count?: number;
  total_bytes?: number;

  mean_packet_size?: number;
  std_packet_size?: number;

  mean_interarrival?: number;
  std_interarrival?: number;

  burstiness?: number;

  client_fingerprint?: string;
  server_fingerprint?: string;

  [key: string]: unknown;
}

export interface DetectorCoverage {
  threat_class: string;
  label?: string;
  detected: boolean;

  [key: string]: unknown;
}

export interface PipelineSnapshot {
  type?: string;
  sequence?: number;
  timestamp?: string;

  packet?: Record<string, unknown>;

  window?: WindowFeatures;

  new_alerts?: BackendAlert[];
  active_alerts?: BackendAlert[];
  incidents?: BackendAlert[];

  correlated_evidence?: CorrelatedEvidence[];
  intelligence?: IntelligenceResult[];

  ml?: {
    score: number;
    is_anomaly: boolean;
    ready?: boolean;
  };

  ml_anomaly_score?: number;
  ml_is_anomaly?: boolean;

  processing_latency_ms?: number;

  telemetry?: {
    flow_groups?: number;
    captured_packets?: number;
    dropped_packets?: number;

    [key: string]: unknown;
  };

  flows?: FlowRecord[];

  dns?: {
    query_count?: number;
    recent_queries?: DnsRecord[];

    [key: string]: unknown;
  };

  encrypted?: {
    encrypted_sessions?: number;
    encrypted_packet_count?: number;
    sessions?: EncryptedSession[];

    [key: string]: unknown;
  };

  detector_coverage?: DetectorCoverage[];

  source?: {
    mode?: string;
    scenario?: string;
    interface?: string;
    interface_name?: string;
    [key: string]: unknown;
  };

  metrics?: Record<string, unknown>;

  [key: string]: unknown;
}

export interface SecurityReport {
  id: string;
  title: string;
  type: string;
  date: string;

  threatCount: number;
  riskScore: number;

  status: 'Ready' | 'Archived';

  executiveSummary: string;

  findings: string[];

  topThreats: {
    type: string;
    count: number;
    maxSeverity: SeverityLevel;
  }[];
}

/*
 * UI adapters retained for the existing Sentinel interface.
 * Runtime security data should come from the backend models above.
 */

export interface NetworkFlow {
  id: string;

  sourceIp: string;
  destinationIp: string;

  sourcePort: number;
  destinationPort: number;

  protocol: ProtocolType;

  duration: number;

  packets: number;
  bytes: number;

  direction:
    | 'Egress (One-Way)'
    | 'Ingress (One-Way)'
    | 'Tap Buffer';

  anomalyScore: number;
  aiClassification: string;

  timestamp: string;

  flags?: string[];

  payloadEntropy?: number;
  payloadHexSample?: string;
  diodeInterface?: string;

  packetCount?: number;
  byteCount?: number;

  packetsPerSecond?: number;
  bytesPerSecond?: number;

  meanPacketSize?: number;
  stdPacketSize?: number;

  meanInterarrival?: number;
  stdInterarrival?: number;

  burstiness?: number;

  clientFingerprint?: string;
  serverFingerprint?: string;

  country?: string;

  riskScore?: number;
  threatType?: string;

  [key: string]: unknown;
}

export interface ThreatEvent {
  id: string;

  severity: SeverityLevel;

  sourceIp: string;
  destinationIp: string;

  protocol: ProtocolType;

  flowDuration: string;

  anomalyScore: number;

  threatType: string;

  status: ThreatStatus;

  time: string;

  confidence: number;

  flowId?: string;

  /*
   * Optional because legacy mock/UI records may not contain
   * backend evidence. Real backend alerts can populate this
   * from BackendAlert.evidence.
   */
  evidence?: Record<string, unknown>;

  /*
   * Retained only for compatibility with the existing UI data.
   * Sentinel itself remains analytical and read-only.
   */
  mitigationAdvice?: string;

  detectorScore?: number;
  mlScore?: number;
  correlationScore?: number;
  progressionScore?: number;
  unifiedScore?: number;
  riskLevel?: SeverityLevel;

  [key: string]: unknown;
}

export interface MapNode {
  id: string;

  ip: string;
  label: string;

  role:
    | 'Core Diode'
    | 'SOC Monitor'
    | 'Critical SCADA'
    | 'DMZ Relay'
    | 'ExternalPeer'
    | 'Suspicious Actor'
    | 'External Peer';

  status:
    | 'normal'
    | 'suspicious'
    | 'threat';

  x: number;
  y: number;

  riskScore: number;

  trafficVolume: string;
  flowCount: number;

  lastSeen: string;

  country?: string;
  latitude?: number;
  longitude?: number;

  organization?: string;
  asn?: string;

  [key: string]: unknown;
}

export interface MapEdge {
  id: string;

  source: string;
  target: string;

  status:
    | 'normal'
    | 'suspicious'
    | 'threat';

  trafficRate: string;

  [key: string]: unknown;
}

export interface AlertItem {
  id: string;

  title: string;

  severity: SeverityLevel;

  threatType: string;

  sourceIp: string;
  destinationIp: string;

  aiConfidence: number;

  timeDetected: string;

  status:
    | 'Active'
    | 'Investigating'
    | 'Resolved'
    | 'False Positive';

  deviationScore: string;

  description: string;

  evidence: string[];

  detectionCount?: number;
  flowId?: string;
  riskScore?: number;

  [key: string]: unknown;
}

export interface FeatureAttribution {
  feature: string;
  importance: number;
  deviation: string;
  description: string;
}

export interface IpDossier {
  ip: string;

  hostname?: string;
  country?: string;
  organization?: string;
  asn?: string;

  reputation?: string;

  firstSeen?: string;
  lastSeen?: string;

  threatCount?: number;
  riskScore?: number;

  relatedThreats?: string[];

  [key: string]: unknown;
}
