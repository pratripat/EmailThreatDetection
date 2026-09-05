export interface EmailAnalysisRequest {
  senderEmail: string;
  subject?: string;
  rawHeaders?: string;
  emailBody?: string;
  timestamp?: string;
}

export interface IpHopIntelligence {
  hopNumber: number;
  ip: string;
  hostname: string;
  country: string;
  city?: string;
  asn: string;
  isp: string;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN';
  firstSeen: string;
  threatFeeds: {
    abuseIpDb: 'HIGH RISK' | 'MEDIUM RISK' | 'CLEAN';
    virusTotal: string; // e.g. "8 / 92 engines"
    spamhausListed: boolean;
  };
}

export interface AuthStatus {
  spf: 'PASSED' | 'FAILED' | 'SOFTFAIL' | 'NONE';
  dkim: 'PASSED' | 'FAILED' | 'NONE';
  dmarc: 'PASSED' | 'FAILED' | 'NONE';
  fromDomain: string;
  returnPathDomain: string;
  alignmentMatched: boolean;
  notes: string[];
}

export interface ExtractedUrl {
  url: string;
  domain: string;
  registeredAgeDays: number;
  reputation: 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE';
  threatScore: number;
  flags: string[];
  redirectChain?: string[];
}

export interface ContentAiAnalysis {
  classification: 'PHISHING' | 'SPOOFING' | 'BEC_FRAUD' | 'BENIGN' | 'MALWARE_DROP';
  confidence: number;
  intents: string[];
  suspiciousPhrases: {
    phrase: string;
    signalType: 'Urgency signal' | 'Credential request' | 'Financial coercion' | 'Security impersonation';
  }[];
  featureContributions: {
    feature: string;
    weight: number; // 0 to 100
    impact: 'positive' | 'negative';
  }[];
}

export interface IocSummary {
  ipAddresses: string[];
  domains: string[];
  urls: string[];
  emailAddresses: string[];
  hashes: string[];
}

export interface AttackGraphNode {
  id: string;
  label: string;
  sublabel: string;
  type: 'email' | 'domain' | 'ip' | 'page' | 'action';
  status: 'critical' | 'warning' | 'clean' | 'neutral';
}

export interface AttackGraphEdge {
  from: string;
  to: string;
  label?: string;
}

export interface InvestigationData {
  id: string; // e.g. "EML-2026-00421"
  subject: string;
  from: string;
  to: string;
  receivedDate: string;
  threatScore: number; // 0-100
  threatLevel: 'CRITICAL' | 'HIGH' | 'SUSPICIOUS' | 'LOW' | 'CLEAN';
  threatType: string; // e.g. "PHISHING", "BEC FRAUD"
  confidence: number; // e.g. 94.7
  authStatus: 'FAILED' | 'PASSED' | 'PARTIAL';
  
  // Threat Breakdown (0-100)
  breakdown: {
    headerAnomalies: number;
    authentication: number;
    urlRisk: number;
    contentNlp: number;
    senderReputation: number;
  };

  // Why is this suspicious reasons
  suspiciousReasons: string[];

  // Sub-modules
  headerHops: IpHopIntelligence[];
  authentication: AuthStatus;
  urls: ExtractedUrl[];
  contentAi: ContentAiAnalysis;
  iocs: IocSummary;
  attackGraph: {
    nodes: AttackGraphNode[];
    edges: AttackGraphEdge[];
  };

  rawHeaders?: string;
  rawBody?: string;
}

export interface CommunityThreatEntry {
  id: string;
  senderEmail: string;
  subject: string;
  threatType: string;
  severity: 'LOW' | 'MEDIUM' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
  originCountry: string;
  originIp: string;
  flaggedCount: number;
  firstSeen: string;
  lastReported: string;
}
