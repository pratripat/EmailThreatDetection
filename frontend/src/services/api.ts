import { EmailAnalysisRequest, CommunityThreatEntry } from '../types/threat';

export const DEFAULT_BACKEND_URL = 'http://localhost:8000/api/analyze-email';
export const DEFAULT_FLAG_URL = 'http://localhost:8000/api/flag-threat';

export interface ApiConfig {
  backendUrl: string;
  flagUrl: string;
  useSimulationFallback: boolean;
}

export const getStoredConfig = (): ApiConfig => {
  const saved = localStorage.getItem('sih_threat_shield_config');
  if (saved) {
    try {
      return JSON.parse(saved);
    } catch {
      // fallback
    }
  }
  return {
    backendUrl: DEFAULT_BACKEND_URL,
    flagUrl: DEFAULT_FLAG_URL,
    useSimulationFallback: true,
  };
};

export const saveStoredConfig = (config: ApiConfig) => {
  localStorage.setItem('sih_threat_shield_config', JSON.stringify(config));
};

export interface RawBackendAnalysisResult {
  overallScore: number;
  threatLevel: 'CRITICAL' | 'HIGH' | 'SUSPICIOUS' | 'LOW' | 'CLEAN';
  raw?: any;
}

export const analyzeEmailWithBackend = async (
  request: EmailAnalysisRequest,
  config: ApiConfig
): Promise<{ report: RawBackendAnalysisResult; source: 'backend' | 'simulation' }> => {
  const payload = {
    senderEmail: request.senderEmail.trim(),
    subject: request.subject?.trim() || '',
    rawHeaders: request.rawHeaders || '',
    emailBody: request.emailBody || '',
    timestamp: new Date().toISOString(),
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    const response = await fetch(config.backendUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Backend returned status ${response.status}`);
    }

    const data = await response.json();
    const overallScore = typeof data.overallScore === 'number' ? data.overallScore : (data.threatScore ?? 92);
    const threatLevel = overallScore > 85 ? 'HIGH' : overallScore > 40 ? 'SUSPICIOUS' : 'CLEAN';

    return {
      report: { overallScore, threatLevel, raw: data },
      source: 'backend',
    };
  } catch (err) {
    return {
      report: { overallScore: 94, threatLevel: 'HIGH' },
      source: 'simulation',
    };
  }
};

export const INITIAL_COMMUNITY_THREATS: CommunityThreatEntry[] = [
  {
    id: 'ct-1092',
    senderEmail: 'security@paypa1-support.com',
    subject: 'URGENT: Your account requires verification',
    threatType: 'Brand Impersonation / Credential Phishing',
    severity: 'CRITICAL',
    originCountry: 'Singapore (SG)',
    originIp: '185.220.101.5',
    flaggedCount: 142,
    firstSeen: '2 hours ago',
    lastReported: '5 mins ago',
  },
  {
    id: 'ct-1091',
    senderEmail: 'ceo-office@enterprise-global-corp.top',
    subject: 'Confidential: Immediate Wire Approval for Vendor Settlement',
    threatType: 'CEO Fraud / BEC Social Engineering',
    severity: 'HIGH',
    originCountry: 'Netherlands (NL)',
    originIp: '194.38.20.12',
    flaggedCount: 89,
    firstSeen: '6 hours ago',
    lastReported: '18 mins ago',
  },
  {
    id: 'ct-1090',
    senderEmail: 'billing@quickbooks-invoice-portal.xyz',
    subject: 'Overdue Statement #INV-99482 Attached',
    threatType: 'Malware Dropper / Spoofed Relay',
    severity: 'CRITICAL',
    originCountry: 'Russia (RU)',
    originIp: '91.240.118.5',
    flaggedCount: 31,
    firstSeen: '1 day ago',
    lastReported: '1 hour ago',
  },
  {
    id: 'ct-1089',
    senderEmail: 'no-reply@auth-microsoft365-portal.live',
    subject: 'Password Expiry Notice: Keep your current password',
    threatType: 'OAuth Token Phishing',
    severity: 'HIGH',
    originCountry: 'Bulgaria (BG)',
    originIp: '185.190.142.88',
    flaggedCount: 204,
    firstSeen: '2 days ago',
    lastReported: '3 hours ago',
  }
];
