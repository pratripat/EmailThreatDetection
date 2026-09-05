import React from 'react';
import { InvestigationData } from '../types/threat';

interface KpiCardsProps {
  data: InvestigationData;
}

export const KpiCards: React.FC<KpiCardsProps> = ({ data }) => {
  const isHighThreat = data.threatLevel === 'HIGH' || data.threatLevel === 'CRITICAL';
  const isClean = data.threatLevel === 'CLEAN';

  const totalIocs = 
    data.iocs.ipAddresses.length +
    data.iocs.domains.length +
    data.iocs.urls.length +
    data.iocs.emailAddresses.length +
    data.iocs.hashes.length;

  return (
    <div className="kpi-grid">
      {/* 1. Threat */}
      <div className="kpi-card">
        <div className="kpi-label">THREAT</div>
        <div className={`kpi-value ${isHighThreat ? 'text-red' : isClean ? 'text-green' : 'text-amber'}`}>
          {data.threatLevel}
        </div>
        <div className="kpi-subtext">{data.threatType}</div>
      </div>

      {/* 2. Confidence */}
      <div className="kpi-card">
        <div className="kpi-label">CONFIDENCE</div>
        <div className="kpi-value text-white">{data.confidence}%</div>
        <div className="kpi-subtext">NLP Model</div>
      </div>

      {/* 3. IOCs Found */}
      <div className="kpi-card">
        <div className="kpi-label">IOCs FOUND</div>
        <div className="kpi-value text-white">{totalIocs}</div>
        <div className="kpi-subtext">Correlated Signals</div>
      </div>

      {/* 4. Auth Status */}
      <div className="kpi-card">
        <div className="kpi-label">AUTH STATUS</div>
        <div className={`kpi-value ${data.authStatus === 'FAILED' ? 'text-red' : 'text-green'}`}>
          {data.authStatus}
        </div>
        <div className="kpi-subtext">SPF / DKIM / DMARC</div>
      </div>
    </div>
  );
};
