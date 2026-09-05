import React from 'react';
import { InvestigationData } from '../types/threat';

interface DashboardCaseCardProps {
  data: InvestigationData;
  onOpenForensicWorkspace: () => void;
  onGenerateReport: () => void;
}

export const DashboardCaseCard: React.FC<DashboardCaseCardProps> = ({
  data,
  onOpenForensicWorkspace,
  onGenerateReport,
}) => {
  const isHighRisk = data.threatLevel === 'HIGH' || data.threatLevel === 'CRITICAL';
  const isClean = data.threatLevel === 'CLEAN';

  return (
    <div className="dashboard-case-card font-mono">
      {/* Top Header */}
      <div className="case-card-header">
        <div className="case-header-left">
          <span className="case-id-tag">CURRENT INCIDENT #{data.id}</span>
          <span className="case-received-time">{data.receivedDate}</span>
        </div>
        <div className="case-header-actions">
          <button className="btn-minimal-action" onClick={onGenerateReport}>
            [ Generate Report ]
          </button>
        </div>
      </div>

      {/* Main Email & Verdict Grid */}
      <div className="case-card-body">
        <div className="case-meta-group">
          <div className="meta-row">
            <span className="meta-k">Subject:</span>
            <span className="meta-v text-white font-sans">{data.subject}</span>
          </div>

          <div className="meta-row">
            <span className="meta-k">Sender:</span>
            <span className="meta-v text-red">{data.from}</span>
          </div>

          <div className="meta-row">
            <span className="meta-k">Recipient:</span>
            <span className="meta-v text-muted">{data.to}</span>
          </div>

          {/* Quick Signals Checklist */}
          <div className="case-signals-list">
            <div className="signals-title">DETECTED ANOMALIES:</div>
            {data.suspiciousReasons.slice(0, 3).map((reason, idx) => (
              <div key={idx} className="signal-item">
                <span className="text-amber">⚠️</span>
                <span className="text-muted">{reason}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Big Verdict Callout */}
        <div className={`case-verdict-box ${isHighRisk ? 'verdict-high' : isClean ? 'verdict-clean' : 'verdict-warning'}`}>
          <div className="verdict-label">
            {isHighRisk ? 'Oh no — pwned!' : isClean ? 'Good news — no threat!' : 'Warning — suspicious!'}
          </div>
          <div className="verdict-number">
            <span className="score-big">{data.threatScore}</span>
            <span className="score-base"> / 100</span>
          </div>
          <div className="verdict-subtext">Threat Probability: {data.confidence}%</div>
        </div>
      </div>

      {/* Action Footer: The killer button to launch full-screen forensic workspace */}
      <div className="case-card-footer">
        <span className="footer-hint text-muted">
          Reconstructed Received route hops, DKIM/SPF alignment, URL crawler sandbox, and NLP intent models available in forensics mode.
        </span>
        <button 
          className="btn-open-forensics"
          onClick={onOpenForensicWorkspace}
        >
          Inspect Forensic Analysis (7 Modules) →
        </button>
      </div>
    </div>
  );
};
