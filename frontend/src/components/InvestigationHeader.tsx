import React from 'react';
import { InvestigationData } from '../types/threat';

export type InvestigationTab = 
  | 'overview' 
  | 'header_forensics' 
  | 'urls' 
  | 'authentication' 
  | 'attack_graph' 
  | 'content_ai' 
  | 'iocs';

interface InvestigationHeaderProps {
  data: InvestigationData;
  activeTab: InvestigationTab;
  onSelectTab: (tab: InvestigationTab) => void;
  onGenerateReport: () => void;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({
  data,
  activeTab,
  onSelectTab,
  onGenerateReport,
}) => {
  const isHighRisk = data.threatLevel === 'HIGH' || data.threatLevel === 'CRITICAL';
  const isClean = data.threatLevel === 'CLEAN';

  return (
    <div className="investigation-header-panel">
      {/* Case Meta Bar */}
      <div className="case-meta-bar">
        <span className="case-id-badge font-mono">
          INVESTIGATION #{data.id}
        </span>
        <button 
          className="btn-report-quick"
          onClick={onGenerateReport}
        >
          Generate Forensic Report →
        </button>
      </div>

      {/* Metadata & Risk Score Box */}
      <div className="email-meta-banner-grid">
        <div className="email-details-box">
          <div className="meta-line">
            <span className="meta-label">Subject:</span>
            <span className="meta-value font-mono text-white">{data.subject}</span>
          </div>

          <div className="meta-line">
            <span className="meta-label">From:</span>
            <span className="meta-value font-mono text-red">{data.from}</span>
          </div>

          <div className="meta-line">
            <span className="meta-label">Received:</span>
            <span className="meta-value font-mono text-muted">{data.receivedDate}</span>
          </div>
        </div>

        {/* Big Minimal Risk Score Card */}
        <div className={`risk-score-box ${isHighRisk ? 'risk-high' : isClean ? 'risk-clean' : 'risk-medium'}`}>
          <div className="risk-level-title">
            {isHighRisk ? 'HIGH RISK — PHISHING' : isClean ? 'VERIFIED — BENIGN' : 'SUSPICIOUS ORIGIN'}
          </div>
          <div className="risk-score-large font-mono">
            <span className="score-val">{data.threatScore}</span>
            <span className="score-divider"> / </span>
            <span className="score-base">100</span>
          </div>
        </div>
      </div>

      {/* Forensic Tabs */}
      <div className="forensic-tabs-strip">
        <button
          className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => onSelectTab('overview')}
        >
          [ Overview ]
        </button>

        <button
          className={`tab-btn ${activeTab === 'header_forensics' ? 'active' : ''}`}
          onClick={() => onSelectTab('header_forensics')}
        >
          [ Header Forensics ]
        </button>

        <button
          className={`tab-btn ${activeTab === 'urls' ? 'active' : ''}`}
          onClick={() => onSelectTab('urls')}
        >
          [ URLs ]
        </button>

        <button
          className={`tab-btn ${activeTab === 'authentication' ? 'active' : ''}`}
          onClick={() => onSelectTab('authentication')}
        >
          [ Authentication ]
        </button>

        <button
          className={`tab-btn ${activeTab === 'attack_graph' ? 'active' : ''}`}
          onClick={() => onSelectTab('attack_graph')}
        >
          [ Origin ]
        </button>

        <button
          className={`tab-btn ${activeTab === 'content_ai' ? 'active' : ''}`}
          onClick={() => onSelectTab('content_ai')}
        >
          [ Content AI ]
        </button>

        <button
          className={`tab-btn ${activeTab === 'iocs' ? 'active' : ''}`}
          onClick={() => onSelectTab('iocs')}
        >
          [ IOCs ]
        </button>
      </div>
    </div>
  );
};
