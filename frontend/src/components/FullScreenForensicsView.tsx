import React from 'react';
import { InvestigationData } from '../types/threat';
import { InvestigationTab } from './InvestigationHeader';
import { OverviewTab } from './InvestigationTabs/OverviewTab';
import { HeaderForensicsTab } from './InvestigationTabs/HeaderForensicsTab';
import { UrlsTab } from './InvestigationTabs/UrlsTab';
import { AuthenticationTab } from './InvestigationTabs/AuthenticationTab';
import { OriginAttackGraphTab } from './InvestigationTabs/OriginAttackGraphTab';
import { ContentAiTab } from './InvestigationTabs/ContentAiTab';
import { IocsTab } from './InvestigationTabs/IocsTab';

interface FullScreenForensicsViewProps {
  data: InvestigationData;
  activeTab: InvestigationTab;
  onSelectTab: (tab: InvestigationTab) => void;
  onBackToDashboard: () => void;
  onGenerateReport: () => void;
}

export const FullScreenForensicsView: React.FC<FullScreenForensicsViewProps> = ({
  data,
  activeTab,
  onSelectTab,
  onBackToDashboard,
  onGenerateReport,
}) => {
  return (
    <div className="fullscreen-forensics-view font-mono">
      {/* Top Bar with Back Button & Case Details */}
      <div className="forensics-top-nav">
        <div className="forensics-nav-left">
          <button 
            className="btn-back-dashboard"
            onClick={onBackToDashboard}
          >
            ← Back to Dashboard
          </button>
          <span className="nav-sep">/</span>
          <span className="text-white font-bold">CASE #{data.id}</span>
          <span className="nav-sep">/</span>
          <span className="text-muted font-sans truncate-text max-w-md">{data.subject}</span>
        </div>

        <div className="forensics-nav-right">
          <span className="text-red font-bold">[{data.threatLevel} · {data.threatScore}/100]</span>
          <button className="btn-minimal-action" onClick={onGenerateReport}>
            [ Generate Report ]
          </button>
        </div>
      </div>

      {/* The 7 Forensic Tabs Strip taking full width */}
      <div className="forensics-full-tabs-strip">
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
          [ URLs ({data.urls.length}) ]
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
          [ IOCs ({data.iocs.ipAddresses.length + data.iocs.domains.length}) ]
        </button>
      </div>

      {/* Forensic Module Body */}
      <div className="forensics-full-body">
        {activeTab === 'overview' && <OverviewTab data={data} />}
        {activeTab === 'header_forensics' && <HeaderForensicsTab data={data} />}
        {activeTab === 'urls' && <UrlsTab data={data} />}
        {activeTab === 'authentication' && <AuthenticationTab data={data} />}
        {activeTab === 'attack_graph' && <OriginAttackGraphTab data={data} />}
        {activeTab === 'content_ai' && <ContentAiTab data={data} />}
        {activeTab === 'iocs' && <IocsTab data={data} />}
      </div>
    </div>
  );
};
