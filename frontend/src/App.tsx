import React, { useState, useEffect } from 'react';
import { Sidebar, NavSection } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { KpiCards } from './components/KpiCards';
import { DashboardCaseCard } from './components/DashboardCaseCard';
import { FullScreenForensicsView } from './components/FullScreenForensicsView';
import { InvestigationTab } from './components/InvestigationHeader';
import { AnalyzeEmailModal } from './components/AnalyzeEmailModal';
import { ForensicReportModal } from './components/ForensicReportModal';
import { IocDatabaseView } from './components/IocDatabaseView';
import { ThreatIntelView } from './components/ThreatIntelView';
import { BackendSettingsModal } from './components/BackendSettingsModal';

import { 
  InvestigationData, 
  EmailAnalysisRequest, 
  CommunityThreatEntry 
} from './types/threat';
import { 
  DEFAULT_INVESTIGATION, 
  createInvestigationFromInput 
} from './services/forensicsData';
import { 
  getStoredConfig, 
  analyzeEmailWithBackend, 
  INITIAL_COMMUNITY_THREATS, 
  ApiConfig 
} from './services/api';

export const App: React.FC = () => {
  // Navigation & View state
  const [activeSection, setActiveSection] = useState<NavSection>('dashboard');
  const [activeForensicTab, setActiveForensicTab] = useState<InvestigationTab>('overview');

  // Active Investigation Data
  const [currentInvestigation, setCurrentInvestigation] = useState<InvestigationData>(DEFAULT_INVESTIGATION);
  const [lastScanTime, setLastScanTime] = useState('2 min ago');

  // Modals
  const [isAnalyzeModalOpen, setIsAnalyzeModalOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  // Backend & Settings
  const [config, setConfig] = useState<ApiConfig>(getStoredConfig());
  const [isBackendConnected, setIsBackendConnected] = useState<boolean | null>(null);
  const [communityThreats] = useState<CommunityThreatEntry[]>(INITIAL_COMMUNITY_THREATS);

  // Probe backend status
  const checkBackendHealth = async (): Promise<boolean> => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(config.backendUrl, { method: 'OPTIONS', signal: controller.signal }).catch(() => null);
      clearTimeout(timeoutId);
      const ok = res ? res.ok || res.status < 500 : false;
      setIsBackendConnected(ok);
      return ok;
    } catch {
      setIsBackendConnected(false);
      return false;
    }
  };

  useEffect(() => {
    checkBackendHealth();
  }, [config.backendUrl]);

  // Execute Analysis via Backend
  const handleRunBackendAnalysis = async (req: EmailAnalysisRequest): Promise<InvestigationData> => {
    try {
      const { report, source } = await analyzeEmailWithBackend(req, config);
      if (source === 'backend' && report?.raw) {
        const raw = report.raw;
        const fallback = createInvestigationFromInput(req);
        return {
          ...fallback,
          ...raw,
          id: raw.id || fallback.id,
          threatScore: typeof raw.threatScore === 'number' ? raw.threatScore : (report.overallScore ?? fallback.threatScore),
          threatLevel: raw.threatLevel || report.threatLevel || fallback.threatLevel,
          threatType: raw.threatType || fallback.threatType,
          confidence: typeof raw.confidence === 'number' ? (raw.confidence <= 1 ? +(raw.confidence * 100).toFixed(1) : raw.confidence) : fallback.confidence,
          authStatus: raw.authStatus || fallback.authStatus,
          breakdown: raw.breakdown ? { ...fallback.breakdown, ...raw.breakdown } : fallback.breakdown,
          suspiciousReasons: Array.isArray(raw.suspiciousReasons) && raw.suspiciousReasons.length > 0 ? raw.suspiciousReasons : fallback.suspiciousReasons,
          headerHops: Array.isArray(raw.headerHops) && raw.headerHops.length > 0 ? raw.headerHops : fallback.headerHops,
          authentication: raw.authentication ? { ...fallback.authentication, ...raw.authentication } : fallback.authentication,
          urls: Array.isArray(raw.urls) ? raw.urls : fallback.urls,
          contentAi: raw.contentAi ? { ...fallback.contentAi, ...raw.contentAi } : fallback.contentAi,
          iocs: raw.iocs ? { ...fallback.iocs, ...raw.iocs } : fallback.iocs,
          attackGraph: raw.attackGraph ? { ...fallback.attackGraph, ...raw.attackGraph } : fallback.attackGraph,
          rawHeaders: raw.rawHeaders || req.rawHeaders,
          rawBody: raw.rawBody || req.emailBody,
        };
      }
      return createInvestigationFromInput(req);
    } catch {
      return createInvestigationFromInput(req);
    }
  };

  const handleAnalysisComplete = (newInvestigation: InvestigationData) => {
    setCurrentInvestigation(newInvestigation);
    // After scanning, take user directly to the full-screen forensic workspace!
    setActiveSection('investigations');
    setActiveForensicTab('overview');
    setLastScanTime('Just now');
  };

  const handleSelectThreatFromFeed = (threat: CommunityThreatEntry) => {
    const generated = createInvestigationFromInput({
      senderEmail: threat.senderEmail,
      subject: threat.subject,
    });
    setCurrentInvestigation(generated);
    setActiveSection('investigations');
    setActiveForensicTab('overview');
    setLastScanTime('Just now');
  };

  return (
    <div className="soc-layout">
      {/* 1. Left Sidebar */}
      <Sidebar
        activeSection={activeSection}
        onSelectSection={setActiveSection}
        isBackendConnected={isBackendConnected}
      />

      {/* 2. Main Investigation Workspace */}
      <div className="workspace-wrapper">
        {/* Render TopBar only on non-fullscreen views */}
        {activeSection !== 'investigations' && (
          <TopBar
            onOpenAnalyzeModal={() => setIsAnalyzeModalOpen(true)}
            onOpenSettings={() => setIsSettingsOpen(true)}
            lastScanTime={lastScanTime}
            caseId={`#${currentInvestigation.id}`}
          />
        )}

        <main className={`workspace-main ${activeSection === 'investigations' ? 'workspace-fullscreen' : ''}`}>
          {/* Main Dashboard View: Purely for Threat Assessment Report */}
          {activeSection === 'dashboard' && (
            <div className="dashboard-flow">
              {/* 4 KPI Cards */}
              <KpiCards data={currentInvestigation} />

              {/* Case Summary Report Card */}
              <DashboardCaseCard
                data={currentInvestigation}
                onOpenForensicWorkspace={() => setActiveSection('investigations')}
                onGenerateReport={() => setIsReportModalOpen(true)}
              />
            </div>
          )}

          {/* Dedicated Full-Screen Forensic Investigation Workspace */}
          {activeSection === 'investigations' && (
            <FullScreenForensicsView
              data={currentInvestigation}
              activeTab={activeForensicTab}
              onSelectTab={setActiveForensicTab}
              onBackToDashboard={() => setActiveSection('dashboard')}
              onGenerateReport={() => setIsReportModalOpen(true)}
            />
          )}

          {/* Collaborative Threat Intelligence Feed */}
          {activeSection === 'threat_intel' && (
            <ThreatIntelView
              threats={communityThreats}
              onSelectThreat={handleSelectThreatFromFeed}
            />
          )}

          {/* IOC Database Registry View */}
          {activeSection === 'ioc_database' && (
            <IocDatabaseView />
          )}

          {/* Direct Reports View */}
          {activeSection === 'reports' && (
            <div className="reports-view-panel font-mono">
              <div className="forensic-subcard full-width">
                <div className="subcard-title-bar">
                  <span className="subcard-title">CASE REPORTS GENERATOR</span>
                </div>
                <p className="subcard-hint mb-4">
                  Export ready-to-present technical evidence summaries and incident response documentation for case #{currentInvestigation.id}.
                </p>
                <button 
                  className="btn-primary-action"
                  onClick={() => setIsReportModalOpen(true)}
                >
                  Open Full Forensic Report Modal
                </button>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Analyze New Email Modal */}
      <AnalyzeEmailModal
        isOpen={isAnalyzeModalOpen}
        onClose={() => setIsAnalyzeModalOpen(false)}
        onAnalyzeComplete={handleAnalysisComplete}
        onRunBackendAnalysis={handleRunBackendAnalysis}
      />

      {/* Forensic Report Modal */}
      <ForensicReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        data={currentInvestigation}
      />

      {/* Backend Settings Configuration */}
      <BackendSettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        config={config}
        onUpdateConfig={setConfig}
        onTestConnection={checkBackendHealth}
      />
    </div>
  );
};

export default App;
