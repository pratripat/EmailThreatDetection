import React from 'react';
import { Shield, Wifi, WifiOff, Settings, Database, Activity } from 'lucide-react';
import { ApiConfig } from '../services/api';

interface HeaderProps {
  config: ApiConfig;
  onOpenSettings: () => void;
  isBackendConnected: boolean | null;
  activeTab: 'scanner' | 'intelligence' | 'routes';
  setActiveTab: (tab: 'scanner' | 'intelligence' | 'routes') => void;
  threatCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  config,
  onOpenSettings,
  isBackendConnected,
  activeTab,
  setActiveTab,
  threatCount,
}) => {
  return (
    <header className="app-header">
      <div className="header-container">
        {/* Brand identity */}
        <div className="brand-section">
          <div className="brand-icon-wrapper">
            <Shield className="brand-icon" />
            <div className="brand-pulse" />
          </div>
          <div>
            <div className="brand-title-row">
              <h1 className="brand-title">AegisMail</h1>
              <span className="brand-badge">THREAT INTEL</span>
            </div>
            <p className="brand-subtitle">Collaborative Email Threat & Spoofing Defense System</p>
          </div>
        </div>

        {/* Navigation tabs */}
        <nav className="header-nav">
          <button
            className={`nav-tab ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            <Activity size={16} />
            <span>Email Inspector</span>
          </button>
          <button
            className={`nav-tab ${activeTab === 'intelligence' ? 'active' : ''}`}
            onClick={() => setActiveTab('intelligence')}
          >
            <Database size={16} />
            <span>Threat Intelligence DB</span>
            <span className="count-pill">{threatCount}</span>
          </button>
        </nav>

        {/* Connection & Configuration Actions */}
        <div className="header-actions">
          <div 
            className={`connection-status ${
              isBackendConnected === true
                ? 'connected'
                : isBackendConnected === false
                ? 'disconnected'
                : 'testing'
            }`}
            title={`Backend: ${config.backendUrl} (${config.useSimulationFallback ? 'Fallback enabled' : 'Strict mode'})`}
          >
            {isBackendConnected === true ? (
              <>
                <Wifi size={14} className="status-icon connected" />
                <span className="status-label">Backend Connected</span>
              </>
            ) : isBackendConnected === false ? (
              <>
                <WifiOff size={14} className="status-icon disconnected" />
                <span className="status-label">
                  {config.useSimulationFallback ? 'Simulated Engine' : 'Backend Offline'}
                </span>
              </>
            ) : (
              <>
                <Activity size={14} className="status-icon animate-spin" />
                <span className="status-label">Checking API...</span>
              </>
            )}
          </div>

          <button 
            className="settings-button"
            onClick={onOpenSettings}
            title="Backend Settings & API Config"
          >
            <Settings size={18} />
          </button>
        </div>
      </div>
    </header>
  );
};
