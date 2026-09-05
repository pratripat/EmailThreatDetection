import React from 'react';

export type NavSection = 'dashboard' | 'investigations' | 'threat_intel' | 'ioc_database' | 'reports';

interface SidebarProps {
  activeSection: NavSection;
  onSelectSection: (section: NavSection) => void;
  isBackendConnected: boolean | null;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeSection,
  onSelectSection,
  isBackendConnected,
}) => {
  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="brand-name">
          <span className="brand-hibp-prefix">';--</span>SENTINEL
        </div>
        <div className="brand-tag">Email Threat Intelligence</div>
      </div>

      {/* Nav */}
      <nav className="sidebar-nav">
        <button
          className={`sidebar-nav-item ${activeSection === 'dashboard' ? 'active' : ''}`}
          onClick={() => onSelectSection('dashboard')}
        >
          <span>Dashboard</span>
        </button>

        <button
          className={`sidebar-nav-item ${activeSection === 'investigations' ? 'active' : ''}`}
          onClick={() => onSelectSection('investigations')}
        >
          <span>Investigations</span>
          <span className="nav-badge">NEW</span>
        </button>

        <button
          className={`sidebar-nav-item ${activeSection === 'threat_intel' ? 'active' : ''}`}
          onClick={() => onSelectSection('threat_intel')}
        >
          <span>Threat Intel</span>
        </button>

        <button
          className={`sidebar-nav-item ${activeSection === 'ioc_database' ? 'active' : ''}`}
          onClick={() => onSelectSection('ioc_database')}
        >
          <span>IOC Database</span>
          <span className="nav-counter">1,482</span>
        </button>

        <button
          className={`sidebar-nav-item ${activeSection === 'reports' ? 'active' : ''}`}
          onClick={() => onSelectSection('reports')}
        >
          <span>Reports</span>
        </button>
      </nav>

      {/* System Status */}
      <div className="sidebar-status-panel">
        <div className="status-panel-title">System Status</div>
        <div className="status-row">
          <span className={`status-dot ${isBackendConnected ? 'online' : 'simulated'}`} />
          <span className="status-name">API Online</span>
        </div>
        <div className="status-row">
          <span className="status-dot online" />
          <span className="status-name">ML Engine</span>
        </div>
        <div className="status-row">
          <span className="status-dot online" />
          <span className="status-name">Threat Intel</span>
        </div>
      </div>
    </aside>
  );
};
