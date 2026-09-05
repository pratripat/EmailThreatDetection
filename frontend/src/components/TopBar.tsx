import React from 'react';

interface TopBarProps {
  onOpenAnalyzeModal: () => void;
  onOpenSettings: () => void;
  lastScanTime: string;
  caseId: string;
}

export const TopBar: React.FC<TopBarProps> = ({
  onOpenAnalyzeModal,
  onOpenSettings,
  lastScanTime,
  caseId,
}) => {
  return (
    <header className="topbar">
      <div className="topbar-left">
        <span className="topbar-title">
          <span className="brand-hibp-prefix">';--</span>have i been phished?
        </span>
        <span className="topbar-divider">/</span>
        <span className="topbar-case font-mono">{caseId}</span>
      </div>

      <div className="topbar-right">
        <span className="last-scan-pill font-mono">Last scan: {lastScanTime}</span>
        <button 
          className="btn-primary-action"
          onClick={onOpenAnalyzeModal}
        >
          + Analyze New Email
        </button>
        <button 
          className="btn-secondary-action"
          onClick={onOpenSettings}
          title="Engine Configuration"
        >
          ⚙ Settings
        </button>
      </div>
    </header>
  );
};
