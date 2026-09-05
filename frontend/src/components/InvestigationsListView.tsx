import React from 'react';
import { Layers } from 'lucide-react';
import { InvestigationData } from '../types/threat';

interface InvestigationsListViewProps {
  currentInvestigation: InvestigationData;
  onSelectCase: (caseData: InvestigationData) => void;
}

export const InvestigationsListView: React.FC<InvestigationsListViewProps> = ({
  currentInvestigation,
}) => {
  return (
    <div className="forensic-subcard full-width">
      <div className="subcard-title-bar">
        <div className="flex items-center gap-2">
          <Layers size={16} className="text-cyan" />
          <span className="subcard-title">FORENSIC INVESTIGATIONS ARCHIVE</span>
        </div>
      </div>

      <div className="ioc-registry-table-wrapper">
        <table className="minimal-table font-mono">
          <thead>
            <tr>
              <th>CASE ID</th>
              <th>SUBJECT / TARGET</th>
              <th>FROM SENDER</th>
              <th>THREAT VERDICT</th>
              <th>CONFIDENCE</th>
              <th>DATE INGESTED</th>
              <th>STATUS</th>
            </tr>
          </thead>
          <tbody>
            {/* Current Active Case */}
            <tr className="active-case-row">
              <td className="font-bold text-cyan">#{currentInvestigation.id}</td>
              <td className="text-white font-sans">{currentInvestigation.subject}</td>
              <td className="text-red">{currentInvestigation.from}</td>
              <td>
                <span className={`ioc-severity-pill ${currentInvestigation.threatLevel.toLowerCase()}`}>
                  {currentInvestigation.threatLevel} ({currentInvestigation.threatScore}/100)
                </span>
              </td>
              <td>{currentInvestigation.confidence}%</td>
              <td className="text-muted">{currentInvestigation.receivedDate}</td>
              <td>
                <span className="status-live-badge">INVESTIGATING</span>
              </td>
            </tr>

            {/* Archive Sample Cases */}
            <tr>
              <td className="text-muted">#EML-2026-00392</td>
              <td className="text-muted font-sans">Confidential: Immediate Wire Approval for Vendor Settlement</td>
              <td className="text-muted">ceo-office@enterprise-global-corp.top</td>
              <td>
                <span className="ioc-severity-pill high">HIGH (91/100)</span>
              </td>
              <td className="text-muted">94.1%</td>
              <td className="text-muted">04 Sep 2026</td>
              <td>
                <span className="status-closed-badge">QUARANTINED</span>
              </td>
            </tr>

            <tr>
              <td className="text-muted">#EML-2026-00388</td>
              <td className="text-muted font-sans">[GitHub] Security advisory notice for repository dependencies</td>
              <td className="text-muted">notifications@github.com</td>
              <td>
                <span className="ioc-severity-pill clean">CLEAN (4/100)</span>
              </td>
              <td className="text-muted">99.2%</td>
              <td className="text-muted">03 Sep 2026</td>
              <td>
                <span className="status-closed-badge">CLEARED</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
};
