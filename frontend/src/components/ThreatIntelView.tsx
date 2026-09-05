import React, { useState } from 'react';
import { Radio, Search, ChevronRight } from 'lucide-react';
import { CommunityThreatEntry } from '../types/threat';

interface ThreatIntelViewProps {
  threats: CommunityThreatEntry[];
  onSelectThreat: (threat: CommunityThreatEntry) => void;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({
  threats,
  onSelectThreat,
}) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filtered = threats.filter((t) =>
    t.senderEmail.toLowerCase().includes(searchTerm.toLowerCase()) ||
    t.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
    t.originIp.includes(searchTerm) ||
    t.threatType.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="forensic-subcard full-width">
      <div className="subcard-title-bar">
        <div className="flex items-center gap-2">
          <Radio size={16} className="text-red" />
          <span className="subcard-title">COLLABORATIVE THREAT INTELLIGENCE FEED</span>
        </div>

        <div className="search-box-minimal">
          <Search size={14} className="text-muted" />
          <input
            type="text"
            placeholder="Search collaborative threat signatures..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input-clean"
          />
        </div>
      </div>

      <p className="subcard-hint">
        Real-time telemetry synchronized across enterprise security nodes. Flagged vectors automatically update firewall perimeter IOCs.
      </p>

      <div className="ioc-registry-table-wrapper">
        <table className="minimal-table">
          <thead>
            <tr>
              <th>FLAGGED SENDER & SUBJECT</th>
              <th>CLASSIFICATION</th>
              <th>ORIGIN TELEMETRY</th>
              <th>COMMUNITY FLAGS</th>
              <th>LAST SEEN</th>
              <th>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="font-mono font-bold text-white">{item.senderEmail}</div>
                  <div className="text-xs text-muted truncate-text">{item.subject}</div>
                </td>
                <td>
                  <span className={`ioc-severity-pill ${item.severity.toLowerCase()}`}>
                    {item.severity}
                  </span>
                  <div className="text-xs text-muted mt-1">{item.threatType}</div>
                </td>
                <td className="font-mono text-xs">
                  <div>📍 {item.originCountry}</div>
                  <div className="text-muted">{item.originIp}</div>
                </td>
                <td>
                  <span className="flag-count-badge font-mono">{item.flaggedCount} reports</span>
                </td>
                <td className="text-xs text-muted font-mono">{item.lastReported}</td>
                <td>
                  <button 
                    className="btn-inspect-mini"
                    onClick={() => onSelectThreat(item)}
                  >
                    <span>Investigate</span>
                    <ChevronRight size={13} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
