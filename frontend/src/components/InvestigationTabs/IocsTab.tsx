import React, { useState } from 'react';
import { InvestigationData } from '../../types/threat';

interface IocsTabProps {
  data: InvestigationData;
}

export const IocsTab: React.FC<IocsTabProps> = ({ data }) => {
  const [copied, setCopied] = useState(false);
  const [added, setAdded] = useState(false);
  const [selectedIoc, setSelectedIoc] = useState<string | null>(null);
  const iocs = data.iocs;

  const handleExport = () => {
    const jsonStr = JSON.stringify(iocs, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IOCs-${data.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopy = () => {
    const text = `IP ADDRESSES:\n${iocs.ipAddresses.join('\n')}\n\nDOMAINS:\n${iocs.domains.join('\n')}\n\nURLS:\n${iocs.urls.join('\n')}\n\nEMAILS:\n${iocs.emailAddresses.join('\n')}\n\nHASHES:\n${iocs.hashes.join('\n')}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="forensic-subcard full-width font-mono">
      <div className="subcard-title-bar">
        <span className="subcard-title">INDICATORS OF COMPROMISE</span>
        <div className="ioc-action-buttons">
          <button className="btn-minimal-action" onClick={handleCopy}>
            {copied ? '✓ Copied' : '[ Copy IOCs ]'}
          </button>
          <button className="btn-minimal-action" onClick={handleExport}>
            [ Export IOCs ]
          </button>
          <button 
            className="btn-minimal-action"
            onClick={() => {
              setAdded(true);
              setTimeout(() => setAdded(false), 2000);
            }}
          >
            {added ? '✓ Added' : '[ Add to Case ]'}
          </button>
        </div>
      </div>

      {/* Summary KPI count row */}
      <div className="ioc-counters-grid">
        <div className="ioc-counter-box">
          <span className="counter-label">IP ADDRESSES</span>
          <span className="counter-val">{iocs.ipAddresses.length}</span>
        </div>
        <div className="ioc-counter-box">
          <span className="counter-label">DOMAINS</span>
          <span className="counter-val">{iocs.domains.length}</span>
        </div>
        <div className="ioc-counter-box">
          <span className="counter-label">URLs</span>
          <span className="counter-val">{iocs.urls.length}</span>
        </div>
        <div className="ioc-counter-box">
          <span className="counter-label">EMAIL ADDRESSES</span>
          <span className="counter-val">{iocs.emailAddresses.length}</span>
        </div>
        <div className="ioc-counter-box">
          <span className="counter-label">HASHES</span>
          <span className="counter-val">{iocs.hashes.length}</span>
        </div>
      </div>

      {selectedIoc && (
        <div className="action-callout-box">
          <div className="callout-header">IOC INTELLIGENCE: {selectedIoc}</div>
          <div className="callout-desc">
            Type: Flagged Ingress Vector • Public Blacklist: True • Related Incident Clusters: 4 • Status: Blocked
          </div>
        </div>
      )}

      {/* Raw Lists */}
      <div className="ioc-tables-grid">
        <div className="ioc-section-card">
          <div className="ioc-sec-header">IP Addresses</div>
          <ul className="ioc-list">
            {iocs.ipAddresses.map((ip, idx) => (
              <li 
                key={idx} 
                className="ioc-row cursor-pointer hover:underline"
                onClick={() => setSelectedIoc(ip)}
              >
                <span>{ip}</span>
                <span className="ioc-tag red">[MALICIOUS]</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="ioc-section-card">
          <div className="ioc-sec-header">Domains</div>
          <ul className="ioc-list">
            {iocs.domains.map((dom, idx) => (
              <li 
                key={idx} 
                className="ioc-row cursor-pointer hover:underline"
                onClick={() => setSelectedIoc(dom)}
              >
                <span>{dom}</span>
                <span className="ioc-tag amber">[TYPOSQUAT]</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="ioc-section-card">
          <div className="ioc-sec-header">URLs</div>
          <ul className="ioc-list">
            {iocs.urls.map((u, idx) => (
              <li 
                key={idx} 
                className="ioc-row cursor-pointer hover:underline"
                onClick={() => setSelectedIoc(u)}
              >
                <span className="truncate-text">{u}</span>
                <span className="ioc-tag red">[PHISH]</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="ioc-section-card">
          <div className="ioc-sec-header">Emails & Signatures</div>
          <ul className="ioc-list">
            {iocs.emailAddresses.map((em, idx) => (
              <li 
                key={idx} 
                className="ioc-row cursor-pointer hover:underline"
                onClick={() => setSelectedIoc(em)}
              >
                <span>{em}</span>
                <span className="ioc-tag purple">[SENDER]</span>
              </li>
            ))}
            {iocs.hashes.map((h, idx) => (
              <li 
                key={idx} 
                className="ioc-row cursor-pointer hover:underline"
                onClick={() => setSelectedIoc(h)}
              >
                <span className="truncate-text">{h}</span>
                <span className="ioc-tag blue">[SHA256]</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
