import React from 'react';
import { InvestigationData } from '../../types/threat';

interface UrlsTabProps {
  data: InvestigationData;
}

export const UrlsTab: React.FC<UrlsTabProps> = ({ data }) => {
  return (
    <div className="forensic-subcard full-width">
      <div className="subcard-title-bar">
        <span className="subcard-title">SUSPICIOUS URLS</span>
        <span className="subcard-badge font-mono">[{data.urls.length} EXTRACTED]</span>
      </div>

      {data.urls.length === 0 ? (
        <div className="text-muted font-mono">No external hyperlinks found in this email.</div>
      ) : (
        <div className="urls-grid font-mono">
          {data.urls.map((u, idx) => (
            <div key={idx} className="url-forensic-card">
              <div className="url-card-header">
                <span className="url-target font-bold text-white truncate-text">{u.url}</span>
                <span className="url-score-pill">Score: {u.threatScore}/100</span>
              </div>

              <div className="url-meta-grid">
                <div className="meta-col">
                  <span className="meta-col-label">Domain:</span>
                  <span className="text-white">{u.domain}</span>
                </div>

                <div className="meta-col">
                  <span className="meta-col-label">Age:</span>
                  <span className="text-amber">{u.registeredAgeDays} days</span>
                </div>

                <div className="meta-col">
                  <span className="meta-col-label">Reputation:</span>
                  <span className={
                    u.reputation === 'MALICIOUS' ? 'text-red font-bold' :
                    u.reputation === 'SUSPICIOUS' ? 'text-amber font-bold' :
                    u.reputation === 'SAFE' ? 'text-green' : 'text-muted'
                  }>
                    {u.reputation}
                  </span>
                </div>
              </div>

              {u.grok_analysis && (
                <div className="redirect-chain-box">
                  <div className="flex justify-between items-center mb-1">
                    <span className="chain-title">Grok AI Forensics:</span>
                    <span className={u.grok_analysis.verdict === 'BENIGN' ? 'text-green font-bold' : 'text-red font-bold'}>
                      [{u.grok_analysis.verdict} &bull; {(u.grok_analysis.confidence * 100).toFixed(0)}%]
                    </span>
                  </div>
                  {u.grok_analysis.reason && (
                    <div className="text-muted text-xs">
                      {u.grok_analysis.reason}
                    </div>
                  )}
                </div>
              )}

              {u.redirectChain && u.redirectChain.length > 1 && (
                <div className="redirect-chain-box">
                  <span className="chain-title">Redirects:</span>
                  <div className="chain-hops">
                    {u.redirectChain.join(' → ')}
                  </div>
                </div>
              )}

              <div className="url-flags-row">
                {u.flags.map((flag, fIdx) => (
                  <span key={fIdx} className="url-flag-tag">
                    ⚠️ {flag}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
