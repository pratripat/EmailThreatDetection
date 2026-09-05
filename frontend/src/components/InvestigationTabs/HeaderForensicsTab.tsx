import React, { useState } from 'react';
import { InvestigationData, IpHopIntelligence } from '../../types/threat';

interface HeaderForensicsTabProps {
  data: InvestigationData;
}

export const HeaderForensicsTab: React.FC<HeaderForensicsTabProps> = ({ data }) => {
  const [selectedHop, setSelectedHop] = useState<IpHopIntelligence | null>(data.headerHops[1] || data.headerHops[0]);

  return (
    <div className="tab-pane-grid">
      {/* Left: Received Timeline Chain */}
      <div className="forensic-subcard">
        <div className="subcard-title-bar">
          <span className="subcard-title">Received: chain timeline</span>
        </div>

        <div className="relay-timeline font-mono">
          {data.headerHops.map((hop, index) => {
            const isSelected = selectedHop?.hopNumber === hop.hopNumber;
            const isMalicious = hop.reputation === 'MALICIOUS';

            return (
              <React.Fragment key={hop.hopNumber}>
                <div 
                  className={`timeline-hop-card ${isSelected ? 'selected' : ''}`}
                  onClick={() => setSelectedHop(hop)}
                >
                  <div className="hop-main-col">
                    <div className="hop-primary-row">
                      <span className={`hop-title font-bold ${isMalicious ? 'text-red' : 'text-white'}`}>
                        {hop.ip}
                      </span>
                      <span className={`badge-pill ${isMalicious ? 'text-red' : 'text-green'}`}>
                        [{hop.reputation}]
                      </span>
                    </div>

                    <div className="hop-meta-row">
                      <span>{hop.hostname}</span>
                      <span>{hop.country}</span>
                    </div>
                  </div>
                </div>

                {index < data.headerHops.length - 1 && (
                  <div className="timeline-arrow-connector font-mono">
                    │<br />
                    ▼
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Right: IP Intelligence Panel */}
      <div className="forensic-subcard">
        <div className="subcard-title-bar">
          <span className="subcard-title">IP INTELLIGENCE</span>
          {selectedHop && (
            <span className="subcard-badge font-mono">{selectedHop.ip}</span>
          )}
        </div>

        {selectedHop ? (
          <div className="ip-intelligence-panel font-mono">
            <div className="intel-table">
              <div className="intel-row">
                <span className="intel-label">IP Address</span>
                <span className="intel-value text-white">{selectedHop.ip}</span>
              </div>

              <div className="intel-row">
                <span className="intel-label">Country</span>
                <span className="intel-value text-white">{selectedHop.country}</span>
              </div>

              <div className="intel-row">
                <span className="intel-label">ASN</span>
                <span className="intel-value text-white">{selectedHop.asn}</span>
              </div>

              <div className="intel-row">
                <span className="intel-label">ISP</span>
                <span className="intel-value text-white">{selectedHop.isp}</span>
              </div>

              <div className="intel-row">
                <span className="intel-label">Reputation</span>
                <span className={`intel-value font-bold ${selectedHop.reputation === 'MALICIOUS' ? 'text-red' : 'text-green'}`}>
                  {selectedHop.reputation}
                </span>
              </div>

              <div className="intel-row">
                <span className="intel-label">First Seen</span>
                <span className="intel-value text-muted">{selectedHop.firstSeen}</span>
              </div>
            </div>

            <div className="threat-feeds-section">
              <div className="feeds-title">Threat feeds:</div>
              <div className="feeds-grid font-mono">
                <div className="feed-box">
                  <div className="feed-name">● AbuseIPDB</div>
                  <div className={`feed-status ${selectedHop.threatFeeds.abuseIpDb === 'HIGH RISK' ? 'text-red' : 'text-green'}`}>
                    {selectedHop.threatFeeds.abuseIpDb}
                  </div>
                </div>

                <div className="feed-box">
                  <div className="feed-name">● VirusTotal</div>
                  <div className="feed-status text-amber">
                    {selectedHop.threatFeeds.virusTotal}
                  </div>
                </div>

                <div className="feed-box">
                  <div className="feed-name">● Spamhaus</div>
                  <div className={`feed-status ${selectedHop.threatFeeds.spamhausListed ? 'text-red' : 'text-green'}`}>
                    {selectedHop.threatFeeds.spamhausListed ? 'LISTED' : 'CLEAN'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-muted font-mono">Click a hop from the timeline to inspect IP intelligence.</div>
        )}
      </div>
    </div>
  );
};
