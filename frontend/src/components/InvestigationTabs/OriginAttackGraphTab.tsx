import React from 'react';
import { InvestigationData } from '../../types/threat';

interface OriginAttackGraphTabProps {
  data: InvestigationData;
}

export const OriginAttackGraphTab: React.FC<OriginAttackGraphTabProps> = ({ data }) => {
  return (
    <div className="forensic-subcard full-width">
      <div className="subcard-title-bar">
        <span className="subcard-title">ATTACK & ORIGIN INFRASTRUCTURE RECONSTRUCTION</span>
      </div>

      <p className="subcard-hint font-mono">
        Reconstructed adversary infrastructure map: routing, spoofed domain, hosting origin, and exfiltration points.
      </p>

      {/* Clean Minimal Box Graph */}
      <div className="attack-graph-container font-mono">
        {/* Tier 1: Email Node */}
        <div className="graph-tier">
          <div className="graph-node node-email">
            <span className="node-label">EMAIL INGRESS</span>
            <span className="node-sublabel text-red font-bold">{data.threatType}</span>
            <span className="node-meta text-muted">ID: {data.id}</span>
          </div>
        </div>

        {/* Fork Connectors */}
        <div className="graph-connector-fork font-mono">
          │<br />
          ┌──────────┴──────────┐<br />
          ▼&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼
        </div>

        {/* Tier 2: Domain & IP */}
        <div className="graph-tier">
          <div className="graph-node">
            <span className="node-label">SPOOFED DOMAIN</span>
            <span className="node-sublabel text-amber">{data.authentication.fromDomain}</span>
            <span className="node-meta">Typosquatting Proxy</span>
          </div>

          <div className="graph-node">
            <span className="node-label">ORIGIN IP</span>
            <span className="node-sublabel text-red font-bold">{data.headerHops[0]?.ip || 'UNKNOWN'}</span>
            <span className="node-meta">{data.headerHops[0]?.country || 'UNKNOWN'}</span>
          </div>
        </div>

        {/* Line */}
        <div className="graph-connector-single font-mono">
          │<br />
          ▼
        </div>

        {/* Tier 3: Login Page & Theft Destination */}
        <div className="graph-tier">
          <div className="graph-node">
            <span className="node-label">HARVESTER LOGIN PAGE</span>
            <span className="node-sublabel text-white">{data.urls[0]?.domain || 'None Detected'}</span>
            <span className="node-meta">{data.urls.length > 0 ? 'Suspicious URL Form' : 'No URLs Flagged'}</span>
          </div>

          <div className="graph-edge-horizontal font-mono">
            ────────►
          </div>

          <div className="graph-node">
            <span className="node-label">EXFILTRATION ENDPOINT</span>
            <span className="node-sublabel text-red font-bold">Credential Theft</span>
            <span className="node-meta">Drop Server C2</span>
          </div>
        </div>
      </div>
    </div>
  );
};
