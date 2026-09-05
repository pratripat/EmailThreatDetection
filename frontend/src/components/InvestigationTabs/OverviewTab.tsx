import React from 'react';
import { InvestigationData } from '../../types/threat';

interface OverviewTabProps {
  data: InvestigationData;
}

// Function to render minimalist terminal progress blocks
const renderAsciiBar = (pct: number, totalBlocks = 20) => {
  const filled = Math.round((pct / 100) * totalBlocks);
  const empty = totalBlocks - filled;
  return '█'.repeat(filled) + '░'.repeat(empty);
};

export const OverviewTab: React.FC<OverviewTabProps> = ({ data }) => {
  return (
    <div className="tab-pane-grid">
      {/* Left Column: Threat Breakdown */}
      <div className="forensic-subcard">
        <div className="subcard-title-bar">
          <span className="subcard-title">Threat breakdown</span>
        </div>

        <div className="breakdown-list font-mono">
          {/* Main Threat Score */}
          <div className="breakdown-item primary-metric">
            <div className="metric-header">
              <span className="metric-name font-bold text-white">THREAT SCORE</span>
              <span className="metric-value font-bold text-red">{data.threatScore}%</span>
            </div>
            <div className="ascii-bar-row text-red">
              <span>{renderAsciiBar(data.threatScore, 20)}</span>
              <span className="ml-2 font-bold">{data.threatScore}%</span>
            </div>
          </div>

          {/* Submetrics */}
          <div className="breakdown-item">
            <div className="metric-header">
              <span className="metric-name">Header Anomalies</span>
              <span className="metric-value">{data.breakdown.headerAnomalies}%</span>
            </div>
            <div className="ascii-bar-row text-white">
              <span>{renderAsciiBar(data.breakdown.headerAnomalies, 15)}</span>
              <span className="ml-2">{data.breakdown.headerAnomalies}%</span>
            </div>
          </div>

          <div className="breakdown-item">
            <div className="metric-header">
              <span className="metric-name">Authentication</span>
              <span className="metric-value">{data.breakdown.authentication}%</span>
            </div>
            <div className="ascii-bar-row text-red">
              <span>{renderAsciiBar(data.breakdown.authentication, 15)}</span>
              <span className="ml-2">{data.breakdown.authentication}%</span>
            </div>
          </div>

          <div className="breakdown-item">
            <div className="metric-header">
              <span className="metric-name">URL Risk</span>
              <span className="metric-value">{data.breakdown.urlRisk}%</span>
            </div>
            <div className="ascii-bar-row text-red">
              <span>{renderAsciiBar(data.breakdown.urlRisk, 15)}</span>
              <span className="ml-2">{data.breakdown.urlRisk}%</span>
            </div>
          </div>

          <div className="breakdown-item">
            <div className="metric-header">
              <span className="metric-name">Content / NLP</span>
              <span className="metric-value">{data.breakdown.contentNlp}%</span>
            </div>
            <div className="ascii-bar-row text-amber">
              <span>{renderAsciiBar(data.breakdown.contentNlp, 15)}</span>
              <span className="ml-2">{data.breakdown.contentNlp}%</span>
            </div>
          </div>

          <div className="breakdown-item">
            <div className="metric-header">
              <span className="metric-name">Sender Reputation</span>
              <span className="metric-value">{data.breakdown.senderReputation}%</span>
            </div>
            <div className="ascii-bar-row text-muted">
              <span>{renderAsciiBar(data.breakdown.senderReputation, 15)}</span>
              <span className="ml-2">{data.breakdown.senderReputation}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Right Column: Why is this suspicious? */}
      <div className="forensic-subcard">
        <div className="subcard-title-bar">
          <span className="subcard-title">Why is this suspicious?</span>
        </div>

        <div className="suspicious-reasons-list font-mono">
          {data.suspiciousReasons.map((reason, idx) => (
            <div key={idx} className="suspicious-reason-row">
              <span className="reason-icon-col">⚠️</span>
              <span className="reason-text">{reason}</span>
            </div>
          ))}
        </div>

        <div className="action-callout-box font-mono">
          <div className="callout-header">RECOMMENDATION</div>
          <div className="callout-desc">
            Quarantine email. Block domain {data.authentication.fromDomain} and origin IP 185.220.101.5 at edge gateway.
          </div>
        </div>
      </div>
    </div>
  );
};
