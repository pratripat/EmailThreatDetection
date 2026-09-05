import React from 'react';
import { InvestigationData } from '../../types/threat';

interface AuthenticationTabProps {
  data: InvestigationData;
}

export const AuthenticationTab: React.FC<AuthenticationTabProps> = ({ data }) => {
  const auth = data.authentication;

  return (
    <div className="tab-pane-grid">
      {/* Visual SPF / DKIM / DMARC */}
      <div className="forensic-subcard">
        <div className="subcard-title-bar">
          <span className="subcard-title">AUTHENTICATION</span>
        </div>

        <div className="auth-protocols-grid font-mono">
          <div className="protocol-card">
            <div className="protocol-header">
              <span className="protocol-title">SPF</span>
              <span className={`protocol-badge ${auth.spf === 'PASSED' ? 'pass' : 'fail'}`}>
                {auth.spf === 'PASSED' ? '✓ PASSED' : '✕ FAILED'}
              </span>
            </div>
            <p className="protocol-desc">Sender Policy Framework validation</p>
          </div>

          <div className="protocol-card">
            <div className="protocol-header">
              <span className="protocol-title">DKIM</span>
              <span className={`protocol-badge ${auth.dkim === 'PASSED' ? 'pass' : 'fail'}`}>
                {auth.dkim === 'PASSED' ? '✓ PASSED' : '✕ FAILED'}
              </span>
            </div>
            <p className="protocol-desc">Cryptographic header signature check</p>
          </div>

          <div className="protocol-card">
            <div className="protocol-header">
              <span className="protocol-title">DMARC</span>
              <span className={`protocol-badge ${auth.dmarc === 'PASSED' ? 'pass' : 'fail'}`}>
                {auth.dmarc === 'PASSED' ? '✓ PASSED' : '✕ FAILED'}
              </span>
            </div>
            <p className="protocol-desc">Alignment and quarantine enforcement</p>
          </div>
        </div>
      </div>

      {/* Sender Alignment */}
      <div className="forensic-subcard">
        <div className="subcard-title-bar">
          <span className="subcard-title">Sender Alignment</span>
        </div>

        <div className="alignment-inspector-box font-mono">
          <div className="alignment-row">
            <span className="align-label">From:</span>
            <span className="align-val text-white">{auth.fromDomain}</span>
          </div>

          <div className="alignment-row">
            <span className="align-label">Return-Path:</span>
            <span className={auth.alignmentMatched ? "align-val text-green" : "align-val text-red"}>{auth.returnPathDomain}</span>
          </div>

          {!auth.alignmentMatched ? (
            <div className="alignment-warning-alert text-red font-mono">
              ⚠️ Domain alignment mismatch
            </div>
          ) : (
            <div className="alignment-success-alert text-green font-mono">
              ✓ Domain alignment verified
            </div>
          )}
        </div>

        <div className="auth-notes-section font-mono">
          <div className="notes-header">DIAGNOSTICS:</div>
          <ul className="notes-list">
            {auth.notes.map((note, idx) => (
              <li key={idx} className="note-item">
                - {note}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
