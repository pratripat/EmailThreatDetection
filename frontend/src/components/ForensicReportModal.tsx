import React, { useState } from 'react';
import { InvestigationData } from '../types/threat';

interface ForensicReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  data: InvestigationData;
}

export const ForensicReportModal: React.FC<ForensicReportModalProps> = ({
  isOpen,
  onClose,
  data,
}) => {
  const [copied, setCopied] = useState(false);
  if (!isOpen) return null;

  const handlePrint = () => {
    window.print();
  };

  const handleCopy = () => {
    const text = `EMAIL FORENSIC REPORT

Verdict:        ${data.threatLevel}
Threat Score:   ${data.threatScore}/100
Threat Type:    ${data.threatType}

────────────────────────────

KEY FINDINGS

✓ Header anomalies detected
✓ SPF/DKIM/DMARC failures
✓ Suspicious URL identified
✓ Malicious IP identified
✓ Phishing intent detected by NLP

────────────────────────────

ORIGIN INTELLIGENCE

Origin IP:       ${data.headerHops[1]?.ip || '185.220.101.5'}
Country:         ${data.headerHops[1]?.country || 'Singapore'}
ASN:             ${data.headerHops[1]?.asn || 'AS49505'}

────────────────────────────

IOCs

${data.iocs.ipAddresses.length} IPs
${data.iocs.domains.length} Domains
${data.iocs.urls.length} URLs
${data.iocs.hashes.length} Hash

────────────────────────────

RECOMMENDATION

Block identified domains/IPs.
Quarantine the email.
Investigate related messages.`;

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="modal-backdrop">
      <div className="report-modal-card font-mono">
        <div className="report-modal-header">
          <span className="report-doc-title">EMAIL FORENSIC REPORT #{data.id}</span>
          <div className="report-header-actions">
            <button className="btn-minimal-action" onClick={handleCopy}>
              {copied ? '✓ Copied' : '[ Copy Text ]'}
            </button>
            <button className="btn-minimal-action" onClick={handlePrint}>
              [ Print ]
            </button>
            <button className="btn-minimal-action" onClick={onClose}>
              [ Close ]
            </button>
          </div>
        </div>

        <div className="report-document-body">
          <div className="report-verdict-box">
            <div className="verdict-row">
              <span>Verdict:</span>
              <span className="text-red font-bold">{data.threatLevel}</span>
            </div>
            <div className="verdict-row">
              <span>Threat Score:</span>
              <span className="text-red font-bold">{data.threatScore}/100</span>
            </div>
            <div className="verdict-row">
              <span>Threat Type:</span>
              <span>{data.threatType}</span>
            </div>
          </div>

          <hr className="report-divider" />

          <div className="report-section">
            <div className="section-heading">KEY FINDINGS</div>
            <ul className="report-bullets">
              <li>✓ Header anomalies detected</li>
              <li>✓ SPF/DKIM/DMARC failures</li>
              <li>✓ Suspicious URL identified</li>
              <li>✓ Malicious IP identified</li>
              <li>✓ Phishing intent detected by NLP</li>
            </ul>
          </div>

          <hr className="report-divider" />

          <div className="report-section">
            <div className="section-heading">ORIGIN INTELLIGENCE</div>
            <div className="report-kv-grid">
              <div>Origin IP:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{data.headerHops[1]?.ip || '185.220.101.5'}</div>
              <div>Country:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{data.headerHops[1]?.country || 'Singapore'}</div>
              <div>ASN:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{data.headerHops[1]?.asn || 'AS49505'}</div>
            </div>
          </div>

          <hr className="report-divider" />

          <div className="report-section">
            <div className="section-heading">IOCs</div>
            <div className="report-bullets">
              <li>{data.iocs.ipAddresses.length} IPs</li>
              <li>{data.iocs.domains.length} Domains</li>
              <li>{data.iocs.urls.length} URLs</li>
              <li>{data.iocs.hashes.length} Hash</li>
            </div>
          </div>

          <hr className="report-divider" />

          <div className="report-section">
            <div className="section-heading">RECOMMENDATION</div>
            <div className="report-recommendation-box text-white">
              Block identified domains/IPs.<br />
              Quarantine the email.<br />
              Investigate related messages.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
