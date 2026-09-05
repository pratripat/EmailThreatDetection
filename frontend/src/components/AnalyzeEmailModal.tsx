import React, { useState } from 'react';
import { EmailAnalysisRequest, InvestigationData } from '../types/threat';

interface AnalyzeEmailModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalyzeComplete: (result: InvestigationData) => void;
  onRunBackendAnalysis: (req: EmailAnalysisRequest) => Promise<InvestigationData>;
}

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

const ANALYSIS_STEPS = [
  'Parsing email MIME structure & metadata',
  'Extracting Received: header routing hops',
  'Validating SPF, DKIM & DMARC authentication',
  'Extracting & sandboxing embedded URLs',
  'Running Transformer NLP & intent classifier',
  'Querying threat intelligence feeds',
  'Geolocating & profiling originating IP',
  'Correlating indicators & computing threat score',
];

export const AnalyzeEmailModal: React.FC<AnalyzeEmailModalProps> = ({
  isOpen,
  onClose,
  onAnalyzeComplete,
  onRunBackendAnalysis,
}) => {
  const [senderEmail, setSenderEmail] = useState('security@paypa1-support.com');
  const [subject, setSubject] = useState('URGENT: Your account requires verification');
  const [rawHeaders, setRawHeaders] = useState('');
  const [emailBody, setEmailBody] = useState('');
  
  const [touched, setTouched] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const [isScanning, setIsScanning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  if (!isOpen) return null;

  const validateEmail = (val: string): boolean => {
    if (!val.trim()) {
      setValidationError('Sender email is required');
      return false;
    }
    if (!EMAIL_REGEX.test(val.trim())) {
      setValidationError('Invalid email format (e.g. sender@domain.com)');
      return false;
    }
    setValidationError(null);
    return true;
  };

  const handleRunAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!validateEmail(senderEmail)) {
      return;
    }

    setIsScanning(true);
    setCurrentStepIndex(0);

    for (let i = 0; i < ANALYSIS_STEPS.length; i++) {
      setCurrentStepIndex(i);
      await new Promise((res) => setTimeout(res, 220));
    }

    try {
      const data = await onRunBackendAnalysis({
        senderEmail: senderEmail.trim(),
        subject: subject.trim(),
        rawHeaders: rawHeaders.trim(),
        emailBody: emailBody.trim(),
        timestamp: new Date().toISOString(),
      });
      onAnalyzeComplete(data);
      onClose();
    } catch (err: any) {
      alert(`Analysis error: ${err.message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const loadPreset = (type: 'phishing' | 'bec' | 'clean') => {
    setTouched(true);
    setValidationError(null);
    if (type === 'phishing') {
      setSenderEmail('security@paypa1-support.com');
      setSubject('URGENT: Your account requires verification');
      setEmailBody('We detected unauthorized sign-in attempts on your PayPal corporate account. Verify immediately:\nhttps://paypal-secure-login.xyz/auth/verify');
      setRawHeaders('Received: from mail-relay-sg01.hosting-cloud.net (185.220.101.5)\nAuthentication-Results: spf=fail dkim=fail dmarc=fail');
    } else if (type === 'bec') {
      setSenderEmail('ceo-office@enterprise-global-corp.top');
      setSubject('Confidential: Immediate Wire Transfer Needed Today');
      setEmailBody('Please process the urgent vendor settlement of $48,500 to routing account #99482 immediately.');
      setRawHeaders('Received: from tor-relay-02.net (194.38.20.12)\nAuthentication-Results: spf=softfail dkim=none');
    } else {
      setSenderEmail('notifications@github.com');
      setSubject('[GitHub] Release v2.4.0 published successfully');
      setEmailBody('The automated continuous integration build completed with zero errors.');
      setRawHeaders('Received: from mail-sor-f41.google.com (209.85.220.41)\nAuthentication-Results: spf=pass dkim=pass dmarc=pass');
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = (event.target?.result as string) || '';
      if (!content) return;

      // RFC boundary: headers and body are separated by a double newline
      const splitIdx = content.search(/\r?\n\r?\n/);
      let headers = '';
      let body = '';

      if (splitIdx !== -1) {
        headers = content.slice(0, splitIdx);
        body = content.slice(splitIdx).replace(/^\r?\n\r?\n/, '');
      } else {
        headers = content;
        body = '';
      }

      setRawHeaders(headers);
      setEmailBody(body);

      // Extract From: address
      const fromMatch = headers.match(/^From:\s*(.+)$/im);
      if (fromMatch) {
        const bracketMatch = fromMatch[1].match(/<([^>]+)>/);
        const emailMatch = fromMatch[1].match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        const extracted = bracketMatch ? bracketMatch[1] : (emailMatch ? emailMatch[1] : fromMatch[1]);
        setSenderEmail(extracted.trim());
      }

      // Extract Subject:
      const subjMatch = headers.match(/^Subject:\s*(.+)$/im);
      if (subjMatch) {
        setSubject(subjMatch[1].trim());
      } else {
        setSubject(file.name.replace(/\.eml$/i, ''));
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card-minimal font-mono">
        <div className="modal-top">
          <span className="modal-title-text">ANALYZE NEW EMAIL</span>
          <button className="modal-close-icon font-mono" onClick={onClose} disabled={isScanning}>
            [ESC]
          </button>
        </div>

        {isScanning ? (
          <div className="scanning-progress-view font-mono">
            <div className="scanning-spinner-row">
              <span className="scanning-headline">EXECUTING FORENSIC SCAN...</span>
            </div>

            <div className="steps-progress-list">
              {ANALYSIS_STEPS.map((step, idx) => {
                const isCompleted = idx < currentStepIndex;
                const isCurrent = idx === currentStepIndex;

                return (
                  <div key={idx} className={`step-item ${isCompleted ? 'done' : isCurrent ? 'running' : 'pending'}`}>
                    <span>{isCompleted ? '✓' : isCurrent ? '►' : '·'}</span>
                    <span className="step-label">{step}</span>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <form onSubmit={handleRunAnalysis} className="modal-form-body font-mono">
            {/* Quick Demo Presets */}
            <div className="preset-bar">
              <span className="preset-title">Presets:</span>
              <button 
                type="button" 
                className="preset-pill"
                onClick={() => loadPreset('phishing')}
              >
                [ PayPal Phish ]
              </button>
              <button 
                type="button" 
                className="preset-pill"
                onClick={() => loadPreset('bec')}
              >
                [ CEO BEC ]
              </button>
              <button 
                type="button" 
                className="preset-pill"
                onClick={() => loadPreset('clean')}
              >
                [ Clean EML ]
              </button>
            </div>

            {/* Drop .EML */}
            <label className="file-drop-zone">
              <input 
                type="file" 
                accept=".eml,.msg,.txt" 
                className="hidden-file-input" 
                onChange={handleFileUpload}
              />
              <div className="drop-texts">
                <span className="text-white">Upload .EML file</span>
                <span className="text-dim text-xs block">or input sender email & headers below</span>
              </div>
            </label>

            {/* Sender Email */}
            <div className="input-group">
              <label className="input-label">
                <span>Sender Email:</span>
                {touched && !validationError && (
                  <span className="regex-badge-ok font-mono">✓ Regex valid</span>
                )}
              </label>
              <input
                type="text"
                className={`minimal-text-input font-mono ${
                  touched && validationError ? 'has-error' : ''
                }`}
                placeholder="security@paypa1-support.com"
                value={senderEmail}
                onChange={(e) => {
                  setSenderEmail(e.target.value);
                  if (touched) validateEmail(e.target.value);
                }}
                onBlur={() => {
                  setTouched(true);
                  validateEmail(senderEmail);
                }}
              />
              {touched && validationError && (
                <div className="regex-error-text font-mono">
                  ✕ {validationError}
                </div>
              )}
            </div>

            {/* Subject */}
            <div className="input-group">
              <label className="input-label">Subject:</label>
              <input
                type="text"
                className="minimal-text-input font-mono"
                placeholder="URGENT: Your account requires verification"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
              />
            </div>

            {/* Raw Headers */}
            <div className="input-group">
              <label className="input-label">Raw Headers (Optional):</label>
              <textarea
                className="minimal-textarea font-mono text-xs"
                rows={2}
                placeholder="Received: from mail.attacker.net (185.220.101.5)..."
                value={rawHeaders}
                onChange={(e) => setRawHeaders(e.target.value)}
              />
            </div>

            {/* Footer */}
            <div className="modal-actions-bar">
              <button type="button" className="btn-cancel font-mono" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="btn-submit-scan font-mono">
                Start Forensic Scan →
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
