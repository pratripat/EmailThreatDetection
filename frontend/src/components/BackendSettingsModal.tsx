import React, { useState } from 'react';
import { X, Server, Check, AlertCircle, RefreshCw, Globe, Shield, Code } from 'lucide-react';
import { ApiConfig, saveStoredConfig } from '../services/api';

interface BackendSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  config: ApiConfig;
  onUpdateConfig: (newConfig: ApiConfig) => void;
  onTestConnection: () => Promise<boolean>;
}

export const BackendSettingsModal: React.FC<BackendSettingsModalProps> = ({
  isOpen,
  onClose,
  config,
  onUpdateConfig,
  onTestConnection,
}) => {
  const [backendUrl, setBackendUrl] = useState(config.backendUrl);
  const [flagUrl, setFlagUrl] = useState(config.flagUrl);
  const [useSimulationFallback, setUseSimulationFallback] = useState(config.useSimulationFallback);
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  if (!isOpen) return null;

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    const updated: ApiConfig = {
      backendUrl: backendUrl.trim(),
      flagUrl: flagUrl.trim(),
      useSimulationFallback,
    };
    saveStoredConfig(updated);
    onUpdateConfig(updated);
    onClose();
  };

  const handleTest = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const ok = await onTestConnection();
      if (ok) {
        setTestResult({ success: true, message: 'Backend reachable and responded successfully.' });
      } else {
        setTestResult({
          success: false,
          message: 'Could not connect to backend. Enable simulation fallback for prototype testing.',
        });
      }
    } catch (err: any) {
      setTestResult({
        success: false,
        message: err.message || 'Connection failed.',
      });
    } finally {
      setIsTesting(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-container">
        <div className="modal-header">
          <div className="modal-title-group">
            <Server size={20} className="text-cyan" />
            <div>
              <h3 className="modal-title">Backend API Configuration</h3>
              <p className="modal-subtitle">Configure the endpoint where email scan payloads are dispatched</p>
            </div>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSave} className="modal-form">
          {/* Analyze Email Endpoint */}
          <div className="form-group">
            <label htmlFor="backendUrl" className="form-label">
              <span>Email Analysis Endpoint (POST)</span>
            </label>
            <div className="input-with-icon">
              <Globe className="input-icon" size={16} />
              <input
                id="backendUrl"
                type="text"
                className="text-input font-mono text-sm"
                value={backendUrl}
                onChange={(e) => setBackendUrl(e.target.value)}
                placeholder="http://localhost:8000/api/analyze-email"
                required
              />
            </div>
            <p className="input-hint">Default route for sending raw email headers, body & sender addresses.</p>
          </div>

          {/* Collaborative Threat DB Flag Endpoint */}
          <div className="form-group">
            <label htmlFor="flagUrl" className="form-label">
              <span>Threat Intelligence Flag Endpoint (POST)</span>
            </label>
            <div className="input-with-icon">
              <Shield className="input-icon" size={16} />
              <input
                id="flagUrl"
                type="text"
                className="text-input font-mono text-sm"
                value={flagUrl}
                onChange={(e) => setFlagUrl(e.target.value)}
                placeholder="http://localhost:8000/api/flag-threat"
                required
              />
            </div>
          </div>

          {/* Simulation Fallback Toggle */}
          <div className="toggle-group">
            <label className="toggle-label">
              <input
                type="checkbox"
                checked={useSimulationFallback}
                onChange={(e) => setUseSimulationFallback(e.target.checked)}
                className="toggle-checkbox"
              />
              <div className="toggle-content">
                <span className="toggle-title">Prototype Simulation Fallback</span>
                <span className="toggle-desc">
                  Automatically show realistic spoofing & route reconstruction if your backend is currently offline.
                </span>
              </div>
            </label>
          </div>

          {/* Outgoing JSON Schema Helper */}
          <div className="schema-box">
            <div className="schema-title">
              <Code size={13} />
              <span>Outgoing POST Payload JSON Schema:</span>
            </div>
            <pre className="schema-pre">
{`{
  "senderEmail": "string (regex-validated)",
  "subject": "string",
  "rawHeaders": "string",
  "emailBody": "string",
  "timestamp": "ISO 8601 string"
}`}
            </pre>
          </div>

          {/* Connection Test Result */}
          {testResult && (
            <div className={`test-result-box ${testResult.success ? 'success' : 'warning'}`}>
              {testResult.success ? <Check size={16} /> : <AlertCircle size={16} />}
              <span>{testResult.message}</span>
            </div>
          )}

          {/* Footer Actions */}
          <div className="modal-footer">
            <button
              type="button"
              className="test-btn"
              onClick={handleTest}
              disabled={isTesting}
            >
              {isTesting ? (
                <>
                  <RefreshCw size={14} className="animate-spin" />
                  <span>Pinging API...</span>
                </>
              ) : (
                <>
                  <RefreshCw size={14} />
                  <span>Test Connection</span>
                </>
              )}
            </button>

            <div className="modal-footer-right">
              <button type="button" className="cancel-btn" onClick={onClose}>
                Cancel
              </button>
              <button type="submit" className="save-btn">
                Save Changes
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
