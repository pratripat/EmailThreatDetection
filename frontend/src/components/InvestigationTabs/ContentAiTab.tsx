import React from 'react';
import { InvestigationData } from '../../types/threat';

interface ContentAiTabProps {
  data: InvestigationData;
}

export const ContentAiTab: React.FC<ContentAiTabProps> = ({ data }) => {
  const ai = data.contentAi;

  return (
    <div className="tab-pane-grid">
      {/* Left: Classification & Detected Intent + Suspicious Phrases */}
      <div className="forensic-subcard font-mono">
        <div className="subcard-title-bar">
          <span className="subcard-title">AI CONTENT ANALYSIS</span>
        </div>

        <div className="mb-3">
          <div><span className="text-muted">Classification:</span> <span className="text-red font-bold">{ai.classification}</span></div>
          <div><span className="text-muted">Confidence:</span> <span className="text-white">{ai.confidence}%</span></div>
        </div>

        <div className="ai-intent-section">
          <div className="intent-label">Detected intent:</div>
          <ul className="list-none pl-0 flex flex-col gap-1 text-xs">
            {ai.intents.map((intent, idx) => (
              <li key={idx} className="text-white">
                ● {intent}
              </li>
            ))}
          </ul>
        </div>

        <div className="suspicious-phrases-section mt-4">
          <div className="phrases-label">Suspicious phrases:</div>

          <div className="phrases-list">
            {ai.suspiciousPhrases.map((item, idx) => (
              <div key={idx} className="phrase-highlight-box">
                <div className="phrase-quote">
                  "{item.phrase}"
                </div>
                <div className="phrase-annotation">
                  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;↑<br />
                  &nbsp;&nbsp; {item.signalType}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right: Feature Contribution / SHAP */}
      <div className="forensic-subcard font-mono">
        <div className="subcard-title-bar">
          <span className="subcard-title">Feature contribution (Explainability)</span>
        </div>

        <div className="feature-weights-list">
          {ai.featureContributions.map((feat, idx) => (
            <div key={idx} className="feature-weight-row">
              <div className="feature-name-row">
                <span className="text-muted">{feat.feature}</span>
                <span className={feat.impact === 'positive' ? 'text-red' : 'text-green'}>
                  {feat.impact === 'positive' ? `+${feat.weight}%` : `-${feat.weight}%`}
                </span>
              </div>
              <div className="bar-track">
                <div 
                  className={`bar-fill ${feat.impact === 'positive' ? 'fill-red' : 'fill-green'}`}
                  style={{ width: `${feat.weight}%` }}
                />
              </div>
            </div>
          ))}
        </div>

        <div className="nlp-summary-box">
          <div className="nlp-title">NLP Heuristics verdict:</div>
          <div className="nlp-text">
            Transformer attention weights concentrated on urgency cues ("suspended within 2 hours") coupled with imperative account re-authentication links.
          </div>
        </div>
      </div>
    </div>
  );
};
