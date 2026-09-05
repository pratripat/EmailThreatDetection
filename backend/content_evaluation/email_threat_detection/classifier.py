"""Email Threat Classifier for SIH 26106.

Performs email tokenization, DistilBERT sequence classification inference,
softmax probability transformation, dynamic label mapping, and configurable
threshold-based decision making.
"""

from dataclasses import asdict, dataclass
import logging
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Union

# Ensure workspace root is in sys.path for direct script execution
_pkg_root = str(Path(__file__).resolve().parent.parent)
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

import torch

try:
    from email_threat_detection.config import DEFAULT_CONFIG, ModelConfig
    from email_threat_detection.model import load_model_and_tokenizer
    from email_threat_detection.preprocessing import format_email_for_model
except ImportError:
    from .config import DEFAULT_CONFIG, ModelConfig
    from .model import load_model_and_tokenizer
    from .preprocessing import format_email_for_model

logger = logging.getLogger("email_threat_detection.classifier")


@dataclass
class EmailClassificationResult:
    """Structured output for email threat classification."""
    
    # Final classification label ("fraudulent" or "legitimate")
    prediction: str
    
    # Probability of being fraudulent / phishing [0.0, 1.0]
    fraud_probability: float
    
    # Probability of being legitimate / safe [0.0, 1.0]
    legitimate_probability: float
    
    # Final threat score [0.0, 1.0] (equivalent to fraud_probability)
    score: float
    
    # Decision threshold applied
    threshold: float
    
    # Concise human-readable decision summary
    decision_label: str
    
    # Model identifier used for inference
    model_name: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a plain Python dictionary."""
        return asdict(self)


class EmailClassifier:
    """Inference engine for email phishing classification using PhishingDistilBERT."""

    def __init__(self, config: Optional[ModelConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.model, self.tokenizer, self.device = load_model_and_tokenizer(self.config)
        self.fraud_index, self.legit_index = self._resolve_label_indices()

    def _resolve_label_indices(self) -> tuple[int, int]:
        """Inspect model id2label / label2id to determine fraudulent and legitimate indices.
        
        If model contains explicit semantic names (e.g. 'phishing', 'fraud', 'safe', 'ham'),
        they are mapped automatically. Otherwise, defaults to config.default_label_mapping.
        """
        id2label = getattr(self.model.config, "id2label", {})
        fraud_idx = None
        legit_idx = None

        if id2label:
            for idx, label in id2label.items():
                label_lower = str(label).lower()
                if any(kw in label_lower for kw in ("phish", "fraud", "spam", "malicious", "threat")):
                    fraud_idx = int(idx)
                elif any(kw in label_lower for kw in ("legit", "ham", "safe", "normal", "clean")):
                    legit_idx = int(idx)

        # If labels are generic like LABEL_0, LABEL_1, fallback to configured mapping
        if fraud_idx is None or legit_idx is None:
            fallback = self.config.default_label_mapping
            # Find index mapped to 'fraudulent' and 'legitimate'
            for idx, name in fallback.items():
                if name.lower() in ("fraudulent", "phishing"):
                    fraud_idx = idx
                elif name.lower() in ("legitimate", "safe", "ham"):
                    legit_idx = idx

        # Defensive fallback if indices are still unresolved
        if fraud_idx is None:
            fraud_idx = 1
        if legit_idx is None:
            legit_idx = 0

        if self.config.debug_mode:
            logger.debug(
                f"Resolved label indices: Fraudulent = {fraud_idx}, Legitimate = {legit_idx}"
            )

        return fraud_idx, legit_idx

    def _tokenize(self, text: str, max_length: Optional[int] = None) -> Dict[str, torch.Tensor]:
        """Tokenize preprocessed email text with truncation.
        
        NOTE [Future Extension]: Long-email sliding-window chunking can be added here
        by generating multiple windowed token tensors and pooling their CLS representations.
        """
        seq_len = max_length or self.config.max_length
        tokens = self.tokenizer(
            text,
            truncation=True,
            padding=False,
            max_length=seq_len,
            return_tensors="pt"
        )
        return {k: v.to(self.device) for k, v in tokens.items()}

    def classify(
        self,
        subject: Optional[str] = None,
        body: Optional[str] = None,
        threshold: Optional[float] = None,
        max_length: Optional[int] = None
    ) -> EmailClassificationResult:
        """Classify an email given its subject and body.
        
        Args:
            subject: Email subject line.
            body: Email body text or HTML.
            threshold: Optional override for the decision threshold.
            max_length: Optional override for token sequence length.
            
        Returns:
            EmailClassificationResult containing probabilities, score, and decision.
        """
        # Validate and format input using dedicated email structure markers
        formatted_text = format_email_for_model(subject, body)
        
        # Determine effective threshold
        applied_threshold = threshold if threshold is not None else self.config.default_threshold
        if not (0.0 <= applied_threshold <= 1.0):
            raise ValueError(f"Threshold must be between 0.0 and 1.0, got {applied_threshold}")

        # Tokenization
        inputs = self._tokenize(formatted_text, max_length=max_length)
        input_token_count = inputs["input_ids"].shape[1]

        # Model forward pass under torch.no_grad()
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits  # Shape: [1, num_classes]
            probabilities = torch.softmax(logits, dim=-1)[0]

        fraud_prob = float(probabilities[self.fraud_index].item())
        legit_prob = float(probabilities[self.legit_index].item())

        # Normalize score in [0.0, 1.0]
        score = round(fraud_prob, 4)
        fraud_prob_rounded = round(fraud_prob, 4)
        legit_prob_rounded = round(legit_prob, 4)

        # Decision based on configurable threshold
        is_fraud = fraud_prob >= applied_threshold
        prediction = "fraudulent" if is_fraud else "legitimate"
        
        decision_label = (
            f"{prediction.upper()} "
            f"(Fraud Score: {score:.3f}, Threshold: {applied_threshold:.3f})"
        )

        if self.config.debug_mode:
            logger.debug(
                f"Input tokens: {input_token_count} | Raw logits: {logits.cpu().numpy().tolist()} | "
                f"Fraud Prob: {fraud_prob_rounded} | Decision: {prediction}"
            )

        return EmailClassificationResult(
            prediction=prediction,
            fraud_probability=fraud_prob_rounded,
            legitimate_probability=legit_prob_rounded,
            score=score,
            threshold=applied_threshold,
            decision_label=decision_label,
            model_name=self.config.model_name
        )


# Global singleton instance of the classifier
_GLOBAL_CLASSIFIER: Optional[EmailClassifier] = None


def get_classifier(config: Optional[ModelConfig] = None) -> EmailClassifier:
    """Retrieve or initialize the global EmailClassifier singleton."""
    global _GLOBAL_CLASSIFIER
    if _GLOBAL_CLASSIFIER is None:
        _GLOBAL_CLASSIFIER = EmailClassifier(config)
    return _GLOBAL_CLASSIFIER


def classify_email(
    subject: Optional[str] = None,
    body: Optional[str] = None,
    threshold: Optional[float] = None,
    config: Optional[ModelConfig] = None
) -> EmailClassificationResult:
    """Public convenience function to classify an email by subject and body.
    
    Args:
        subject: Email subject line.
        body: Email body text (plain text or HTML).
        threshold: Optional custom decision threshold [0.0, 1.0].
        config: Optional custom ModelConfig.
        
    Returns:
        EmailClassificationResult with prediction, probabilities, score, and decision.
    """
    classifier = get_classifier(config)
    return classifier.classify(subject=subject, body=body, threshold=threshold)


def classify_email_dict(
    email_data: Dict[str, Any],
    threshold: Optional[float] = None,
    config: Optional[ModelConfig] = None
) -> EmailClassificationResult:
    """Classify an email provided as a dictionary/object.
    
    Expected keys: 'subject' (or 'Subject') and 'body' (or 'Body', 'text', 'content').
    """
    subject = email_data.get("subject", email_data.get("Subject", ""))
    body = email_data.get(
        "body",
        email_data.get("Body", email_data.get("text", email_data.get("content", "")))
    )
    return classify_email(subject=subject, body=body, threshold=threshold, config=config)


if __name__ == "__main__":
    sample_subject = "Urgent account verification"
    sample_body = (
        "Your account will be suspended within 24 hours due to suspicious activity. "
        "Click here immediately to verify your identity: http://secure-banking-verify-alert.com/login"
    )
    result = classify_email(subject=sample_subject, body=sample_body)
    print(f"Prediction: {result.prediction.upper()}")
    print(f"Fraud probability: {result.fraud_probability:.3f}")
    print(f"Legitimate probability: {result.legitimate_probability:.3f}")
    print(f"Score: {result.score:.3f}")
