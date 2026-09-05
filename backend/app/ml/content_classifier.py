"""
Machine Learning & NLP Content Classifier Service
Provides local neural model inference when weights are supplied, or honest heuristic fallback.
Strictly avoids fabricating ML confidence percentages or synthetic SHAP values.
"""

import os
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

from ..config import EMAIL_MODEL_PATH, USE_GPU_FOR_INFERENCE
from ..models.investigation import (
    ContentAiSummary,
    SuspiciousPhrase,
    FeatureContribution,
)
from ..analyzers.content_analysis import analyze_content
from ..intelligence.models import ProvenanceType
from .feature_extraction import extract_content_features

logger = logging.getLogger(__name__)


class ContentClassifierService:
    """
    Email Content Classifier supporting both local HuggingFace/PyTorch models
    and honest rule-based heuristic fallback.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = (model_path or EMAIL_MODEL_PATH).strip()
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self.is_model_loaded = False

        if self.model_path and Path(self.model_path).exists():
            self._load_local_model()

    def _load_local_model(self) -> None:
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            if USE_GPU_FOR_INFERENCE and torch.cuda.is_available():
                self.device = "cuda"

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
            self.model.to(self.device)
            self.model.eval()
            self.is_model_loaded = True
            logger.info(f"Loaded local NLP content model from {self.model_path} onto {self.device}")
        except Exception as e:
            logger.warning(f"Failed to load model from {self.model_path}: {e}. Falling back to heuristic classifier.")
            self.is_model_loaded = False

    def classify(
        self,
        subject: str = "",
        body_plain: str = "",
        body_html: str = ""
    ) -> ContentAiSummary:
        """
        Classify email content into threat category with honest confidence and verifiable explanations.
        """
        # Always run baseline pattern analysis for explicit intents and phrases
        heuristic_res = analyze_content(subject, body_plain, body_html)
        features = extract_content_features(subject, body_plain, body_html)

        suspicious_phrases = [
            SuspiciousPhrase(phrase=sp["phrase"], signalType=sp["signalType"])
            for sp in heuristic_res.suspicious_phrases
        ]

        # 1. Real Model Inference (if loaded)
        if self.is_model_loaded and self.model and self.tokenizer:
            try:
                import torch
                text_input = f"{subject} [SEP] {body_plain}".strip()
                inputs = self.tokenizer(
                    text_input,
                    truncation=True,
                    max_length=512,
                    return_tensors="pt"
                ).to(self.device)

                with torch.no_grad():
                    outputs = self.model(**inputs)
                    probs = torch.softmax(outputs.logits, dim=-1).squeeze().tolist()

                # Map model logits to classification labels
                labels = ["BENIGN", "PHISHING", "SPOOFING", "BEC_FRAUD", "MALWARE_DROP"]
                max_idx = int(torch.argmax(outputs.logits, dim=-1).item())
                chosen_label = labels[max_idx] if max_idx < len(labels) else "BENIGN"
                confidence = float(probs[max_idx]) if isinstance(probs, list) else float(probs)

                return ContentAiSummary(
                    classification=chosen_label,
                    confidence=round(confidence, 4),
                    intents=heuristic_res.intents,
                    suspiciousPhrases=suspicious_phrases,
                    featureContributions=[]  # Honest: empty unless real SHAP/IG is computed
                )
            except Exception as e:
                logger.debug(f"Model inference failed: {e}. Reverting to heuristic summary.")

        # 2. Heuristic Classification (Honest, verifiable fallback)
        # Never fabricate 90%+ confidence when using simple pattern matching
        return ContentAiSummary(
            classification=heuristic_res.classification,
            confidence=heuristic_res.confidence,
            intents=heuristic_res.intents,
            suspiciousPhrases=suspicious_phrases,
            featureContributions=[]  # Strictly no fabricated SHAP values
        )
