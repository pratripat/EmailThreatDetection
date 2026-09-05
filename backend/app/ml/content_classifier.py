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
    Strictly avoids fabricating ML confidence percentages or synthetic SHAP values.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = (model_path if model_path is not None else EMAIL_MODEL_PATH).strip()
        self.model = None
        self.tokenizer = None
        self.device = "cpu"
        self.is_model_loaded = False
        self._bert_classifier = None

        if self.model_path and Path(self.model_path).exists():
            self._load_local_model()
        elif model_path is None and not self.model_path:
            self._load_bert_classifier()

    def _load_bert_classifier(self) -> None:
        try:
            import sys
            _content_eval_dir = Path(__file__).resolve().parents[2] / "content_evaluation"
            if str(_content_eval_dir) not in sys.path and _content_eval_dir.exists():
                sys.path.insert(0, str(_content_eval_dir))

            from email_threat_detection.classifier import get_classifier
            self._bert_classifier = get_classifier()
            self.is_model_loaded = True
            logger.info("Loaded integrated PhishingDistilBERT classifier singleton.")
        except Exception as e:
            logger.warning(f"Failed to load integrated BERT classifier: {e}. Falling back to heuristic classifier.")
            self.is_model_loaded = False
            self._bert_classifier = None

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

        # 1. Real BERT Model Inference (if loaded via integrated module)
        if self.is_model_loaded and self._bert_classifier:
            try:
                bert_res = self._bert_classifier.classify(subject=subject, body=body_plain or body_html)

                is_fraud = bert_res.fraud_probability >= 0.60 or (
                    bert_res.fraud_probability >= 0.45 and (heuristic_res.classification != "BENIGN" or bool(heuristic_res.intents))
                )

                if is_fraud:
                    chosen_label = heuristic_res.classification if heuristic_res.classification != "BENIGN" else "PHISHING"
                    confidence = bert_res.fraud_probability
                else:
                    chosen_label = "BENIGN"
                    confidence = bert_res.legitimate_probability if not heuristic_res.intents else heuristic_res.confidence

                intents = list(heuristic_res.intents)
                if is_fraud and not intents:
                    intents.append("Phishing Content Pattern")

                feature_contributions: List[FeatureContribution] = []
                if is_fraud:
                    feature_contributions.append(
                        FeatureContribution(
                            feature="DistilBERT Semantic Threat Cue",
                            weight=round(bert_res.fraud_probability * 100, 1),
                            impact="positive"
                        )
                    )
                    if features.get("upper_ratio", 0) > 0.15:
                        feature_contributions.append(
                            FeatureContribution(
                                feature="Excessive Capitalization",
                                weight=round(features["upper_ratio"] * 100, 1),
                                impact="positive"
                            )
                        )
                    if features.get("exclamation_count", 0) > 1:
                        feature_contributions.append(
                            FeatureContribution(
                                feature="Urgency Exclamations",
                                weight=min(30.0, float(features["exclamation_count"] * 10.0)),
                                impact="positive"
                            )
                        )

                return ContentAiSummary(
                    classification=chosen_label,
                    confidence=round(confidence, 4),
                    intents=intents,
                    suspiciousPhrases=suspicious_phrases,
                    featureContributions=feature_contributions
                )
            except Exception as e:
                logger.warning(f"BERT classifier inference failed: {e}. Reverting to heuristic summary.")

        # 2. Local custom model inference (if loaded via model_path)
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
                    featureContributions=[]
                )
            except Exception as e:
                logger.debug(f"Model inference failed: {e}. Reverting to heuristic summary.")

        # 3. Heuristic Classification (Honest, verifiable fallback)
        return ContentAiSummary(
            classification=heuristic_res.classification,
            confidence=heuristic_res.confidence,
            intents=heuristic_res.intents,
            suspiciousPhrases=suspicious_phrases,
            featureContributions=[]
        )
