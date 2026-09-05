"""Email Threat Detection Package for SIH 26106.

Provides inference pipeline for email phishing classification using Gaykar/PhishingDistilBERT.
"""

from email_threat_detection.config import DEFAULT_CONFIG, ModelConfig
from email_threat_detection.model import load_model_and_tokenizer
from email_threat_detection.preprocessing import (
    extract_clean_text_from_html,
    format_email_for_model,
    preprocess_text_content,
    replace_phone_numbers,
    replace_urls,
)
from email_threat_detection.classifier import (
    EmailClassificationResult,
    EmailClassifier,
    classify_email,
    classify_email_dict,
    get_classifier,
)

__all__ = [
    "DEFAULT_CONFIG",
    "ModelConfig",
    "load_model_and_tokenizer",
    "extract_clean_text_from_html",
    "format_email_for_model",
    "preprocess_text_content",
    "replace_phone_numbers",
    "replace_urls",
    "EmailClassificationResult",
    "EmailClassifier",
    "classify_email",
    "classify_email_dict",
    "get_classifier",
]
