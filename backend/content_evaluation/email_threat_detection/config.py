"""Configuration constants and settings for SIH 26106 Email Threat Detection Pipeline."""

from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class ModelConfig:
    """Configuration container for model loading, tokenization, and thresholding."""
    
    # Hugging Face model identifier
    model_name: str = "Gaykar/PhishingDistilBERT"
    
    # Maximum token sequence length for truncation (DistilBERT standard context is 512, default 256 for email speed)
    max_length: int = 256
    
    # Decision threshold for flagging an email as fraudulent [0.0, 1.0]
    # Prediction: fraudulent if fraud_probability >= threshold, else legitimate
    default_threshold: float = 0.5
    
    # Fallback label index mapping if model config does not provide descriptive labels
    # Standard security convention: 0 = Legitimate (Ham), 1 = Fraudulent (Phishing/Spam)
    default_label_mapping: Dict[int, str] = field(
        default_factory=lambda: {
            0: "legitimate",
            1: "fraudulent",
        }
    )
    
    # Safe logging mode: suppress sensitive email body/subject in stdout/logs
    debug_mode: bool = False
    
    # Force device ('cpu', 'cuda', or None for auto-detection)
    device_override: Optional[str] = None


# Default global configuration instance
DEFAULT_CONFIG = ModelConfig()
