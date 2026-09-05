"""Model and Tokenizer loader for Gaykar/PhishingDistilBERT.

Handles device selection (CUDA if available, otherwise CPU), model loading,
evaluation mode configuration, and tokenizer initialization.
"""

import logging
from pathlib import Path
import sys
from typing import Optional, Tuple, cast

# Ensure workspace root is in sys.path for direct script execution
_pkg_root = str(Path(__file__).resolve().parent.parent)
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

import torch
from transformers import (
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
)

try:
    from email_threat_detection.config import DEFAULT_CONFIG, ModelConfig
except ImportError:
    from .config import DEFAULT_CONFIG, ModelConfig

logger = logging.getLogger("email_threat_detection.model")

# Module-level cache for singleton model and tokenizer
_CACHED_MODEL: Optional[DistilBertForSequenceClassification] = None
_CACHED_TOKENIZER: Optional[DistilBertTokenizerFast] = None
_CACHED_DEVICE: Optional[torch.device] = None


def get_device(device_override: Optional[str] = None) -> torch.device:
    """Detect and return compute device (CUDA if available, otherwise CPU)."""
    if device_override:
        return torch.device(device_override)
    
    if torch.cuda.is_available():
        device = torch.device("cuda")
        device_name = torch.cuda.get_device_name(0)
        logger.info(f"Using CUDA device: {device_name}")
    else:
        device = torch.device("cpu")
        logger.info("CUDA not available. Using CPU device.")
    
    return device


def load_model_and_tokenizer(
    config: Optional[ModelConfig] = None
) -> Tuple[DistilBertForSequenceClassification, DistilBertTokenizerFast, torch.device]:
    """Load DistilBertTokenizerFast and DistilBertForSequenceClassification.
    
    Sets model to evaluation mode and caches instances in memory.
    """
    global _CACHED_MODEL, _CACHED_TOKENIZER, _CACHED_DEVICE

    cfg = config or DEFAULT_CONFIG
    device = get_device(cfg.device_override)

    if (
        _CACHED_MODEL is not None
        and _CACHED_TOKENIZER is not None
        and _CACHED_DEVICE is not None
    ):
        return _CACHED_MODEL, _CACHED_TOKENIZER, _CACHED_DEVICE

    logger.info(f"Loading tokenizer from '{cfg.model_name}'...")
    tokenizer = cast(
        DistilBertTokenizerFast,
        DistilBertTokenizerFast.from_pretrained(cfg.model_name),
    )

    logger.info(f"Loading sequence classification model from '{cfg.model_name}'...")
    model = cast(
        DistilBertForSequenceClassification,
        DistilBertForSequenceClassification.from_pretrained(cfg.model_name),
    )

    # Move model to detected hardware device and switch to evaluation mode
    model.to(device)  # pyright: ignore[reportArgumentType]
    model.eval()

    if cfg.debug_mode:
        logger.debug(f"Model architecture: {type(model).__name__}")
        logger.debug(f"Model config id2label: {model.config.id2label}")
        logger.debug(f"Model config label2id: {model.config.label2id}")
        logger.debug(f"Vocabulary size: {tokenizer.vocab_size}")

    _CACHED_MODEL = model
    _CACHED_TOKENIZER = tokenizer
    _CACHED_DEVICE = device

    return model, tokenizer, device
