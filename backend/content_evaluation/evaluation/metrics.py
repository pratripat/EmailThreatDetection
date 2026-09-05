"""Evaluation metrics computation for SIH 26106 Email Threat Detection.

Calculates accuracy, precision, recall, F1, confusion matrix, probability separation,
confidence bands distribution, and multi-threshold sensitivity curves.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import numpy as np
import pandas as pd


@dataclass
class ConfusionMatrixData:
    """Security-focused 2x2 confusion matrix."""
    true_positives: int    # Actual fraudulent correctly flagged as fraudulent
    false_positives: int   # Actual legitimate incorrectly flagged as fraudulent (false alarm)
    true_negatives: int    # Actual legitimate correctly allowed as legitimate
    false_negatives: int   # Actual fraudulent incorrectly allowed as legitimate (missed threat)


@dataclass
class ProbabilitySeparation:
    """Descriptive analysis of threat scores across classes."""
    mean_phishing_score: float
    mean_legitimate_score: float
    min_tp_score: float    # Min score among correctly flagged phishing emails
    max_tn_score: float    # Max score among correctly flagged legitimate emails


@dataclass
class ThresholdComparisonRow:
    """Evaluation metrics for a specific decision threshold."""
    threshold: float
    accuracy: float
    precision: float
    recall: float
    f1: float
    false_positives: int
    false_negatives: int


@dataclass
class EvaluationMetricsResult:
    """Complete collection of evaluation metrics for a test run."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    confusion_matrix: ConfusionMatrixData
    probability_separation: ProbabilitySeparation
    confidence_bands: Dict[str, int]
    threshold_comparison: List[ThresholdComparisonRow]
    total_samples: int
    total_phishing: int
    total_legitimate: int


def compute_metrics(
    predictions_df: pd.DataFrame,
    pos_label: str = "fraudulent",
    neg_label: str = "legitimate",
    thresholds: Optional[List[float]] = None,
) -> EvaluationMetricsResult:
    """Compute comprehensive performance and probability metrics from predictions dataframe.
    
    Expected columns in predictions_df:
        - true_label: 'fraudulent' or 'legitimate'
        - score: float in [0.0, 1.0] (probability of fraudulent)
        - predicted_label: 'fraudulent' or 'legitimate' (at baseline threshold)
    """
    if thresholds is None:
        thresholds = [0.30, 0.40, 0.50, 0.60, 0.70, 0.80]

    # Convert columns to plain Python lists for strict type safety and speed
    y_true: List[str] = [str(x) for x in predictions_df["true_label"].tolist()]
    y_pred: List[str] = [str(x) for x in predictions_df["predicted_label"].tolist()]
    scores: List[float] = [float(x) for x in predictions_df["score"].tolist()]

    total_samples = len(y_true)
    total_phishing = sum(1 for yt in y_true if yt == pos_label)
    total_legitimate = sum(1 for yt in y_true if yt == neg_label)

    # 1. Confusion Matrix at primary threshold
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == pos_label and yp == pos_label)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == neg_label and yp == pos_label)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == neg_label and yp == neg_label)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == pos_label and yp == neg_label)

    cm_data = ConfusionMatrixData(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
    )

    # 2. Overall Metrics at primary threshold
    acc = (tp + tn) / total_samples if total_samples > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

    # 3. Probability Separation Analysis
    phishing_scores = [s for s, yt in zip(scores, y_true) if yt == pos_label]
    legit_scores = [s for s, yt in zip(scores, y_true) if yt == neg_label]

    mean_phish = float(np.mean(phishing_scores)) if phishing_scores else 0.0
    mean_legit = float(np.mean(legit_scores)) if legit_scores else 0.0

    tp_scores = [s for s, yt, yp in zip(scores, y_true, y_pred) if yt == pos_label and yp == pos_label]
    min_tp = min(tp_scores) if tp_scores else 0.0

    tn_scores = [s for s, yt, yp in zip(scores, y_true, y_pred) if yt == neg_label and yp == neg_label]
    max_tn = max(tn_scores) if tn_scores else 0.0

    prob_sep = ProbabilitySeparation(
        mean_phishing_score=round(mean_phish, 4),
        mean_legitimate_score=round(mean_legit, 4),
        min_tp_score=round(min_tp, 4),
        max_tn_score=round(max_tn, 4),
    )

    # 4. Confidence Bands Distribution
    bands = {
        "0.00 - 0.20": sum(1 for s in scores if 0.00 <= s <= 0.20),
        "0.20 - 0.40": sum(1 for s in scores if 0.20 < s <= 0.40),
        "0.40 - 0.60": sum(1 for s in scores if 0.40 < s <= 0.60),
        "0.60 - 0.80": sum(1 for s in scores if 0.60 < s <= 0.80),
        "0.80 - 1.00": sum(1 for s in scores if 0.80 < s <= 1.00),
    }

    # 5. Threshold Sensitivity Sweep
    threshold_rows: List[ThresholdComparisonRow] = []
    for t in thresholds:
        t_tp = sum(1 for yt, s in zip(y_true, scores) if yt == pos_label and s >= t)
        t_fp = sum(1 for yt, s in zip(y_true, scores) if yt == neg_label and s >= t)
        t_tn = sum(1 for yt, s in zip(y_true, scores) if yt == neg_label and s < t)
        t_fn = sum(1 for yt, s in zip(y_true, scores) if yt == pos_label and s < t)

        t_acc = (t_tp + t_tn) / total_samples if total_samples > 0 else 0.0
        t_prec = t_tp / (t_tp + t_fp) if (t_tp + t_fp) > 0 else 0.0
        t_rec = t_tp / (t_tp + t_fn) if (t_tp + t_fn) > 0 else 0.0
        t_f1 = (2 * t_prec * t_rec) / (t_prec + t_rec) if (t_prec + t_rec) > 0 else 0.0

        threshold_rows.append(
            ThresholdComparisonRow(
                threshold=t,
                accuracy=round(t_acc, 4),
                precision=round(t_prec, 4),
                recall=round(t_rec, 4),
                f1=round(t_f1, 4),
                false_positives=t_fp,
                false_negatives=t_fn,
            )
        )

    return EvaluationMetricsResult(
        accuracy=round(acc, 4),
        precision=round(prec, 4),
        recall=round(rec, 4),
        f1=round(f1, 4),
        confusion_matrix=cm_data,
        probability_separation=prob_sep,
        confidence_bands=bands,
        threshold_comparison=threshold_rows,
        total_samples=total_samples,
        total_phishing=total_phishing,
        total_legitimate=total_legitimate,
    )
