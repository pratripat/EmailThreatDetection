"""Main evaluation driver for SIH 26106 Email Threat Detection.

Loads ground-truth emails from public benchmark datasets, executes the production inference
pipeline (Gaykar/PhishingDistilBERT) without modification, evaluates multi-class & probability
metrics, and produces detailed predictions and structured Markdown reports.
"""

import argparse
from pathlib import Path
import sys

# Ensure repository root is in sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import pandas as pd

from email_threat_detection.classifier import classify_email
from email_threat_detection.config import DEFAULT_CONFIG
from evaluation.data_loader import (
    DEFAULT_DATASET_NAME,
    RANDOM_SEED,
    SUPPORTED_DATASETS,
    get_or_create_evaluation_sample,
    resolve_dataset_name,
)
from evaluation.metrics import compute_metrics
from evaluation.report import generate_evaluation_report

# Paths
EVAL_DIR = Path(__file__).resolve().parent
RESULTS_DIR = EVAL_DIR / "results"
DETAILED_PREDICTIONS_PATH = RESULTS_DIR / "detailed_predictions.csv"
REPORT_PATH = RESULTS_DIR / "evaluation_report.md"


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate SIH 26106 Email Threat Detection Pipeline")
    parser.add_argument(
        "--dataset",
        type=str,
        default=DEFAULT_DATASET_NAME,
        help=f"Hugging Face dataset identifier or short alias ('rich', 'navyasri') (default: '{DEFAULT_DATASET_NAME}')",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.50,
        help="Primary classification decision threshold [0.0, 1.0] (default: 0.50)",
    )
    parser.add_argument(
        "--split",
        type=str,
        default=None,
        help="Hugging Face dataset split to evaluate against (default: dataset default, e.g. 'test')",
    )
    parser.add_argument(
        "--regenerate-data",
        action="store_true",
        help="Force re-downloading and re-sampling the ground-truth evaluation CSV",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Include full email body in detailed predictions file for debugging",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    threshold = args.threshold
    if not (0.0 <= threshold <= 1.0):
        print(f"Error: Threshold must be between 0.0 and 1.0, got {threshold}", file=sys.stderr)
        sys.exit(1)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    dataset_canonical = resolve_dataset_name(args.dataset)
    meta = SUPPORTED_DATASETS.get(dataset_canonical, {
        "url": f"https://huggingface.co/datasets/{dataset_canonical}",
        "default_split": "test",
        "sample_filename": "evaluation_sample_custom.csv",
    })
    target_split = args.split or meta.get("default_split", "test")
    dataset_url = meta.get("url", f"https://huggingface.co/datasets/{dataset_canonical}")

    # 1. Load or create fixed ground-truth sample (100 emails: 50 phishing, 50 legit)
    print(f"\n[1/4] Preparing ground-truth evaluation dataset: {dataset_canonical} (split: '{target_split}')...")
    df_eval = get_or_create_evaluation_sample(
        dataset_name=dataset_canonical,
        regenerate=args.regenerate_data,
        n_phishing=50,
        n_legitimate=50,
        random_state=RANDOM_SEED,
        split=target_split,
    )

    print(f"      Loaded {len(df_eval)} samples for evaluation.")

    # 2. Run inference using the actual production pipeline
    print(f"\n[2/4] Executing inference using Gaykar/PhishingDistilBERT (threshold = {threshold:.2f})...")
    prediction_records = []

    eval_records = [dict(r) for r in df_eval.to_dict(orient="records")]
    for row in eval_records:
        sample_id = row.get("id", 0)
        raw_subj = row.get("subject")
        subj = str(raw_subj) if raw_subj is not None and str(raw_subj).lower() != "nan" else ""
        raw_body = row.get("body")
        body = str(raw_body) if raw_body is not None and str(raw_body).lower() != "nan" else ""
        true_lbl = str(row.get("true_label") or "")

        # Call production pipeline entry point directly
        result = classify_email(subject=subj, body=body, threshold=threshold)

        is_correct = bool(result.prediction == true_lbl)

        record = {
            "id": sample_id,
            "true_label": true_lbl,
            "predicted_label": result.prediction,
            "fraud_probability": result.fraud_probability,
            "legitimate_probability": result.legitimate_probability,
            "score": result.score,
            "threshold": threshold,
            "correct": is_correct,
            "subject": subj,
        }
        if args.debug:
            record["body"] = body

        prediction_records.append(record)

    predictions_df = pd.DataFrame(prediction_records)

    # 3. Save detailed predictions
    predictions_df.to_csv(DETAILED_PREDICTIONS_PATH, index=False)
    print(f"      Detailed predictions saved to: {DETAILED_PREDICTIONS_PATH.relative_to(repo_root)}")

    # 4. Compute metrics
    print(f"\n[3/4] Computing metrics, probability distribution, and threshold curves...")
    metrics = compute_metrics(predictions_df)

    # 5. Generate Markdown Report
    print(f"\n[4/4] Generating evaluation report...")
    generate_evaluation_report(
        metrics=metrics,
        detailed_df=predictions_df,
        output_path=REPORT_PATH,
        dataset_name=dataset_canonical,
        dataset_url=dataset_url,
        model_name=DEFAULT_CONFIG.model_name,
        primary_threshold=threshold,
        random_seed=RANDOM_SEED,
        dataset_split=target_split,
    )

    # 6. Print requested terminal summary
    print("\n" + "=" * 40)
    print("SIH 26106 MODEL EVALUATION")
    print("=" * 40)
    print(f"Dataset: {dataset_canonical}")
    print(f"Split  : {target_split} (held-out)")
    print(f"Samples: {metrics.total_samples}")
    print(f"Phishing: {metrics.total_phishing}")
    print(f"Legitimate: {metrics.total_legitimate}")
    print("")
    print(f"Accuracy : {metrics.accuracy:.2f}")
    print(f"Precision: {metrics.precision:.2f}")
    print(f"Recall   : {metrics.recall:.2f}")
    print(f"F1 Score : {metrics.f1:.2f}")
    print("")
    print(f"False Positives: {metrics.confusion_matrix.false_positives}")
    print(f"False Negatives: {metrics.confusion_matrix.false_negatives}")
    print("")
    print(f"Threshold: {threshold:.2f}")
    print("=" * 40 + "\n")


if __name__ == "__main__":
    main()
