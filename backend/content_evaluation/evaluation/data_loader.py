"""Dataset loader and sampling utility for SIH 26106 Email Threat Detection evaluation.

Supports multiple public Hugging Face phishing email datasets:
- amrithanandini/phishing-email-rich-dataset (rich corporate & personal email corpus with native subject/body)
- Navyasri17/phishing_emails-data (instructional text prompt formatted emails)

Extracts email subject and body fields, standardizes binary labels ('fraudulent' vs 'legitimate'),
and creates balanced, reproducible evaluation samples.
"""

from pathlib import Path
import re
from typing import Any, Dict, Optional, Tuple
import pandas as pd

# Supported datasets metadata
SUPPORTED_DATASETS: Dict[str, Dict[str, str]] = {
    "amrithanandini/phishing-email-rich-dataset": {
        "url": "https://huggingface.co/datasets/amrithanandini/phishing-email-rich-dataset",
        "default_split": "test",
        "sample_filename": "evaluation_sample_rich.csv",
        "description": "Rich email dataset with distinct subject/body and real-world corporate/personal communication patterns.",
    },
    "Navyasri17/phishing_emails-data": {
        "url": "https://huggingface.co/datasets/Navyasri17/phishing_emails-data",
        "default_split": "test",
        "sample_filename": "evaluation_sample_navyasri.csv",
        "description": "Instruction-formatted prompt dataset with embedded email headers.",
    },
}

DEFAULT_DATASET_NAME = "amrithanandini/phishing-email-rich-dataset"
DATA_DIR = Path(__file__).resolve().parent / "data"
RANDOM_SEED = 42


def resolve_dataset_name(name_or_alias: str) -> str:
    """Resolve user-provided dataset name or short alias to canonical Hugging Face ID."""
    alias = name_or_alias.strip().lower()
    if alias in ("rich", "amrithanandini", "amrithanandini/phishing-email-rich-dataset"):
        return "amrithanandini/phishing-email-rich-dataset"
    if alias in ("navyasri", "navyasri17", "navyasri17/phishing_emails-data"):
        return "Navyasri17/phishing_emails-data"
    return name_or_alias


def parse_email_text(raw_text: str) -> Tuple[str, str]:
    """Parse raw instructional text from prompt-based datasets to isolate email Subject and Body.
    
    The dataset formats entries as:
        Is the following email safe or phishing??
        Date: ...
        Sender: ...
        Receiver: ...
        Email Subject: <Subject Text>
        Email Body: <Body Text>
        Email type is: [safe email/phishing email]
    """
    if not isinstance(raw_text, str):
        return "", ""

    subject = ""
    body = ""

    # 1. Extract Subject
    sub_match = re.search(
        r'Email Subject:\s*(.*?)(?=\n\s*Email Body:|\n\n|\Z)',
        raw_text,
        re.DOTALL | re.IGNORECASE
    )
    if sub_match:
        subject = sub_match.group(1).strip()
    else:
        # Fallback to standard "Subject:"
        sub_match2 = re.search(
            r'\bSubject:\s*(.*?)(?=\n\s*(?:Body|Email Body):|\n\n|\Z)',
            raw_text,
            re.DOTALL | re.IGNORECASE
        )
        if sub_match2:
            subject = sub_match2.group(1).strip()

    # 2. Extract Body
    body_match = re.search(
        r'Email Body:\s*(.*?)(?=\n\s*Email type is:|\Z)',
        raw_text,
        re.DOTALL | re.IGNORECASE
    )
    if body_match:
        body = body_match.group(1).strip()
    else:
        # Fallback to standard "Body:" or prompt stripping
        body_match2 = re.search(
            r'\bBody:\s*(.*?)(?=\n\s*Email type is:|\Z)',
            raw_text,
            re.DOTALL | re.IGNORECASE
        )
        if body_match2:
            body = body_match2.group(1).strip()
        else:
            # Strip prompt headers and footers
            cleaned = re.sub(r'^Is the following email[^\n]*\n+', '', raw_text, flags=re.IGNORECASE)
            cleaned = re.sub(r'\n+Email type is:[^\n]*$', '', cleaned, flags=re.IGNORECASE)
            body = cleaned.strip()

    return subject, body


def map_dataset_label(label_raw: Any) -> Optional[str]:
    """Map heterogeneous dataset label formats to the classifier's standard classes.
    
    Returns 'fraudulent', 'legitimate', or None if unmappable.
    """
    if label_raw is None:
        return None

    # Handle integer labels (1 = Phishing, 0 = Safe/Legit)
    if isinstance(label_raw, (int, float)):
        if int(label_raw) == 1:
            return "fraudulent"
        if int(label_raw) == 0:
            return "legitimate"

    label_str = str(label_raw).strip().lower()
    if label_str in ("1", "phish", "phishing", "fraudulent", "phishing email", "spam"):
        return "fraudulent"
    if label_str in ("0", "safe", "legit", "legitimate", "safe email", "ham"):
        return "legitimate"
    
    if "phish" in label_str:
        return "fraudulent"
    if any(kw in label_str for kw in ("safe", "legit", "ham")):
        return "legitimate"

    return None


def get_or_create_evaluation_sample(
    dataset_name: str = DEFAULT_DATASET_NAME,
    output_path: Optional[Path] = None,
    regenerate: bool = False,
    n_phishing: int = 50,
    n_legitimate: int = 50,
    random_state: int = RANDOM_SEED,
    split: Optional[str] = None,
) -> pd.DataFrame:
    """Retrieve existing evaluation sample or generate a fresh, balanced ground-truth CSV.
    
    Args:
        dataset_name: Canonical Hugging Face dataset identifier or alias.
        output_path: Target CSV path. Defaults to evaluation/data/evaluation_sample_<dataset>.csv.
        regenerate: If True, forces re-downloading and sampling from Hugging Face.
        n_phishing: Number of phishing examples to sample.
        n_legitimate: Number of legitimate examples to sample.
        random_state: Random seed for reproducibility.
        split: Hugging Face dataset split. Defaults to the dataset's default_split ('test').
        
    Returns:
        DataFrame containing columns: [id, subject, body, true_label]
    """
    canonical_name = resolve_dataset_name(dataset_name)
    meta = SUPPORTED_DATASETS.get(canonical_name, {
        "url": f"https://huggingface.co/datasets/{canonical_name}",
        "default_split": "test",
        "sample_filename": "evaluation_sample_custom.csv",
    })

    target_split = split or meta.get("default_split", "test")
    default_filename = meta.get("sample_filename", "evaluation_sample.csv")
    save_path = output_path or (DATA_DIR / default_filename)
    save_path.parent.mkdir(parents=True, exist_ok=True)

    if save_path.exists() and not regenerate:
        df_cached = pd.read_csv(save_path)
        df_cached["subject"] = df_cached["subject"].fillna("")
        df_cached["body"] = df_cached["body"].fillna("")
        return df_cached

    print(f"[DataLoader] Downloading public dataset '{canonical_name}' (split='{target_split}') from Hugging Face...")
    from datasets import Dataset, load_dataset

    ds = load_dataset(canonical_name, split=target_split)
    if not isinstance(ds, Dataset):
        raise TypeError(f"Expected datasets.Dataset, got {type(ds)}")

    df_raw = pd.DataFrame(ds.to_pandas())
    print(f"[DataLoader] Downloaded {len(df_raw)} raw rows from '{target_split}' split. Parsing email fields...")

    records = []
    raw_records = [dict(r) for r in df_raw.to_dict(orient="records")]

    for row in raw_records:
        if "amrithanandini" in canonical_name:
            # Native distinct subject, body, label
            raw_subj = row.get("subject")
            subject = str(raw_subj).strip() if raw_subj is not None and str(raw_subj).lower() != "nan" else ""
            raw_body = row.get("body")
            body = str(raw_body).strip() if raw_body is not None and str(raw_body).lower() != "nan" else ""
            mapped_label = map_dataset_label(row.get("label"))
        else:
            # Navyasri prompt wrapper or generic
            if "text" in row and "email_type" in row:
                raw_text = str(row.get("text") or "")
                raw_label = row.get("email_type")
                subject, body = parse_email_text(raw_text)
                mapped_label = map_dataset_label(raw_label)
            else:
                # Fallback to standard column names
                raw_subj = row.get("subject") or row.get("Subject") or ""
                subject = str(raw_subj).strip() if str(raw_subj).lower() != "nan" else ""
                raw_body = row.get("body") or row.get("Body") or row.get("text") or row.get("Email Text") or ""
                body = str(raw_body).strip() if str(raw_body).lower() != "nan" else ""
                raw_label = row.get("label") or row.get("Email Type") or row.get("target") or row.get("type")
                mapped_label = map_dataset_label(raw_label)

        if not mapped_label:
            continue

        if not subject and not body:
            continue

        records.append({
            "subject": subject,
            "body": body,
            "true_label": mapped_label,
        })

    df_parsed = pd.DataFrame(records)

    # Filter by class
    phishing_df = df_parsed[df_parsed["true_label"] == "fraudulent"]
    legit_df = df_parsed[df_parsed["true_label"] == "legitimate"]

    if len(phishing_df) < n_phishing or len(legit_df) < n_legitimate:
        raise ValueError(
            f"Not enough examples in dataset '{canonical_name}'. Required {n_phishing} phishing, {n_legitimate} legit. "
            f"Found {len(phishing_df)} phishing and {len(legit_df)} legit."
        )

    # Sample exactly n_phishing and n_legitimate
    sample_phish = phishing_df.sample(n=n_phishing, random_state=random_state)
    sample_legit = legit_df.sample(n=n_legitimate, random_state=random_state)

    # Combine and shuffle
    sample_combined = pd.concat([sample_phish, sample_legit], ignore_index=True)
    shuffled = sample_combined.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    sample_df = pd.DataFrame(shuffled)

    # Assign deterministic IDs (1 to 100)
    sample_df["id"] = list(range(1, len(sample_df) + 1))
    final_df = pd.DataFrame(sample_df[["id", "subject", "body", "true_label"]])

    # Save to disk
    final_df.to_csv(save_path, index=False)
    print(f"[DataLoader] Successfully saved {len(final_df)} sampled emails to: {save_path}")

    return final_df
