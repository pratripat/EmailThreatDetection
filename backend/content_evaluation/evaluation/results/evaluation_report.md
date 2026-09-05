# SIH 26106 Email Threat Detection Evaluation

## Dataset

- **Dataset name**: `amrithanandini/phishing-email-rich-dataset`
- **Dataset split**: `test` (held-out test split)
- **Dataset URL**: [https://huggingface.co/datasets/amrithanandini/phishing-email-rich-dataset](https://huggingface.co/datasets/amrithanandini/phishing-email-rich-dataset)
- **Number of examples selected**: 100
- **Number of phishing examples**: 50
- **Number of legitimate examples**: 50
- **Sampling seed**: `42`
- **Date/time of evaluation**: `2026-09-05 06:11:07`
- **Model name**: `Gaykar/PhishingDistilBERT`
- **Primary threshold**: `0.50`

## Overall Performance

| Metric | Value |
| :--- | :---: |
| Accuracy | 0.9500 |
| Precision | 0.9592 |
| Recall | 0.9400 |
| F1-Score | 0.9495 |
| False Positives (False Alarms) | 2 |
| False Negatives (Missed Attacks) | 3 |

## Confusion Matrix

Explicit security interpretation:
- **False Positive**: A legitimate email incorrectly flagged as fraudulent (inconveniences users/business communications).
- **False Negative**: A fraudulent/phishing email incorrectly allowed as legitimate (critical security vulnerability).

| Actual \ Predicted | Predicted Legitimate | Predicted Fraudulent | Total |
| :--- | :---: | :---: | :---: |
| **Actual Legitimate** | 48 (TN) | 2 (FP) | 50 |
| **Actual Fraudulent** | 3 (FN) | 47 (TP) | 50 |
| **Total** | 51 | 49 | 100 |

## Probability Separation

- **Average fraud score for actual phishing emails**: `0.9297`
- **Average fraud score for actual legitimate emails**: `0.0629`
- **Minimum score among correctly detected phishing emails (TP Min)**: `0.5896`
- **Maximum score among correctly detected legitimate emails (TN Max)**: `0.3616`

### Score Distribution Across Confidence Bands

| Confidence Band | Email Count | Percentage |
| :--- | :---: | :---: |
| `0.00 - 0.20` | 48 | 48.0% |
| `0.20 - 0.40` | 2 | 2.0% |
| `0.40 - 0.60` | 2 | 2.0% |
| `0.60 - 0.80` | 2 | 2.0% |
| `0.80 - 1.00` | 46 | 46.0% |

> *Note: These confidence bands represent descriptive raw probability scores produced by the DistilBERT sequence classification head and are not statistically calibrated Bayesian probabilities.*

## Threshold Comparison

| Threshold | Accuracy | Precision | Recall | F1 | False Positives | False Negatives |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **0.30** | 0.9600 | 0.9423 | 0.9800 | 0.9608 | 3 | 1 |
| **0.40** | 0.9600 | 0.9600 | 0.9600 | 0.9600 | 2 | 2 |
| **0.50** *(Current Default)* | 0.9500 | 0.9592 | 0.9400 | 0.9495 | 2 | 3 |
| **0.60** | 0.9400 | 0.9583 | 0.9200 | 0.9388 | 2 | 4 |
| **0.70** | 0.9500 | 0.9787 | 0.9200 | 0.9485 | 1 | 4 |
| **0.80** | 0.9400 | 0.9783 | 0.9000 | 0.9375 | 1 | 5 |

### Threshold Analysis & Operational Recommendation

In a cybersecurity pipeline such as SIH 26106, missing a malicious email (False Negative) presents a significantly higher organizational risk than quarantining a legitimate message for review (False Positive). While the pipeline default remains **0.50**, the sweep reveals that a threshold of **0.30** yields a recall of **98.0%** with **1** missed phishing emails, compared to 3 missed attacks at the 0.50 default. This finding is submitted as an **operational tuning recommendation** rather than an automatic change to production configuration.

## Error Analysis

- **Total False Positives**: `2`
- **Total False Negatives**: `3`

### False Positives (Legitimate Classified as Fraudulent)
- **Sample ID #25**
  - **Subject**: `tenaska iv oct 2000`
  - **True Label**: `legitimate` | **Predicted**: `fraudulent`
  - **Fraud Score**: `0.9274`
  - *Analyst note: Structural elements or phrasing exhibited similarity to mass notification templates.*
- **Sample ID #99**
  - **Subject**: `weekly deal report`
  - **True Label**: `legitimate` | **Predicted**: `fraudulent`
  - **Fraud Score**: `0.6531`
  - *Analyst note: Structural elements or phrasing exhibited similarity to mass notification templates.*

### False Negatives (Phishing Classified as Legitimate)
- **Sample ID #12**
  - **Subject**: `returned mail : response error`
  - **True Label**: `fraudulent` | **Predicted**: `legitimate`
  - **Fraud Score**: `0.0060`
  - *Analyst note: Phishing email lacks aggressive urgency words or overt credential demands.*
- **Sample ID #40**
  - **Subject**: `office xp - $ 60`
  - **True Label**: `fraudulent` | **Predicted**: `legitimate`
  - **Fraud Score**: `0.3607`
  - *Analyst note: Phishing email lacks aggressive urgency words or overt credential demands.*
- **Sample ID #84**
  - **Subject**: `re : good news - in ^ ~ cr ~ eas _ ^ ed drive and performance`
  - **True Label**: `fraudulent` | **Predicted**: `legitimate`
  - **Fraud Score**: `0.4684`
  - *Analyst note: Phishing email lacks aggressive urgency words or overt credential demands.*

## Conclusion

1. **Pipeline Accuracy**: The current inference pipeline achieved an overall accuracy of **95.0%** on the fixed 100-email balanced evaluation set.
2. **Error Distribution**: The pipeline produced **2** False Positive(s) and **3** False Negative(s). False negatives remain the primary security risk.
3. **Threshold Suitability**: The default threshold of **0.50** offers a balanced operating point; however, lowering the threshold to **0.30** significantly enhances detection recall for high-security deployments.
4. **Baseline Viability for SIH 26106**: `Gaykar/PhishingDistilBERT` demonstrates robust semantic understanding of email structure markers (`[SSUB]`, `[SBODY]`, `[LINK]`, `[PHONE]`) and serves as an effective text-classification core for the broader threat detection architecture.
5. **Scope Limitations**: This test was performed on a discrete 100-sample balanced subset from a public research corpus. It evaluates text and structural content only and does not test external URL reputation, attachment analysis, domain spoofing (SPF/DKIM/DMARC), or zero-day email attacks.

---
## ⚠️ Scope Disclaimers & Limitations

- This report presents a benchmark evaluation on a fixed 100-sample held-out subset and **does not prove 100% accuracy** or complete real-world phishing prevention.
- The evaluation **does not claim statistically calibrated probabilities**; output scores reflect raw softmax logits from the model classification head.
- The sample is drawn from public academic datasets and **is not a statistically representative sample of global or Indian organizational email distributions**.
- The model operates strictly as an **email text classifier**; it does not analyze attachments, detonate files, or inspect live web destinations.
