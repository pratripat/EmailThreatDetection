"""Unit and sanity tests for SIH 26106 Email Threat Detection pipeline."""

import unittest
from email_threat_detection.preprocessing import (
    extract_clean_text_from_html,
    format_email_for_model,
    preprocess_text_content,
    replace_phone_numbers,
    replace_urls,
)
from email_threat_detection.classifier import (
    EmailClassificationResult,
    classify_email,
    classify_email_dict,
)


class TestEmailPreprocessing(unittest.TestCase):
    """Test suite for URL/phone replacement, HTML stripping, and structural token formatting."""

    def test_url_replacement_http_https_www(self):
        sample = "Visit http://secure-login.com/auth and https://bank-verify.org or www.test.net."
        processed = replace_urls(sample)
        self.assertNotIn("http://", processed)
        self.assertNotIn("https://", processed)
        self.assertNotIn("www.", processed)
        self.assertIn("[LINK]", processed)
        # Verify exactly 3 link tokens replaced
        self.assertEqual(processed.count("[LINK]"), 3)

    def test_phone_replacement(self):
        sample = "Call us at +1-800-555-0199 or (555) 123-4567 for immediate help."
        processed = replace_phone_numbers(sample)
        self.assertIn("[PHONE]", processed)
        self.assertEqual(processed.count("[PHONE]"), 2)

    def test_phone_replacement_does_not_corrupt_ordinary_numbers(self):
        sample = "In year 2026, the invoice total is $4500 for order 1234."
        processed = replace_phone_numbers(sample)
        self.assertNotIn("[PHONE]", processed)
        self.assertIn("2026", processed)
        self.assertIn("4500", processed)

    def test_html_tag_extraction(self):
        html_input = "<html><body><p>Dear customer,</p><br><div>Please verify.</div></body></html>"
        extracted = extract_clean_text_from_html(html_input)
        self.assertNotIn("<p>", extracted)
        self.assertNotIn("<div>", extracted)
        self.assertIn("Dear customer,", extracted)
        self.assertIn("Please verify.", extracted)

    def test_structural_tokens_formatting(self):
        sub = "Urgent Notice"
        bod = "Click here http://example.com"
        formatted = format_email_for_model(sub, bod)
        
        self.assertTrue(formatted.startswith("[SSUB]"))
        self.assertIn("[ESUB]", formatted)
        self.assertIn("[SBODY]", formatted)
        self.assertTrue(formatted.endswith("[EBODY]"))
        self.assertIn("[LINK]", formatted)
        self.assertNotIn("http://example.com", formatted)

    def test_edge_cases_empty_and_none(self):
        # Missing / None inputs must not raise exceptions
        res1 = format_email_for_model(None, None)
        self.assertEqual(res1, "[SSUB] [ESUB] [SBODY] [EBODY]")

        res2 = format_email_for_model("", "")
        self.assertEqual(res2, "[SSUB] [ESUB] [SBODY] [EBODY]")

        res3 = format_email_for_model("   \t\n  ", None)
        self.assertEqual(res3, "[SSUB] [ESUB] [SBODY] [EBODY]")


class TestEmailClassifierPipeline(unittest.TestCase):
    """Smoke and sanity tests for classifier execution, output types, and thresholding."""

    def test_classification_output_types_and_ranges(self):
        sub = "Account Security Alert"
        bod = "Your account password will expire. Click http://reset-password-now.com to update."
        
        result = classify_email(subject=sub, body=bod)
        
        self.assertIsInstance(result, EmailClassificationResult)
        self.assertIn(result.prediction, ["fraudulent", "legitimate"])
        self.assertIsInstance(result.fraud_probability, float)
        self.assertIsInstance(result.legitimate_probability, float)
        self.assertIsInstance(result.score, float)
        
        # Verify probability bounds [0.0, 1.0]
        self.assertGreaterEqual(result.fraud_probability, 0.0)
        self.assertLessEqual(result.fraud_probability, 1.0)
        self.assertGreaterEqual(result.legitimate_probability, 0.0)
        self.assertLessEqual(result.legitimate_probability, 1.0)
        self.assertGreaterEqual(result.score, 0.0)
        self.assertLessEqual(result.score, 1.0)

        # Sum of probabilities should be approximately 1.0
        prob_sum = result.fraud_probability + result.legitimate_probability
        self.assertAlmostEqual(prob_sum, 1.0, places=2)

    def test_threshold_configurable_behavior(self):
        sub = "Urgent billing question"
        bod = "Please verify your recent charge here: http://charges-alert.com"
        
        # High threshold -> biased towards "legitimate"
        result_high = classify_email(subject=sub, body=bod, threshold=0.999)
        self.assertEqual(result_high.threshold, 0.999)
        if result_high.fraud_probability < 0.999:
            self.assertEqual(result_high.prediction, "legitimate")

        # Low threshold -> biased towards "fraudulent"
        result_low = classify_email(subject=sub, body=bod, threshold=0.001)
        self.assertEqual(result_low.threshold, 0.001)
        if result_low.fraud_probability >= 0.001:
            self.assertEqual(result_low.prediction, "fraudulent")

    def test_dict_input_interface(self):
        email_data = {
            "subject": "Monthly status update",
            "body": "Hi, please review the attached document. Regards, John."
        }
        result = classify_email_dict(email_data)
        self.assertIsInstance(result, EmailClassificationResult)
        self.assertIn(result.prediction, ["fraudulent", "legitimate"])


if __name__ == "__main__":
    unittest.main()
