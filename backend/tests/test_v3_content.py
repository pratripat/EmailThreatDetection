from backend.app.ml.content_classifier import ContentClassifierService
from backend.app.ml.feature_extraction import extract_content_features


def test_feature_extraction():
    feats = extract_content_features(
        subject="URGENT SECURITY ALERT",
        body_plain="Please reset your password immediately!",
        body_html="<p>Please <script>alert(1)</script> reset</p>"
    )
    assert feats["has_script_tags"] is True
    assert feats["has_html"] is True
    assert feats["exclamation_count"] >= 1
    assert feats["upper_ratio"] > 0.0


def test_content_classifier_honest_heuristic_fallback():
    classifier = ContentClassifierService(model_path="")
    assert classifier.is_model_loaded is False

    # Test clean text
    clean_res = classifier.classify(
        subject="Meeting Agenda for Next Tuesday",
        body_plain="Hi team, attached is the presentation for our weekly standup.",
        body_html=""
    )
    assert clean_res.classification == "BENIGN"
    assert clean_res.confidence == 0.0
    assert clean_res.featureContributions == []
    assert clean_res.intents == []

    # Test suspicious text
    phish_res = classifier.classify(
        subject="Urgent: Your account has been suspended",
        body_plain="Please verify your account password immediately to avoid termination.",
        body_html=""
    )
    assert phish_res.classification == "PHISHING"
    assert phish_res.confidence == 0.50  # Honest heuristic confidence, not 0.99
    assert phish_res.featureContributions == []  # No fake SHAP
    assert "Credential Harvesting" in phish_res.intents
    assert "Urgent Coercion" in phish_res.intents
