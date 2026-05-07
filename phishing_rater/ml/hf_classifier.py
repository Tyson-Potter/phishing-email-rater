"""HuggingFace transformer-based phishing classifier (cybersectony DistilBERT).

Privacy posture: telemetry disabled, offline mode preferred after first download.
The model runs entirely on the local machine; no email content is transmitted.
"""
import logging
import os

# Disable telemetry, suppress auth nag, mute progress bars, prefer cache reads.
# `setdefault` so a user can override these by exporting the variable explicitly.
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

from functools import lru_cache  # noqa: E402

from transformers import pipeline  # noqa: E402

logging.getLogger("huggingface_hub").setLevel(logging.ERROR)

DEFAULT_MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
DEFAULT_PHISHING_LABELS = "LABEL_1,phishing,phishing_url,phishing_url_alt"
DEFAULT_LEGITIMATE_LABELS = "LABEL_0,legitimate,legitimate_email,legitimate_url"


def _parse_label_set(env_var, default):
    """Comma-separated env var → set of label strings. Empty entries dropped."""
    raw = os.getenv(env_var, default)
    return {label.strip() for label in raw.split(",") if label.strip()}


# Model + label config can be overridden via env (or .env file) so the classifier
# can be swapped to any text-classification model on the Hub. Default is the
# cybersectony DistilBERT with binary LABEL_0/LABEL_1 outputs.
MODEL_ID = os.getenv("PHISHING_RATER_ML_MODEL", DEFAULT_MODEL_ID)
PHISHING_LABELS = _parse_label_set("PHISHING_RATER_ML_PHISHING_LABELS",
                                    DEFAULT_PHISHING_LABELS)
LEGITIMATE_LABELS = _parse_label_set("PHISHING_RATER_ML_LEGITIMATE_LABELS",
                                      DEFAULT_LEGITIMATE_LABELS)
LABEL_FRIENDLY = {"LABEL_0": "legitimate", "LABEL_1": "phishing"}


@lru_cache(maxsize=1)
def _get_classifier():
    """Load and cache the classifier pipeline. Subsequent calls reuse the same instance."""
    return pipeline("text-classification", model=MODEL_ID, top_k=None)


def classify(text):
    """Run the classifier on email body text and return a normalized score dict.

    Returns: {phishing_score, legitimate_score, top_label, raw, error}
    Scores sum to 1.0 (binary softmax). top_label is the human-readable winner.
    """
    if not text or not text.strip():
        return {
            "phishing_score": None,
            "legitimate_score": None,
            "top_label": None,
            "raw": [],
            "error": "empty input (no body text)",
        }

    clf = _get_classifier()
    result = clf(text, truncation=True, max_length=512)

    scores = result[0]
    phishing_score = sum(s["score"] for s in scores if s["label"] in PHISHING_LABELS)
    legitimate_score = sum(s["score"] for s in scores if s["label"] in LEGITIMATE_LABELS)
    top = max(scores, key=lambda s: s["score"])

    return {
        "phishing_score": phishing_score,
        "legitimate_score": legitimate_score,
        "top_label": LABEL_FRIENDLY.get(top["label"], top["label"]),
        "raw": scores,
        "error": None,
    }
