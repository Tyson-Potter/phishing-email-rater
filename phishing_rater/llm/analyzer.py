"""LLM-augmented phishing analysis.

Defaults to local Ollama (privacy-by-default). External providers (real OpenAI,
Anthropic via OpenAI-compatible proxy, etc.) are opt-in via environment variables.

Every prompt/response pair is appended to a local audit log so a SOC reviewer
can replay any classification later.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from openai import OpenAI

DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_BASE_URL = "http://localhost:11434/v1"
DEFAULT_API_KEY = "ollama"  # Ollama ignores this; needed only because the SDK requires a value.

AUDIT_LOG_DIR = Path(".phishing_rater") / "llm_audit"

SYSTEM_PROMPT = """You are a SOC analyst reviewing a possibly-phishing email.

Analyze the email and return ONLY a JSON object with this exact shape:
{
  "classification": "phishing" | "legitimate" | "suspicious",
  "confidence": "low" | "medium" | "high",
  "indicators": ["string", "..."],
  "recommended_action": "string"
}

Rules:
- "indicators" must be 1-5 short, specific reasons drawn from the email content.
- Use ONLY information present in the email. Do NOT invent headers, facts, or details.
- If the evidence is mixed or insufficient, classify as "suspicious" with "low" confidence.
- Return ONLY the JSON object. No markdown, no explanation, no preamble.
"""


def _get_client():
    """Build an OpenAI-compatible client. Defaults to local Ollama, override via env."""
    base_url = os.getenv("PHISHING_RATER_LLM_BASE_URL", DEFAULT_BASE_URL)
    api_key = os.getenv("PHISHING_RATER_LLM_API_KEY", DEFAULT_API_KEY)
    return OpenAI(base_url=base_url, api_key=api_key)


def _build_user_prompt(email_text):
    """Format the email body as the user message, truncated to a safe length."""
    truncated = (email_text or "").strip()[:8000]
    return f"Email content:\n---\n{truncated}\n---"


def _audit_log(prompt, response_text, model):
    """Append the prompt+response to a daily JSONL audit log."""
    AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "prompt": prompt,
        "response": response_text,
    }
    log_file = AUDIT_LOG_DIR / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(record) + "\n")


def analyze_email(email_text, model=None):
    """Run an LLM analysis pass and return a structured findings dict.

    Returns: {classification, confidence, indicators, recommended_action, error}
    """
    if not email_text or not email_text.strip():
        return _empty_result(error="empty input (no body text)")

    model = model or os.getenv("PHISHING_RATER_LLM_MODEL", DEFAULT_MODEL)
    user_prompt = _build_user_prompt(email_text)

    try:
        client = _get_client()
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content or ""
        _audit_log(user_prompt, raw, model)
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        return _empty_result(error=f"LLM returned non-JSON: {e}")
    except Exception as e:
        return _empty_result(error=f"LLM call failed: {e}")

    return {
        "classification": parsed.get("classification"),
        "confidence": parsed.get("confidence"),
        "indicators": parsed.get("indicators", []),
        "recommended_action": parsed.get("recommended_action"),
        "error": None,
    }


def _empty_result(error):
    return {
        "classification": None,
        "confidence": None,
        "indicators": [],
        "recommended_action": None,
        "error": error,
    }
