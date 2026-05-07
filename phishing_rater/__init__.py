"""Phishing Email Rater package.

Loads configuration from a local .env file (if present) on import, so
overrides for ML model selection, LLM backend, API keys, etc. are picked
up automatically. See `.env.example` for the full list of variables.
"""
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv is a hard requirement, but if someone imports the package
    # without installing it, we silently fall back to environment variables only.
    pass
