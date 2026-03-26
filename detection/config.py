"""
FileSense — Centralized Configuration
======================================
Single source for all configurable values.
"""

import os
import json

# ── Paths ─────────────────────────────────────────────
BASE_DIR    = os.path.dirname(__file__)
MODEL_DIR   = os.path.join(BASE_DIR, "models")
OUTPUT_DIR  = os.path.join(BASE_DIR, "outputs")
DATASET_DIR = os.path.join(BASE_DIR, "datasets")

MODEL1_PATH      = os.path.join(MODEL_DIR, "model1.joblib")
VECTORIZER1_PATH = os.path.join(MODEL_DIR, "vectorizer1.joblib")
MODEL2_PATH      = os.path.join(MODEL_DIR, "model2.joblib")
VECTORIZER2_PATH = os.path.join(MODEL_DIR, "vectorizer2.joblib")
META_PATH        = os.path.join(MODEL_DIR, "meta.json")
SHAP_BG_PATH     = os.path.join(MODEL_DIR, "shap_background.npz")
REPORT_PATH      = os.path.join(MODEL_DIR, "training_report.json")

# ── Detection threshold ───────────────────────────────
DEFAULT_THRESHOLD = 70.0  # percent

def get_threshold() -> float:
    """Load threshold from meta.json, fallback to default."""
    try:
        if os.path.exists(META_PATH):
            with open(META_PATH, 'r') as f:
                meta = json.load(f)
            return float(meta.get("threshold", DEFAULT_THRESHOLD))
    except Exception:
        pass
    return DEFAULT_THRESHOLD


# ── LLM / xAI (Grok) settings ───────────────────────
XAI_API_KEY    = os.getenv("XAI_API_KEY", "")
XAI_MODEL      = os.getenv("XAI_MODEL", "grok-3-mini")
XAI_BASE_URL   = os.getenv("XAI_BASE_URL", "https://api.x.ai/v1")
LLM_TIMEOUT    = int(os.getenv("LLM_TIMEOUT", "30"))

# Legacy aliases kept so nothing else breaks if referenced
OLLAMA_URL   = os.getenv("OLLAMA_URL", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "")

# ── Logging ───────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ── API limits ────────────────────────────────────────
MAX_QUERY_LENGTH = 10000  # characters

# ── SMTP (kept for backward compat, not used by detection engine) ──
SMTP_HOST    = "smtp.gmail.com"
SMTP_PORT    = 587
SMTP_USER    = os.getenv("SMTP_USER", "")
SMTP_PASS    = os.getenv("SMTP_PASS", "")
ALERT_EMAILS = os.getenv("ALERT_EMAILS", "").split(",")

DB_PATH = "filesense.db"
