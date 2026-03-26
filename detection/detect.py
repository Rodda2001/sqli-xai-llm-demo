"""
FileSense — Detection Engine (Improved)
========================================
Inference pipeline: preprocessing → Model 1 (binary) → Model 2 (subtype) →
SHAP/XAI (SQLi only) → LLM explanation (SQLi only) → response.
"""

import os
import re
import time
import json
import joblib
import shap
import numpy as np
from datetime import datetime
from scipy.sparse import hstack, csr_matrix

from preprocessing import (
    normalize_query,
    extract_structural_features,
    NUM_STRUCTURAL_FEATURES,
    STRUCTURAL_FEATURE_NAMES,
)
from config import (
    MODEL1_PATH,
    VECTORIZER1_PATH,
    MODEL2_PATH,
    VECTORIZER2_PATH,
    SHAP_BG_PATH,
    XAI_API_KEY,
    XAI_MODEL,
    XAI_BASE_URL,
    LLM_TIMEOUT,
    MAX_QUERY_LENGTH,
    get_threshold,
    OPENROUTER_API_KEY,
    OPENROUTER_MODEL,
    OPENROUTER_BASE_URL,
    LLM_TIMEOUT,
)
from logger import get_logger

log = get_logger("detect")

# ══════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════

def validate_vectorizer(name: str, vectorizer) -> None:
    """Ensure a loaded TF-IDF vectorizer is truly fitted."""
    try:
        if not hasattr(vectorizer, "vocabulary_") or not vectorizer.vocabulary_:
            raise ValueError("missing vocabulary_")

        # This is the exact operation that was failing in your logs
        _ = vectorizer.transform(["select 1"])

        if hasattr(vectorizer, "idf_"):
            _ = vectorizer.idf_

        _ = vectorizer.get_feature_names_out()
        log.info("%s validated successfully", name)

    except Exception as e:
        raise RuntimeError(f"{name} is not a valid fitted TF-IDF vectorizer: {e}") from e


def load_artifacts():
    log.info("Loading models...")

    model1 = joblib.load(MODEL1_PATH)
    vectorizer1 = joblib.load(VECTORIZER1_PATH)
    model2 = joblib.load(MODEL2_PATH)
    vectorizer2 = joblib.load(VECTORIZER2_PATH)

    validate_vectorizer("vectorizer1", vectorizer1)
    validate_vectorizer("vectorizer2", vectorizer2)

    log.info("Models loaded successfully")
    return model1, vectorizer1, model2, vectorizer2


# ══════════════════════════════════════════════════════════════════
# Model Loading
# ══════════════════════════════════════════════════════════════════

try:
    model1, vectorizer1, model2, vectorizer2 = load_artifacts()
except Exception as e:
    log.error(f"Failed to load models: {e}")
    raise


# ── Load SHAP background ─────────────────────────────
explainer1 = None
try:
    if os.path.exists(SHAP_BG_PATH):
        bg_data = np.load(SHAP_BG_PATH)["data"]
        expected_features = vectorizer1.transform(["test"]).shape[1] + NUM_STRUCTURAL_FEATURES

        if bg_data.shape[1] == expected_features:
            explainer1 = shap.LinearExplainer(model1, bg_data)
            log.info(f"SHAP explainer loaded with background sample ({bg_data.shape[0]} rows)")
        else:
            log.warning(
                f"SHAP background dimension mismatch: got {bg_data.shape[1]}, expected {expected_features}. Using fallback."
            )

    if explainer1 is None:
        fallback_bg = vectorizer1.transform(["select 1"])
        struct_bg = csr_matrix(extract_structural_features("select 1").reshape(1, -1))
        fallback_combined = hstack([fallback_bg, struct_bg])
        explainer1 = shap.LinearExplainer(model1, fallback_combined)
        log.warning("Using fallback SHAP background (single sample)")

except Exception as e:
    log.error(f"SHAP explainer setup failed: {e}")
    explainer1 = None


# ── Load threshold ────────────────────────────────────
THRESHOLD = get_threshold()
log.info(f"Detection threshold: {THRESHOLD}%")


# ══════════════════════════════════════════════════════════════════
# MITRE ATT&CK Mapping
# ══════════════════════════════════════════════════════════════════

MITRE_MAP = {
    "auth_bypass": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "severity": "critical",
    },
    "union_based": {
        "tactic": "Collection",
        "technique": "T1005",
        "name": "Data from Local System",
        "severity": "critical",
    },
    "blind_boolean": {
        "tactic": "Discovery",
        "technique": "T1082",
        "name": "System Information Discovery",
        "severity": "high",
    },
    "blind_time": {
        "tactic": "Discovery",
        "technique": "T1082",
        "name": "System Information Discovery",
        "severity": "high",
    },
    "error_based": {
        "tactic": "Collection",
        "technique": "T1005",
        "name": "Data from Local System",
        "severity": "high",
    },
    "stacked_queries": {
        "tactic": "Execution",
        "technique": "T1059",
        "name": "Command and Scripting Interpreter",
        "severity": "critical",
    },
    "evasion": {
        "tactic": "Defense Evasion",
        "technique": "T1027",
        "name": "Obfuscated Files or Information",
        "severity": "high",
    },
    "other": {
        "tactic": "Initial Access",
        "technique": "T1190",
        "name": "Exploit Public-Facing Application",
        "severity": "medium",
    },
}


# ══════════════════════════════════════════════════════════════════
# Feature building
# ══════════════════════════════════════════════════════════════════

def build_inference_features(query: str, vectorizer):
    """Build combined features for a single query, matching training pipeline."""
    normalized = normalize_query(query)
    tfidf = vectorizer.transform([normalized])
    struct = csr_matrix(extract_structural_features(normalized).reshape(1, -1))
    return hstack([tfidf, struct])


# ══════════════════════════════════════════════════════════════════
# XAI — SQL-aware pattern explanation
# ══════════════════════════════════════════════════════════════════

SQL_PATTERNS = [
    (r"(?i)OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", "OR 1=1 (tautology)"),
    (r"(?i)OR\s+['\"][^'\"]*['\"]\s*=\s*['\"]", "OR ''='' (string tautology)"),
    (r"(?i)OR\s+TRUE", "OR TRUE"),
    (r"(?i)UNION\s+(ALL\s+)?SELECT", "UNION SELECT"),
    (r"(?i)information_schema\.(tables|columns|schemata)", "information_schema access"),
    (r"(?i)GROUP_CONCAT\s*\(", "GROUP_CONCAT() exfil"),
    (r"(?i)CONCAT\s*\(", "CONCAT() exfil"),
    (r"(?i)SLEEP\s*\(\s*\d+\s*\)", "SLEEP() time delay"),
    (r"(?i)WAITFOR\s+DELAY", "WAITFOR DELAY"),
    (r"(?i)BENCHMARK\s*\(", "BENCHMARK() timing"),
    (r"(?i)PG_SLEEP\s*\(", "pg_sleep() timing"),
    (r"(?i)SUBSTRING\s*\(", "SUBSTRING() extraction"),
    (r"(?i)ASCII\s*\(\s*SUBSTRING", "ASCII(SUBSTRING()) blind"),
    (r"(?i)IF\s*\(.+SLEEP", "IF(condition,SLEEP) blind"),
    (r"(?i)EXTRACTVALUE\s*\(", "EXTRACTVALUE() error"),
    (r"(?i)UPDATEXML\s*\(", "UPDATEXML() error"),
    (r"(?i)FLOOR\s*\(\s*RAND", "FLOOR(RAND()) error"),
    (r"(?i)EXP\s*\(\s*~", "EXP(~) error overflow"),
    (r"(?i);\s*DROP\s+TABLE", "DROP TABLE (destructive)"),
    (r"(?i);\s*DELETE\s+FROM", "DELETE FROM (destructive)"),
    (r"(?i);\s*INSERT\s+INTO", "INSERT INTO (injection)"),
    (r"(?i);\s*UPDATE\s+\w+\s+SET", "UPDATE SET (tampering)"),
    (r"(?i)XP_CMDSHELL", "xp_cmdshell (RCE)"),
    (r"(?i)EXEC\s+(master\.\.)?xp_", "EXEC xp_ (RCE)"),
    (r"/\*\*/", "/**/ comment bypass"),
    (r"/\*!.+\*/", "/*!...*/ MySQL bypass"),
    (r"(?i)CHAR\s*\(\s*\d+", "CHAR() encoding"),
    (r"0[xX][0-9a-fA-F]{2,}", "hex encoding"),
    (r"(?i)@@version", "@@version fingerprint"),
    (r"(?i)SELECT\s+.*FROM\s+mysql\.user", "mysql.user access"),
    (r"(?i)LOAD_FILE\s*\(", "LOAD_FILE() file read"),
    (r"(?i)INTO\s+OUTFILE", "INTO OUTFILE write"),
    (r"(?i)SHOW\s+DATABASES", "SHOW DATABASES recon"),
    (r"--\s*$|--\s+", "-- comment terminator"),
    (r"#\s*$", "# comment terminator"),
]


def generate_xai_tokens(query: str, vec_features, shap_values_array, feature_names) -> list:
    raw_tokens = {}
    dense = vec_features.toarray()[0]

    for i in range(len(shap_values_array)):
        if i < len(feature_names) and dense[i] > 0:
            raw_tokens[str(feature_names[i]).strip()] = float(shap_values_array[i])

    positive_shaps = sorted([v for v in raw_tokens.values() if v > 0], reverse=True)
    total_positive_shap = sum(positive_shaps) or 1.0

    xai_tokens = []
    matched = []

    for pattern, label in SQL_PATTERNS:
        m = re.search(pattern, query)
        if m:
            match_len = len(m.group(0))
            query_len = max(len(query), 1)
            base_score = total_positive_shap * max(match_len / query_len, 0.15)

            match_text = m.group(0).lower()
            frag_shap = 0.0
            for token, shap_val in raw_tokens.items():
                t = token.strip().lower()
                if shap_val > 0 and (t in match_text or match_text in t):
                    frag_shap += shap_val

            final_score = max(frag_shap, base_score)
            matched.append({
                "token": label,
                "shap": round(final_score, 4),
                "direction": "sqli",
            })

    seen = set()
    for p in sorted(matched, key=lambda x: x["shap"], reverse=True):
        if p["token"] not in seen:
            seen.add(p["token"])
            xai_tokens.append(p)
        if len(xai_tokens) >= 6:
            break

    if not xai_tokens:
        xai_tokens = _fallback_xai_tokens(query)

    return xai_tokens


# ══════════════════════════════════════════════════════════════════
# LLM Explanation
# ══════════════════════════════════════════════════════════════════

def get_llm_explanation(report: dict) -> str:
    tokens = ", ".join([f"'{t['token']}'" for t in report["xai_tokens"][:5]])
    attack = report["attack_type"]
    conf = report["confidence"]
    mitre = report["mitre"]
    query = report["query"]

    prompt = f"""You are a SOC analyst writing an incident alert. Be extremely concise and technical. No fluff, no generic advice.

DETECTED QUERY: {query}
CLASSIFICATION: {attack} (confidence: {conf}%)
MITRE: {mitre['technique']} — {mitre['name']}
SHAP TRIGGERS: {tokens}

Write EXACTLY in this format (4 short lines):
Threat: [One sentence — what this specific query does and the attacker's exact goal]
Reason: [One sentence — why this was flagged, referencing actual patterns found]
Key Signals: [Comma-separated list of the specific suspicious tokens/patterns]
Recommendation: [One sentence — the exact immediate response step for this specific attack]
"""

    try:
        import requests

        if not OPENROUTER_API_KEY:
            log.warning("OPENROUTER_API_KEY not set — using fallback explanation")
            return generate_fallback_explanation(report)

        response = requests.post(
            f"{OPENROUTER_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://sqli-xai-llm-demo.onrender.com",
                "X-Title": "QueryGuard",
            },
            json={
                "model": OPENROUTER_MODEL,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 300,
                "stream": False,
            },
            timeout=LLM_TIMEOUT,
        )

        if response.status_code == 200:
            data = response.json()
            text = data["choices"][0]["message"]["content"].strip()
            if text and len(text) > 20:
                log.info(f"LLM explanation generated via OpenRouter ({len(text)} chars)")
                return text
            log.warning("OpenRouter returned empty or too-short response, using fallback")
        else:
            log.warning(f"OpenRouter returned HTTP {response.status_code}: {response.text[:300]}")

    except Exception as e:
        log.warning(f"OpenRouter call failed: {e}")

    return generate_fallback_explanation(report)


def generate_fallback_explanation(report: dict) -> str:
    attack = report["attack_type"]
    conf = report["confidence"]
    mitre = report["mitre"]
    tokens = ", ".join([t["token"] for t in report["xai_tokens"][:4]])

    attack_descriptions = {
        "auth_bypass": (
            "Authentication bypass via tautology injection",
            "the query contains a logical tautology that always evaluates to true, bypassing authentication checks",
            "Verify authentication logic is not vulnerable to boolean injection. Review parameterized query usage on the affected endpoint.",
        ),
        "union_based": (
            "UNION-based data exfiltration attempt",
            "the query appends a UNION SELECT to extract data from other database tables, potentially exposing credentials or sensitive records",
            "Block the source IP immediately. Audit database access logs for successful exfiltration and check if the UNION query returned data to the attacker.",
        ),
        "blind_time": (
            "Time-based blind SQL injection probe",
            "the query uses time delay functions to infer database content by measuring response latency",
            "Monitor for repeated slow-response requests from this source. The attacker is likely automating extraction — block the IP and review WAF rules.",
        ),
        "blind_boolean": (
            "Boolean-based blind SQL injection",
            "the query uses conditional expressions to infer database content based on true/false response differences",
            "Check for repeated similar requests with varying conditions. This indicates active data extraction — block and investigate the source.",
        ),
        "error_based": (
            "Error-based SQL injection for data extraction",
            "the query triggers deliberate database errors to leak internal schema and data through error messages",
            "Ensure database error messages are not exposed to clients. Review the affected endpoint for proper error handling.",
        ),
        "stacked_queries": (
            "Stacked query injection — potential destructive operation",
            "the query chains multiple SQL statements using semicolons, potentially executing DROP, DELETE, or system commands",
            "CRITICAL: Verify database integrity immediately. Check for data loss or unauthorized modifications. Block the source and review execution logs.",
        ),
        "evasion": (
            "Obfuscated SQL injection with evasion techniques",
            "the query uses encoding, comments, or character manipulation to bypass WAF and signature-based detection",
            "Update WAF rules to handle the detected evasion technique. Investigate whether prior attacks from this source bypassed detection.",
        ),
        "other": (
            "SQL injection attempt detected",
            "the query contains suspicious SQL patterns that indicate an injection attempt",
            "Review the query against the application's expected input format. Block the source if repeated attempts are observed.",
        ),
    }

    desc = attack_descriptions.get(attack, attack_descriptions["other"])

    return (
        f"Threat: {desc[0]} detected with {conf:.1f}% confidence "
        f"(MITRE {mitre['technique']} — {mitre['name']}).\n"
        f"Reason: {desc[1]}.\n"
        f"Key Signals: {tokens}.\n"
        f"Recommendation: {desc[2]}"
    )


# ══════════════════════════════════════════════════════════════════
# Main Detection Function
# ══════════════════════════════════════════════════════════════════

def detect(query: str) -> dict:
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not query or not isinstance(query, str):
        return _error_response("", timestamp, "invalid query")

    query = query.strip()
    if len(query) == 0:
        return _error_response("", timestamp, "empty query")

    if len(query) > MAX_QUERY_LENGTH:
        query = query[:MAX_QUERY_LENGTH]
        log.warning(f"Query truncated to {MAX_QUERY_LENGTH} chars")

    try:
        vec1 = build_inference_features(query, vectorizer1)
        proba = model1.predict_proba(vec1)[0]
        confidence = float(proba[1]) * 100
        is_sqli = confidence >= THRESHOLD

        attack_type = "normal"
        mitre = None

        if is_sqli:
            vec2 = build_inference_features(query, vectorizer2)
            attack_type = model2.predict(vec2)[0]
            mitre = MITRE_MAP.get(attack_type, MITRE_MAP["other"])

        xai_tokens = []
        if is_sqli and explainer1 is not None:
            try:
                shap_values = explainer1.shap_values(vec1)
                shap_array = shap_values[0] if isinstance(shap_values, list) else shap_values[0]
                tfidf_names = list(vectorizer1.get_feature_names_out())
                all_names = tfidf_names + STRUCTURAL_FEATURE_NAMES
                xai_tokens = generate_xai_tokens(query, vec1, shap_array, all_names)
                log.info(f"XAI generated: {len(xai_tokens)} tokens")
            except Exception as e:
                log.error(f"SHAP/XAI failed: {e}")
                xai_tokens = _fallback_xai_tokens(query)

        llm_explanation = None
        if is_sqli:
            try:
                llm_explanation = get_llm_explanation({
                    "query": query,
                    "attack_type": attack_type,
                    "confidence": round(confidence, 2),
                    "mitre": mitre,
                    "xai_tokens": xai_tokens,
                })
            except Exception as e:
                log.error(f"LLM explanation failed: {e}")
                llm_explanation = generate_fallback_explanation({
                    "query": query,
                    "attack_type": attack_type,
                    "confidence": round(confidence, 2),
                    "mitre": mitre,
                    "xai_tokens": xai_tokens,
                })

        elapsed = round(time.time() - start_time, 3)

        report = {
            "query": query,
            "timestamp": timestamp,
            "is_sqli": bool(is_sqli),
            "confidence": round(confidence, 2),
            "label": "SQLi Detected" if is_sqli else "Normal",
            "attack_type": attack_type,
            "severity": mitre["severity"] if mitre else "none",
            "mitre": mitre,
            "xai_tokens": xai_tokens,
            "llm_explanation": llm_explanation,
        }

        if is_sqli:
            log.info(f"SQLi detected: type={attack_type} conf={confidence:.1f}% elapsed={elapsed}s")
        else:
            log.info(f"Safe query: conf={confidence:.1f}% elapsed={elapsed}s")

        return report

    except Exception as e:
        log.exception("Detection pipeline error")
        return _error_response(query, timestamp, str(e))


def _error_response(query: str, timestamp: str, error_message: str) -> dict:
    return {
        "query": query,
        "timestamp": timestamp,
        "is_sqli": False,
        "confidence": 0.0,
        "label": "Engine Error",
        "attack_type": "engine_error",
        "severity": "high",
        "mitre": None,
        "xai_tokens": [],
        "llm_explanation": None,
        "pipeline_error": True,
        "error": error_message,
    }


def _fallback_xai_tokens(query: str) -> list:
    tokens = []
    for pattern, label in SQL_PATTERNS[:15]:
        if re.search(pattern, query):
            tokens.append({"token": label, "shap": 0.5, "direction": "sqli"})
        if len(tokens) >= 4:
            break
    if not tokens:
        tokens.append({"token": "suspicious pattern", "shap": 0.3, "direction": "sqli"})
    return tokens


if __name__ == "__main__":
    test_queries = [
        "SELECT * FROM users WHERE id = 1",
        "' OR '1'='1",
        "1 UNION SELECT username, password FROM admin--",
        "' AND SLEEP(5)--",
    ]

    for query in test_queries:
        result = detect(query)
        print(f"\n{'─'*60}")
        print(f"Query: {query}")
        print(f"SQLi:  {result['is_sqli']}")
        print(f"Conf:  {result['confidence']}%")
        print(f"Type:  {result['attack_type']}")
        print(f"Sev:   {result['severity']}")
        if result.get("mitre"):
            print(f"MITRE: {result['mitre']['technique']} — {result['mitre']['name']}")
        print(f"XAI:   {result['xai_tokens'][:3]}")
        if result.get("pipeline_error"):
            print(f"ERR:   {result.get('error')}")
        elif result['llm_explanation']:
            print(f"LLM:   {result['llm_explanation'][:150]}...")
        else:
            print("LLM:   (not needed — safe query)")
