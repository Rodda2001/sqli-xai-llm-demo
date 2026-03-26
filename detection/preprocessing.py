"""
FileSense — Shared Preprocessing Module
========================================
Single source of truth for query normalization used in:
  - dataset preparation (prepare.py)
  - model training (train_one.py)
  - inference (detect.py)

This ensures zero train/inference drift.
"""

import re
import numpy as np
from urllib.parse import unquote


# ── URL decoding (safe, partial) ──────────────────────────────────
def safe_url_decode(text: str) -> str:
    """Decode common URL-encoded fragments without destroying SQL structure."""
    try:
        decoded = unquote(text)
        # Only accept the decode if it didn't produce null bytes or binary junk
        if '\x00' in decoded:
            return text
        return decoded
    except Exception:
        return text


# ── Core normalizer ───────────────────────────────────────────────
def normalize_query(query: str) -> str:
    """
    Normalize a SQL query for ML consumption.
    
    Preserves:
      - SQL injection patterns (quotes, operators, comments, tautologies, UNION, etc.)
      - SQL keywords and structure
      - Semicolons, comment markers (-- # /*), quote characters
    
    Normalizes:
      - whitespace (collapse runs to single space)
      - URL-encoded fragments
      - case (lowercase) — safe because SQL keywords are case-insensitive
        and char n-gram TF-IDF operates on character sequences
    """
    if not isinstance(query, str):
        query = str(query)
    
    query = query.strip()
    if not query:
        return ""
    
    # Step 1: safe URL decode
    query = safe_url_decode(query)
    
    # Step 2: collapse whitespace (preserve single spaces)
    query = re.sub(r'\s+', ' ', query)
    
    # Step 3: lowercase (safe for char n-gram TF-IDF; preserves pattern structure)
    query = query.lower()
    
    return query.strip()


# ── Structural feature extraction ─────────────────────────────────
# Suspicious SQL keywords/functions for structural features
SUSPICIOUS_KEYWORDS = [
    'union', 'select', 'sleep', 'benchmark', 'waitfor', 'drop', 'delete',
    'insert', 'update', 'exec', 'xp_cmdshell', 'information_schema',
    'load_file', 'outfile', 'into', 'concat', 'group_concat',
    'extractvalue', 'updatexml', 'pg_sleep', 'char', 'ascii',
    'substring', 'floor', 'rand', 'exp',
]

SUSPICIOUS_FUNCTIONS = [
    'sleep(', 'benchmark(', 'pg_sleep(', 'waitfor ',
    'extractvalue(', 'updatexml(', 'load_file(',
    'concat(', 'group_concat(', 'char(', 'ascii(',
    'substring(', 'xp_cmdshell',
]


def extract_structural_features(query: str) -> np.ndarray:
    """
    Extract lightweight structural features from a (normalized) query.
    Returns a fixed-length numpy array of 10 features:
      0: query_length (log-scaled)
      1: single_quote_count
      2: double_quote_count
      3: comment_marker_count (-- or # or /*)
      4: semicolon_count
      5: suspicious_keyword_count
      6: suspicious_function_count
      7: equals_operator_count
      8: parenthesis_count
      9: hex_or_encoded_count
    """
    q = query.lower() if query else ""
    
    features = np.zeros(10, dtype=np.float64)
    
    # 0: query length (log-scaled to avoid magnitude issues)
    features[0] = np.log1p(len(q))
    
    # 1: single quote count
    features[1] = q.count("'")
    
    # 2: double quote count
    features[2] = q.count('"')
    
    # 3: comment markers
    features[3] = (
        q.count('--') +
        q.count('#') +
        len(re.findall(r'/\*', q))
    )
    
    # 4: semicolons
    features[4] = q.count(';')
    
    # 5: suspicious keyword count
    features[5] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in q)
    
    # 6: suspicious function presence
    features[6] = sum(1 for fn in SUSPICIOUS_FUNCTIONS if fn in q)
    
    # 7: equals operators
    features[7] = q.count('=')
    
    # 8: parenthesis count
    features[8] = q.count('(') + q.count(')')
    
    # 9: hex or encoded patterns
    features[9] = len(re.findall(r'0x[0-9a-f]{2,}', q)) + len(re.findall(r'%[0-9a-f]{2}', q))
    
    return features


# ── Feature name list (for reports) ───────────────────────────────
STRUCTURAL_FEATURE_NAMES = [
    'query_length_log', 'single_quote_count', 'double_quote_count',
    'comment_marker_count', 'semicolon_count', 'suspicious_keyword_count',
    'suspicious_function_count', 'equals_operator_count',
    'parenthesis_count', 'hex_encoded_count',
]

NUM_STRUCTURAL_FEATURES = len(STRUCTURAL_FEATURE_NAMES)
