

import os
import re
import sys
import pandas as pd
import numpy as np
from collections import Counter


sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from preprocessing import normalize_query

BASE_DIR    = os.path.dirname(os.path.dirname(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "datasets")

DATASETS = [
    (os.path.join(DATASET_DIR, "sqli.csv"),   "utf-16",  "sqli_v1"),
    (os.path.join(DATASET_DIR, "sqliv2.csv"), "utf-16",  "sqli_v2"),
    (os.path.join(DATASET_DIR, "SQLiV3.csv"), "latin-1", "sqli_v3"),
]

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def log(msg, color=CYAN):
    print(f"{color}{msg}{RESET}")


def load_datasets():
    log("\n── Step 1: Loading Datasets")
    all_data = []

    for path, encoding, source_name in DATASETS:
        try:
            df = pd.read_csv(path, encoding=encoding, on_bad_lines="skip")
            df["_source"] = source_name
            log(f"  ✓ Loaded {os.path.basename(path)} — {len(df)} rows ({len(df.columns)} cols)", GREEN)
            all_data.append(df)
        except Exception as e:
            log(f"  ✗ Failed to load {os.path.basename(path)}: {e}", RED)
            sys.exit(1)

    combined = pd.concat(all_data, ignore_index=True)
    log(f"\n  Total rows combined: {len(combined)}", CYAN)
    return combined


def repair_and_clean(df):
    log("\n── Step 2: Repairing and Cleaning Data")

    # Identify query and label columns
    query_col = None
    label_col = None
    for col in df.columns:
        cl = col.lower().strip()
        if cl in ["query", "sentence", "text"] and query_col is None:
            query_col = col
        if cl in ["label", "class", "target"] and label_col is None:
            label_col = col

    if not query_col or not label_col:
        log(f"  Could not find columns. Found: {list(df.columns)}", RED)
        sys.exit(1)

    log(f"  Query column: {query_col}", GREEN)
    log(f"  Label column: {label_col}", GREEN)

    # Repair: some datasets have label spilling into unnamed cols
    unnamed_cols = [c for c in df.columns if "unnamed" in c.lower() or c.strip() == ""]
    
    def repair_label(row):
        raw_label = row[label_col]
        val = pd.to_numeric(raw_label, errors="coerce")
        if not np.isnan(val) and val in (0, 1):
            return int(val)
        for uc in unnamed_cols:
            if uc in row.index:
                fallback = pd.to_numeric(row[uc], errors="coerce")
                if not np.isnan(fallback) and fallback in (0, 1):
                    return int(fallback)
        return np.nan

    df["_label"] = df.apply(repair_label, axis=1)
    
    repaired = df["_label"].notna().sum()
    original_valid = pd.to_numeric(df[label_col], errors="coerce").isin([0, 1]).sum()
    log(f"  Labels repaired: {repaired - original_valid} additional rows recovered", GREEN)

    clean = pd.DataFrame({
        "query":   df[query_col].astype(str).str.strip(),
        "label":   df["_label"],
        "_source": df["_source"],
    })

    before = len(clean)
    clean = clean.dropna(subset=["label"])
    clean["label"] = clean["label"].astype(int)
    clean = clean[clean["query"].str.len() > 2]
    clean = clean[clean["query"] != "nan"]
    after_basic = len(clean)
    log(f"  Removed {before - after_basic} rows with bad labels/empty queries", GREEN)

    # Deduplicate on normalized query
    clean["_norm"] = clean["query"].apply(normalize_query)
    before_dedup = len(clean)
    clean = clean.drop_duplicates(subset=["_norm"])
    after_dedup = len(clean)
    log(f"  Deduplicated: {before_dedup - after_dedup} near-duplicates removed", GREEN)
    clean = clean.drop(columns=["_norm"])

    log(f"  Clean rows: {len(clean)}", GREEN)
    counts = Counter(clean["label"])
    log(f"  Normal: {counts[0]}  SQLi: {counts[1]}", CYAN)

    # Per-source breakdown
    log("  Per-source breakdown:", CYAN)
    for src in sorted(clean["_source"].unique()):
        src_df = clean[clean["_source"] == src]
        src_counts = Counter(src_df["label"])
        log(f"    {src:<12} total={len(src_df):>6}  normal={src_counts.get(0,0):>6}  sqli={src_counts.get(1,0):>6}", GREEN)

    return clean


def label_attack_type(query):
    """Improved SQLi subtype labeling with better coverage."""
    q = query.upper()

    # Time-based blind
    if re.search(r"SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|PG_SLEEP\s*\(", q):
        return "blind_time"

    # Error-based
    if re.search(r"EXTRACTVALUE\s*\(|UPDATEXML\s*\(|FLOOR\s*\(\s*RAND|EXP\s*\(\s*~|CONVERT\s*\(.*INT", q):
        return "error_based"

    # Stacked queries / destructive
    if re.search(r";\s*(DROP|DELETE|INSERT|UPDATE|EXEC|CREATE|ALTER|TRUNCATE)\b|XP_CMDSHELL|SHUTDOWN", q):
        return "stacked_queries"

    # Union-based
    if re.search(r"UNION\s+(ALL\s+)?SELECT", q):
        return "union_based"

    # Evasion / encoding
    if re.search(r"/\*\*/|/\*!|0X[0-9A-F]{2,}|CHAR\s*\(\s*\d+|UNHEX\s*\(|HEX\s*\(", q):
        return "evasion"

    # Boolean-based blind
    if re.search(r"AND\s+\d+\s*=\s*\d+|AND\s+\(SELECT|AND\s+ASCII\s*\(|AND\s+SUBSTR|AND\s+LENGTH|AND\s+ORD\s*\(|IF\s*\(", q):
        return "blind_boolean"

    # Auth bypass — tautology patterns
    if re.search(r"OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|OR\s+['\"][^'\"]*['\"]\s*=\s*['\"]|OR\s+TRUE|OR\s+NOT\s+FALSE|'\s*OR\s*'", q):
        return "auth_bypass"

    # Fallback: generic other
    return "other"


def label_attacks(df):
    log("\n── Step 3: Labeling Attack Subtypes")

    sqli_df   = df[df["label"] == 1].copy()
    normal_df = df[df["label"] == 0].copy()

    sqli_df["attack_type"]   = sqli_df["query"].apply(label_attack_type)
    normal_df["attack_type"] = "normal"

    df = pd.concat([sqli_df, normal_df], ignore_index=True)

    log("  Attack type distribution:", CYAN)
    counts = Counter(df["attack_type"])
    for attack, count in sorted(counts.items(), key=lambda x: -x[1]):
        pct = count / len(df) * 100
        log(f"    {attack:<20} {count:>6}  ({pct:.1f}%)", GREEN)

    return df


def save_data(df):
    log("\n── Step 4: Saving Cleaned Dataset")

    output_path = os.path.join(DATASET_DIR, "cleaned.csv")
    df.to_csv(output_path, index=False)

    log(f"  Saved → {output_path}", GREEN)
    log(f"  Total rows: {len(df)}", GREEN)
    log(f"  Columns: {list(df.columns)}", CYAN)


if __name__ == "__main__":
    log("\n╔══════════════════════════════════════════╗", CYAN)
    log("║     FileSense — Data Preparation v2      ║", CYAN)
    log("╚══════════════════════════════════════════╝\n", CYAN)

    df = load_datasets()
    df = repair_and_clean(df)
    df = label_attacks(df)
    save_data(df)

    log("\n✓ Done\n", GREEN)
