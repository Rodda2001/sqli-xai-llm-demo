
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter
from scipy.sparse import hstack, csr_matrix
 
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    accuracy_score, precision_score, recall_score, f1_score
)
 
import warnings
warnings.filterwarnings("ignore")
 
# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from preprocessing import normalize_query, extract_structural_features, NUM_STRUCTURAL_FEATURES, STRUCTURAL_FEATURE_NAMES
 
BASE_DIR    = os.path.dirname(os.path.dirname(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "datasets")
MODEL_DIR   = os.path.join(BASE_DIR, "models")
OUTPUT_DIR  = os.path.join(BASE_DIR, "outputs")
DATA_PATH   = os.path.join(DATASET_DIR, "cleaned.csv")
 
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
 
def log(msg, color=CYAN):
    print(f"{color}{msg}{RESET}")
 
 
# Feature combination helper 
def build_features(queries, vectorizer, fit=False):
  
    # Normalize queries
    normalized = [normalize_query(q) for q in queries]
    
    # TF-IDF
    if fit:
        tfidf_matrix = vectorizer.fit_transform(normalized)
    else:
        tfidf_matrix = vectorizer.transform(normalized)
    
    # Structural features
    struct_array = np.array([extract_structural_features(q) for q in normalized])
    struct_sparse = csr_matrix(struct_array)
    
    # Combine
    combined = hstack([tfidf_matrix, struct_sparse])
    return combined
 
 
def load_data():
    log("\n── Loading Dataset")
    if not os.path.exists(DATA_PATH):
        log(f"  Dataset not found at {DATA_PATH}", RED)
        sys.exit(1)
 
    df = pd.read_csv(DATA_PATH)
    log(f"  Loaded {len(df)} rows", GREEN)
    log(f"  Columns: {list(df.columns)}", CYAN)
 
    counts = Counter(df["label"].astype(int))
    log(f"  Normal: {counts[0]}  SQLi: {counts[1]}", CYAN)
    return df
 
 
def train_model1(df):
    log("\n── Step 2: Training Model 1 (Binary Detection)")
 
    X_raw = df["query"].values
    y     = df["label"].astype(int).values
 
    # Split with reproducible seed
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, random_state=42, stratify=y
    )
    log(f"  Train: {len(X_train_raw)}  Test: {len(X_test_raw)}", CYAN)
 
    # Vectorizer
    log("  Vectorizing (char n-gram TF-IDF + structural features)...", CYAN)
    vectorizer = TfidfVectorizer(
        analyzer     = "char_wb",
        ngram_range  = (2, 5),
        max_features = 15000,
        sublinear_tf = True,
        min_df       = 3,
    )
 
    X_train = build_features(X_train_raw, vectorizer, fit=True)
    X_test  = build_features(X_test_raw, vectorizer, fit=False)
 
    # Train
    log("  Training Logistic Regression...", CYAN)
    model = LogisticRegression(
        C            = 10.0,
        class_weight = "balanced",
        max_iter     = 1000,
        solver       = "lbfgs",
        random_state = 42,
    )
    model.fit(X_train, y_train)
 
    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
 
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
 
    log(f"\n  Accuracy  : {acc*100:.2f}%", GREEN)
    log(f"  Precision : {prec*100:.2f}%", GREEN)
    log(f"  Recall    : {rec*100:.2f}%", GREEN)
    log(f"  F1-Score  : {f1*100:.2f}%", GREEN)
    log(f"  ROC-AUC   : {auc:.4f}", GREEN)
 
    # Cross validation
    log("\n  Running 5-fold cross validation...", CYAN)
    cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="roc_auc")
    log(f"  CV AUC scores: {[round(s,4) for s in cv_scores]}", CYAN)
    log(f"  Mean: {cv_scores.mean():.4f}  Std: {cv_scores.std():.4f}", GREEN)
 
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    log(f"\n  Confusion Matrix:", CYAN)
    log(f"  True Normal : {cm[0][0]:>5}  False SQLi : {cm[0][1]:>5}", GREEN)
    log(f"  Missed SQLi : {cm[1][0]:>5}  True SQLi  : {cm[1][1]:>5}", GREEN)
 
    report_text = classification_report(y_test, y_pred, target_names=["Normal", "SQLi"])
    log(f"\n{report_text}", GREEN)
 
    # ── Save evaluation artifacts ──
    os.makedirs(OUTPUT_DIR, exist_ok=True)
 
    # Classification report
    with open(os.path.join(OUTPUT_DIR, "model1_classification_report.txt"), "w") as f:
        f.write("Model 1 — Binary SQLi Detection\n")
        f.write("=" * 50 + "\n\n")
        f.write(report_text)
        f.write(f"\nAccuracy:  {acc*100:.2f}%\n")
        f.write(f"ROC-AUC:   {auc:.4f}\n")
        f.write(f"CV AUC:    {cv_scores.mean():.4f} ± {cv_scores.std():.4f}\n")
 
    # Confusion matrix plot
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        
        fig, ax = plt.subplots(figsize=(6, 5))
        im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        ax.set_title("Model 1 — Confusion Matrix", fontsize=13)
        ax.set_xlabel("Predicted", fontsize=11)
        ax.set_ylabel("Actual", fontsize=11)
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Normal", "SQLi"])
        ax.set_yticklabels(["Normal", "SQLi"])
        for i in range(2):
            for j in range(2):
                color = "white" if cm[i, j] > cm.max() / 2 else "black"
                ax.text(j, i, str(cm[i, j]), ha="center", va="center", color=color, fontsize=14)
        fig.colorbar(im)
        fig.tight_layout()
        fig.savefig(os.path.join(OUTPUT_DIR, "confusion_matrix_model1.png"), dpi=150)
        plt.close(fig)
        log("  ✓ Confusion matrix plot saved", GREEN)
    except Exception as e:
        log(f"  ⚠ Could not save confusion matrix plot: {e}", YELLOW)
 
    # ── Save SHAP background sample ──
    log("  Saving SHAP background sample...", CYAN)
    try:
        import shap
        bg_idx = np.random.RandomState(42).choice(X_train.shape[0], size=min(200, X_train.shape[0]), replace=False)
        bg_sample = X_train[bg_idx].toarray()
        np.savez_compressed(
            os.path.join(MODEL_DIR, "shap_background.npz"),
            data=bg_sample
        )
        log("  ✓ SHAP background sample saved (200 rows)", GREEN)
    except Exception as e:
        log(f"  ⚠ Could not save SHAP background: {e}", YELLOW)
 
    # ── Sample predictions ──
    with open(os.path.join(OUTPUT_DIR, "sample_predictions.txt"), "w") as f:
        f.write("Sample Predictions — Model 1\n")
        f.write("=" * 60 + "\n\n")
        sample_idx = np.random.RandomState(42).choice(len(X_test_raw), size=min(20, len(X_test_raw)), replace=False)
        for idx in sample_idx:
            q = X_test_raw[idx]
            pred = y_pred[idx]
            prob = y_prob[idx]
            actual = y_test[idx]
            status = "✓" if pred == actual else "✗"
            f.write(f"{status} Query: {q[:100]}{'...' if len(q)>100 else ''}\n")
            f.write(f"  Actual: {'SQLi' if actual else 'Normal'}  Predicted: {'SQLi' if pred else 'Normal'}  Prob(SQLi): {prob:.4f}\n\n")
 
    metrics1 = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "cv_auc_mean": round(cv_scores.mean(), 4),
        "cv_auc_std": round(cv_scores.std(), 4),
        "confusion_matrix": cm.tolist(),
        "train_size": len(X_train_raw),
        "test_size": len(X_test_raw),
    }
 
    return model, vectorizer, metrics1
 
 
def prepare_model2_data(df):
    log("\n── Step 3: Preparing Attack Type Data")
 
    sqli_df = df[df["label"] == 1].copy()
    log(f"  SQLi queries: {len(sqli_df)}", CYAN)
 
    # Merge tiny classes into "other"
    type_counts = Counter(sqli_df["attack_type"])
    min_class_size = 50  
    
    merge_map = {}
    for atype, count in type_counts.items():
        if count < min_class_size and atype != "other":
            merge_map[atype] = "other"
    
    if merge_map:
        log(f"  Merging small classes into 'other': {merge_map}", YELLOW)
        sqli_df["attack_type"] = sqli_df["attack_type"].replace(merge_map)
 
    log("  Attack type distribution (after merge):", CYAN)
    counts = Counter(sqli_df["attack_type"])
    for attack, count in sorted(counts.items(), key=lambda x: -x[1]):
        log(f"    {attack:<20} {count}", GREEN)
 
    return sqli_df, dict(counts), merge_map
 
 
def train_model2(sqli_df):
    log("\n── Step 4: Training Model 2 (Subtype Classification)")
 
    X_raw = sqli_df["query"].values
    y     = sqli_df["attack_type"].values
 
    # Split
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, random_state=42, stratify=y
    )
    log(f"  Train: {len(X_train_raw)}  Test: {len(X_test_raw)}", CYAN)
 
    # Vectorizer
    log("  Vectorizing (char n-gram TF-IDF + structural features)...", CYAN)
    vectorizer = TfidfVectorizer(
        analyzer     = "char_wb",
        ngram_range  = (2, 5),
        max_features = 8000,
        sublinear_tf = True,
        min_df       = 2,
    )
 
    X_train = build_features(X_train_raw, vectorizer, fit=True)
    X_test  = build_features(X_test_raw, vectorizer, fit=False)
 
    # Train
    log("  Training Logistic Regression...", CYAN)
    model = LogisticRegression(
        C            = 10.0,
        class_weight = "balanced",
        max_iter     = 1000,
        solver       = "lbfgs",
        random_state = 42,
    )
    model.fit(X_train, y_train)
 
    # Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
 
    log(f"\n  Accuracy : {acc*100:.2f}%", GREEN)
 
    labels = sorted(set(y_test) | set(y_pred))
    report_text = classification_report(y_test, y_pred, labels=labels, zero_division=0)
    log(f"\n{report_text}", GREEN)
 
    # Save artifacts
    os.makedirs(OUTPUT_DIR, exist_ok=True)
 
    with open(os.path.join(OUTPUT_DIR, "model2_classification_report.txt"), "w") as f:
        f.write("Model 2 — SQLi Subtype Classification\n")
        f.write("=" * 50 + "\n\n")
        f.write(report_text)
        f.write(f"\nAccuracy: {acc*100:.2f}%\n")
 
    # Confusion matrix plot
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
 
        cm = confusion_matrix(y_test, y_pred, labels=labels)
        fig, ax = plt.subplots(figsize=(8, 7))
        im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        ax.set_title("Model 2 — Subtype Confusion Matrix", fontsize=13)
        ax.set_xlabel("Predicted", fontsize=11)
        ax.set_ylabel("Actual", fontsize=11)
        ax.set_xticks(range(len(labels)))
        ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=9)
        ax.set_yticklabels(labels, fontsize=9)
        for i in range(len(labels)):
            for j in range(len(labels)):
                color = "white" if cm[i, j] > cm.max() / 2 else "black"
                ax.text(j, i, str(cm[i, j]), ha="center", va="center", color=color, fontsize=10)
        fig.colorbar(im)
        fig.tight_layout()
        fig.savefig(os.path.join(OUTPUT_DIR, "confusion_matrix_model2.png"), dpi=150)
        plt.close(fig)
        log("  ✓ Model 2 confusion matrix plot saved", GREEN)
    except Exception as e:
        log(f"  ⚠ Could not save model 2 confusion matrix plot: {e}", YELLOW)
 
    # Metrics dict
    report_dict = classification_report(y_test, y_pred, labels=labels, output_dict=True, zero_division=0)
    metrics2 = {
        "accuracy": round(acc, 4),
        "macro_precision": round(report_dict.get("macro avg", {}).get("precision", 0), 4),
        "macro_recall": round(report_dict.get("macro avg", {}).get("recall", 0), 4),
        "macro_f1": round(report_dict.get("macro avg", {}).get("f1-score", 0), 4),
        "weighted_f1": round(report_dict.get("weighted avg", {}).get("f1-score", 0), 4),
        "classes": labels,
        "train_size": len(X_train_raw),
        "test_size": len(X_test_raw),
    }
 
    return model, vectorizer, metrics2
 
 
def save_models(model1, vec1, model2, vec2):
    log("\n── Step 5: Saving Models")
    os.makedirs(MODEL_DIR, exist_ok=True)
 
    joblib.dump(model1, os.path.join(MODEL_DIR, "model1.joblib"))
    joblib.dump(vec1,   os.path.join(MODEL_DIR, "vectorizer1.joblib"))
    joblib.dump(model2, os.path.join(MODEL_DIR, "model2.joblib"))
    joblib.dump(vec2,   os.path.join(MODEL_DIR, "vectorizer2.joblib"))
 
    log("  ✓ model1.joblib saved", GREEN)
    log("  ✓ vectorizer1.joblib saved", GREEN)
    log("  ✓ model2.joblib saved", GREEN)
    log("  ✓ vectorizer2.joblib saved", GREEN)
    log(f"\n  All models saved → {MODEL_DIR}", GREEN)
 
 
def save_meta_and_report(df, metrics1, metrics2, subtype_dist, merge_map):
    log("\n── Step 6: Saving Metadata and Training Report")
 
    threshold = 70.0
 
    # meta.json
    meta = {
        "threshold": threshold,
        "num_structural_features": NUM_STRUCTURAL_FEATURES,
        "structural_feature_names": STRUCTURAL_FEATURE_NAMES,
        "model1_type": "LogisticRegression",
        "model2_type": "LogisticRegression",
        "vectorizer1_type": "TfidfVectorizer(char_wb, 2-5, max=15000)",
        "vectorizer2_type": "TfidfVectorizer(char_wb, 2-5, max=8000)",
        "trained_at": datetime.now().isoformat(),
        "version": "2.0",
    }
    with open(os.path.join(MODEL_DIR, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    log("  ✓ meta.json saved", GREEN)
 
    # training_report.json
    class_dist = Counter(df["label"].astype(int))
    source_dist = {}
    if "_source" in df.columns:
        for src in df["_source"].unique():
            src_counts = Counter(df[df["_source"] == src]["label"].astype(int))
            source_dist[src] = {"normal": int(src_counts.get(0, 0)), "sqli": int(src_counts.get(1, 0))}
 
    report = {
        "generated_at": datetime.now().isoformat(),
        "dataset": {
            "total_rows": len(df),
            "normal_count": int(class_dist[0]),
            "sqli_count": int(class_dist[1]),
            "per_source": source_dist,
        },
        "preprocessing": {
            "normalization": "whitespace_collapse + lowercase + url_decode",
            "features": "char_wb TF-IDF (2,5) + 10 structural features",
            "structural_features": STRUCTURAL_FEATURE_NAMES,
        },
        "train_test_split": {
            "test_size": 0.2,
            "random_state": 42,
            "stratified": True,
        },
        "model1": {
            "type": "LogisticRegression",
            "params": {"C": 1.0, "class_weight": "balanced", "solver": "lbfgs"},
            "threshold": threshold,
            "metrics": metrics1,
        },
        "model2": {
            "type": "LogisticRegression",
            "params": {"C": 1.0, "class_weight": "balanced", "solver": "lbfgs"},
            "subtype_distribution": {k: int(v) for k, v in subtype_dist.items()},
            "merge_map": merge_map,
            "metrics": metrics2,
        },
    }
 
    with open(os.path.join(MODEL_DIR, "training_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    log("  ✓ training_report.json saved", GREEN)
 
 
if __name__ == "__main__":
    log("\n╔══════════════════════════════════════════╗", CYAN)
    log("║     FileSense — Model Training v2        ║", CYAN)
    log("╚══════════════════════════════════════════╝\n", CYAN)
 
    df = load_data()
    model1, vec1, metrics1 = train_model1(df)
    sqli_df, subtype_dist, merge_map = prepare_model2_data(df)
    model2, vec2, metrics2 = train_model2(sqli_df)
    save_models(model1, vec1, model2, vec2)
    save_meta_and_report(df, metrics1, metrics2, subtype_dist, merge_map)
 
    log("\n✓ Training complete! All models and artifacts saved.\n", GREEN)
 