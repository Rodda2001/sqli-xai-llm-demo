#!/usr/bin/env python3
"""
FileSense — Comprehensive Model Evaluation
============================================
Standalone evaluation script for thesis testing/evaluation chapter.

Produces:
  - Full metrics for Model 1 (binary SQLi detection)
  - Full metrics for Model 2 (subtype classification)
  - Baseline comparison against alternative ML classifiers
  - SHAP/XAI analysis for sample SQLi queries
  - ROC curve, confusion matrices, classification reports
  - Thesis-ready outputs saved to detection/evaluation/

Usage:
    cd SQLI+XAI+LLM
    python detection/scripts/evaluate_models.py

    # Or with custom output dir:
    python detection/scripts/evaluate_models.py --output-dir detection/evaluation

Requirements:
    Same as the existing project: scikit-learn, pandas, numpy, joblib,
    shap, matplotlib, scipy
"""

import os
import sys
import json
import time
import argparse
import warnings
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from collections import Counter, OrderedDict
from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, roc_curve,
    accuracy_score, precision_score, recall_score, f1_score,
    precision_recall_curve, auc,
)
from sklearn.pipeline import Pipeline
from sklearn.base import BaseEstimator, TransformerMixin

warnings.filterwarnings("ignore")

# ── Add project root to path ─────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DETECTION_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, DETECTION_DIR)

from preprocessing import (
    normalize_query, extract_structural_features,
    NUM_STRUCTURAL_FEATURES, STRUCTURAL_FEATURE_NAMES,
)

# ── Paths ─────────────────────────────────────────────────────────
MODEL_DIR   = os.path.join(DETECTION_DIR, "models")
DATASET_DIR = os.path.join(DETECTION_DIR, "datasets")
DATA_PATH   = os.path.join(DATASET_DIR, "cleaned.csv")
META_PATH   = os.path.join(MODEL_DIR, "meta.json")
SHAP_BG     = os.path.join(MODEL_DIR, "shap_background.npz")

# ── Colors ────────────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
B = "\033[1m"; X = "\033[0m"

def log(msg, color=C):
    print(f"{color}{msg}{X}")


# ══════════════════════════════════════════════════════════════════
# Feature Building (matches training pipeline exactly)
# ══════════════════════════════════════════════════════════════════

def build_features(queries, vectorizer, fit=False):
    """Build combined TF-IDF + structural feature matrix."""
    normalized = [normalize_query(q) for q in queries]
    if fit:
        tfidf = vectorizer.fit_transform(normalized)
    else:
        tfidf = vectorizer.transform(normalized)
    struct = csr_matrix(np.array([extract_structural_features(q) for q in normalized]))
    return hstack([tfidf, struct])


class QueryFeatureTransformer(BaseEstimator, TransformerMixin):
    """Sklearn-compatible transformer for Pipeline-based CV."""
    def __init__(self, max_features=15000, ngram_range=(2, 5), min_df=3):
        self.max_features = max_features
        self.ngram_range = ngram_range
        self.min_df = min_df
        self.vectorizer_ = None

    def fit(self, X, y=None):
        normalized = [normalize_query(q) for q in X]
        self.vectorizer_ = TfidfVectorizer(
            analyzer="char_wb", ngram_range=self.ngram_range,
            max_features=self.max_features, sublinear_tf=True, min_df=self.min_df,
        )
        self.vectorizer_.fit(normalized)
        return self

    def transform(self, X):
        normalized = [normalize_query(q) for q in X]
        tfidf = self.vectorizer_.transform(normalized)
        struct = csr_matrix(np.array([extract_structural_features(q) for q in normalized]))
        return hstack([tfidf, struct])


# ══════════════════════════════════════════════════════════════════
# Plotting helpers
# ══════════════════════════════════════════════════════════════════

def save_confusion_matrix(cm, labels, title, path):
    """Save a confusion matrix as a PNG image."""
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(max(6, len(labels)*1.1), max(5, len(labels)*1.0)))
        im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
        ax.set_title(title, fontsize=13, pad=12)
        ax.set_xlabel("Predicted", fontsize=11)
        ax.set_ylabel("Actual", fontsize=11)
        ax.set_xticks(range(len(labels)))
        ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=9)
        ax.set_yticklabels(labels, fontsize=9)
        for i in range(len(labels)):
            for j in range(len(labels)):
                color = "white" if cm[i, j] > cm.max() / 2 else "black"
                ax.text(j, i, str(cm[i, j]), ha="center", va="center", color=color, fontsize=11)
        fig.colorbar(im)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return True
    except Exception as e:
        log(f"  ⚠ Plot failed: {e}", Y)
        return False


def save_roc_curve(y_true, y_prob, title, path):
    """Save ROC curve as PNG."""
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        roc_auc_val = auc(fpr, tpr)
        fig, ax = plt.subplots(figsize=(7, 6))
        ax.plot(fpr, tpr, color="#2563eb", lw=2, label=f"ROC curve (AUC = {roc_auc_val:.4f})")
        ax.plot([0, 1], [0, 1], color="#94a3b8", lw=1, linestyle="--", label="Random baseline")
        ax.set_xlim([-0.01, 1.01])
        ax.set_ylim([-0.01, 1.01])
        ax.set_xlabel("False Positive Rate", fontsize=11)
        ax.set_ylabel("True Positive Rate", fontsize=11)
        ax.set_title(title, fontsize=13)
        ax.legend(loc="lower right", fontsize=10)
        ax.grid(True, alpha=0.3)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return True
    except Exception as e:
        log(f"  ⚠ ROC plot failed: {e}", Y)
        return False


def save_baseline_chart(df_results, path):
    """Save baseline comparison bar chart."""
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        metrics = ["accuracy", "precision", "recall", "f1_score"]
        fig, axes = plt.subplots(1, 4, figsize=(18, 5))
        colors = ["#2563eb", "#7c3aed", "#059669", "#d97706", "#dc2626", "#6366f1"]
        for idx, metric in enumerate(metrics):
            ax = axes[idx]
            vals = df_results[metric].values
            names = df_results["model"].values
            bars = ax.barh(range(len(names)), vals, color=[colors[i % len(colors)] for i in range(len(names))])
            ax.set_yticks(range(len(names)))
            ax.set_yticklabels(names, fontsize=9)
            ax.set_xlim([min(vals.min() - 0.02, 0.9), 1.005])
            ax.set_title(metric.replace("_", " ").title(), fontsize=11, fontweight="bold")
            ax.grid(True, axis="x", alpha=0.3)
            for bar, v in zip(bars, vals):
                ax.text(v + 0.001, bar.get_y() + bar.get_height()/2, f"{v:.4f}", va="center", fontsize=8)
        fig.suptitle("Model 1 — Baseline Comparison", fontsize=14, fontweight="bold", y=1.02)
        fig.tight_layout()
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return True
    except Exception as e:
        log(f"  ⚠ Baseline chart failed: {e}", Y)
        return False


# ══════════════════════════════════════════════════════════════════
# Evaluation Functions
# ══════════════════════════════════════════════════════════════════

def evaluate_model1(df, out_dir):
    """Full evaluation of Model 1 (binary SQLi detection)."""
    log("\n" + "═" * 60)
    log("  MODEL 1 — Binary SQLi Detection Evaluation")
    log("═" * 60)

    # Load saved model + vectorizer
    model1 = joblib.load(os.path.join(MODEL_DIR, "model1.joblib"))
    vec1   = joblib.load(os.path.join(MODEL_DIR, "vectorizer1.joblib"))

    # Load threshold
    threshold = 50.0
    if os.path.exists(META_PATH):
        with open(META_PATH) as f:
            meta = json.load(f)
        threshold = meta.get("threshold", 50.0)
    log(f"  Threshold: {threshold}%", C)

    # Prepare data (same split as training)
    X_raw = df["query"].values
    y     = df["label"].astype(int).values
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, random_state=42, stratify=y
    )
    log(f"  Test set: {len(X_test_raw)} samples", C)

    # Build features using saved vectorizer
    X_test = build_features(X_test_raw, vec1, fit=False)

    # Validate dimensions
    expected = model1.n_features_in_
    actual = X_test.shape[1]
    if expected != actual:
        log(f"  ✗ Feature mismatch: model expects {expected}, got {actual}", R)
        return None
    log(f"  Feature dimensions: {actual} (TF-IDF + {NUM_STRUCTURAL_FEATURES} structural)", G)

    # Predict
    y_prob = model1.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= (threshold / 100.0)).astype(int)

    # Compute metrics
    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    auc_val = roc_auc_score(y_test, y_prob)
    cm   = confusion_matrix(y_test, y_pred)

    log(f"\n  Accuracy  : {acc*100:.2f}%", G)
    log(f"  Precision : {prec*100:.2f}%", G)
    log(f"  Recall    : {rec*100:.2f}%", G)
    log(f"  F1-Score  : {f1*100:.2f}%", G)
    log(f"  ROC-AUC   : {auc_val:.4f}", G)
    log(f"\n  Confusion Matrix:", C)
    log(f"  TN={cm[0][0]:>5}  FP={cm[0][1]:>5}", G)
    log(f"  FN={cm[1][0]:>5}  TP={cm[1][1]:>5}", G)

    report_text = classification_report(y_test, y_pred, target_names=["Normal", "SQLi"])
    log(f"\n{report_text}", G)

    # ── Save artifacts ──
    metrics = {
        "model": "Model 1 — Binary SQLi Detection",
        "type": "LogisticRegression",
        "threshold": threshold,
        "test_size": len(X_test_raw),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc_val, 4),
        "confusion_matrix": {"TN": int(cm[0][0]), "FP": int(cm[0][1]),
                             "FN": int(cm[1][0]), "TP": int(cm[1][1])},
        "false_positive_rate": round(cm[0][1] / max(cm[0].sum(), 1), 4),
        "false_negative_rate": round(cm[1][0] / max(cm[1].sum(), 1), 4),
    }
    with open(os.path.join(out_dir, "metrics_model1.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    with open(os.path.join(out_dir, "classification_report_model1.txt"), "w") as f:
        f.write(f"Model 1 — Binary SQLi Detection\n{'='*50}\n")
        f.write(f"Threshold: {threshold}%\nTest samples: {len(X_test_raw)}\n\n")
        f.write(report_text)
        f.write(f"\nAccuracy:  {acc*100:.2f}%\nROC-AUC:   {auc_val:.4f}\n")

    save_confusion_matrix(cm, ["Normal", "SQLi"],
                          "Model 1 — Confusion Matrix",
                          os.path.join(out_dir, "confusion_matrix_model1.png"))
    save_roc_curve(y_test, y_prob,
                   "Model 1 — ROC Curve",
                   os.path.join(out_dir, "roc_curve_model1.png"))

    # ── Sample predictions (FP + FN + correct) ──
    fp_idx = np.where((y_pred == 1) & (y_test == 0))[0]
    fn_idx = np.where((y_pred == 0) & (y_test == 1))[0]
    tp_idx = np.where((y_pred == 1) & (y_test == 1))[0]
    tn_idx = np.where((y_pred == 0) & (y_test == 0))[0]

    with open(os.path.join(out_dir, "sample_predictions.txt"), "w") as f:
        f.write(f"Sample Predictions — Model 1\n{'='*60}\n")
        f.write(f"Threshold: {threshold}%\n\n")

        f.write(f"── FALSE NEGATIVES (Missed SQLi) — {len(fn_idx)} total ──\n\n")
        for i in fn_idx[:10]:
            f.write(f"  Query: {X_test_raw[i][:120]}\n  Prob(SQLi): {y_prob[i]:.4f}\n\n")

        f.write(f"\n── FALSE POSITIVES (False alarms) — {len(fp_idx)} total ──\n\n")
        for i in fp_idx[:10]:
            f.write(f"  Query: {X_test_raw[i][:120]}\n  Prob(SQLi): {y_prob[i]:.4f}\n\n")

        f.write(f"\n── TRUE POSITIVES (sample) ──\n\n")
        for i in tp_idx[:5]:
            f.write(f"  Query: {X_test_raw[i][:120]}\n  Prob(SQLi): {y_prob[i]:.4f}\n\n")

        f.write(f"\n── TRUE NEGATIVES (sample) ──\n\n")
        for i in tn_idx[:5]:
            f.write(f"  Query: {X_test_raw[i][:120]}\n  Prob(SQLi): {y_prob[i]:.4f}\n\n")

    log("  ✓ Model 1 evaluation artifacts saved", G)
    return {
        "X_train_raw": X_train_raw, "X_test_raw": X_test_raw,
        "y_train": y_train, "y_test": y_test,
        "y_pred": y_pred, "y_prob": y_prob,
        "model": model1, "vectorizer": vec1,
        "metrics": metrics,
    }


def evaluate_model2(df, out_dir):
    """Full evaluation of Model 2 (subtype classification)."""
    log("\n" + "═" * 60)
    log("  MODEL 2 — SQLi Subtype Classification Evaluation")
    log("═" * 60)

    model2 = joblib.load(os.path.join(MODEL_DIR, "model2.joblib"))
    vec2   = joblib.load(os.path.join(MODEL_DIR, "vectorizer2.joblib"))

    sqli_df = df[df["label"] == 1].copy()

    # Merge small classes same as training
    type_counts = Counter(sqli_df["attack_type"])
    for atype, count in type_counts.items():
        if count < 50 and atype != "other":
            sqli_df.loc[sqli_df["attack_type"] == atype, "attack_type"] = "other"

    X_raw = sqli_df["query"].values
    y     = sqli_df["attack_type"].values

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, random_state=42, stratify=y
    )
    log(f"  Test set: {len(X_test_raw)} SQLi samples", C)

    X_test = build_features(X_test_raw, vec2, fit=False)
    y_pred = model2.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    labels = sorted(set(y_test) | set(y_pred))
    report_text = classification_report(y_test, y_pred, labels=labels, zero_division=0)
    report_dict = classification_report(y_test, y_pred, labels=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    log(f"\n  Accuracy: {acc*100:.2f}%", G)
    log(f"\n{report_text}", G)

    metrics = {
        "model": "Model 2 — SQLi Subtype Classification",
        "type": "LogisticRegression",
        "test_size": len(X_test_raw),
        "accuracy": round(acc, 4),
        "macro_precision": round(report_dict["macro avg"]["precision"], 4),
        "macro_recall": round(report_dict["macro avg"]["recall"], 4),
        "macro_f1": round(report_dict["macro avg"]["f1-score"], 4),
        "weighted_precision": round(report_dict["weighted avg"]["precision"], 4),
        "weighted_recall": round(report_dict["weighted avg"]["recall"], 4),
        "weighted_f1": round(report_dict["weighted avg"]["f1-score"], 4),
        "classes": labels,
        "per_class": {lbl: {
            "precision": round(report_dict[lbl]["precision"], 4),
            "recall": round(report_dict[lbl]["recall"], 4),
            "f1": round(report_dict[lbl]["f1-score"], 4),
            "support": int(report_dict[lbl]["support"]),
        } for lbl in labels},
    }
    with open(os.path.join(out_dir, "metrics_model2.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    with open(os.path.join(out_dir, "classification_report_model2.txt"), "w") as f:
        f.write(f"Model 2 — SQLi Subtype Classification\n{'='*50}\n\n")
        f.write(report_text)
        f.write(f"\nAccuracy: {acc*100:.2f}%\n")

    save_confusion_matrix(cm, labels,
                          "Model 2 — Subtype Confusion Matrix",
                          os.path.join(out_dir, "confusion_matrix_model2.png"))

    log("  ✓ Model 2 evaluation artifacts saved", G)
    return metrics


# ══════════════════════════════════════════════════════════════════
# Baseline Comparison
# ══════════════════════════════════════════════════════════════════

def run_baseline_comparison(m1_ctx, out_dir):
    """Compare the deployed LR model against alternative classifiers."""
    log("\n" + "═" * 60)
    log("  BASELINE COMPARISON — Model 1 Alternatives")
    log("═" * 60)

    X_train_raw = m1_ctx["X_train_raw"]
    X_test_raw  = m1_ctx["X_test_raw"]
    y_train     = m1_ctx["y_train"]
    y_test      = m1_ctx["y_test"]

    # Build features fresh for baselines
    vec_baseline = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(2, 5),
        max_features=15000, sublinear_tf=True, min_df=3,
    )
    X_train = build_features(X_train_raw, vec_baseline, fit=True)
    X_test  = build_features(X_test_raw, vec_baseline, fit=False)

    # Ensure non-negative for MultinomialNB
    X_train_nn = X_train.copy(); X_train_nn[X_train_nn < 0] = 0
    X_test_nn  = X_test.copy();  X_test_nn[X_test_nn < 0] = 0

    baselines = OrderedDict([
        ("Logistic Regression (deployed)", LogisticRegression(
            C=10.0, class_weight="balanced", max_iter=1000, solver="lbfgs", random_state=42)),
        ("Linear SVM", CalibratedClassifierCV(
            LinearSVC(C=1.0, class_weight="balanced", max_iter=2000, random_state=42), cv=3)),
        ("SGD Classifier", SGDClassifier(
            loss="modified_huber", class_weight="balanced", max_iter=1000, random_state=42)),
        ("Multinomial NB", None),  # handled separately (non-negative)
        ("Random Forest (n=100)", RandomForestClassifier(
            n_estimators=100, class_weight="balanced", max_depth=30, random_state=42, n_jobs=-1)),
    ])

    results = []

    for name, clf in baselines.items():
        log(f"\n  Training: {name}...", C)
        t0 = time.time()

        try:
            if name == "Multinomial NB":
                clf = MultinomialNB(alpha=0.1)
                clf.fit(X_train_nn, y_train)
                y_pred = clf.predict(X_test_nn)
                y_prob = clf.predict_proba(X_test_nn)[:, 1]
            else:
                clf.fit(X_train, y_train)
                y_pred = clf.predict(X_test)
                if hasattr(clf, "predict_proba"):
                    y_prob = clf.predict_proba(X_test)[:, 1]
                elif hasattr(clf, "decision_function"):
                    y_prob = clf.decision_function(X_test)
                else:
                    y_prob = y_pred.astype(float)

            elapsed = time.time() - t0
            acc  = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec  = recall_score(y_test, y_pred, zero_division=0)
            f1v  = f1_score(y_test, y_pred, zero_division=0)
            try:
                auc_val = roc_auc_score(y_test, y_prob)
            except Exception:
                auc_val = 0.0
            cm = confusion_matrix(y_test, y_pred)

            row = {
                "model": name,
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1v, 4),
                "roc_auc": round(auc_val, 4),
                "FP": int(cm[0][1]),
                "FN": int(cm[1][0]),
                "train_time_s": round(elapsed, 2),
            }
            results.append(row)
            log(f"    Acc={acc:.4f}  Prec={prec:.4f}  Rec={rec:.4f}  F1={f1v:.4f}  AUC={auc_val:.4f}  FN={cm[1][0]}  ({elapsed:.1f}s)", G)

        except Exception as e:
            log(f"    ✗ Failed: {e}", R)
            results.append({"model": name, "accuracy": 0, "precision": 0, "recall": 0,
                            "f1_score": 0, "roc_auc": 0, "FP": 0, "FN": 0, "train_time_s": 0, "error": str(e)})

    df_results = pd.DataFrame(results)
    df_results.to_csv(os.path.join(out_dir, "baseline_comparison.csv"), index=False)
    save_baseline_chart(df_results, os.path.join(out_dir, "baseline_comparison.png"))

    log("\n  ✓ Baseline comparison saved", G)
    return df_results


# ══════════════════════════════════════════════════════════════════
# SHAP / XAI Evaluation
# ══════════════════════════════════════════════════════════════════

def run_shap_evaluation(m1_ctx, out_dir):
    """Generate SHAP explanations for sample SQLi queries."""
    log("\n" + "═" * 60)
    log("  SHAP / XAI Evaluation")
    log("═" * 60)

    model1 = m1_ctx["model"]
    vec1   = m1_ctx["vectorizer"]

    # Load or create SHAP background
    explainer = None
    try:
        import shap
        if os.path.exists(SHAP_BG):
            bg_data = np.load(SHAP_BG)["data"]
            expected = model1.n_features_in_
            if bg_data.shape[1] == expected:
                explainer = shap.LinearExplainer(model1, bg_data)
                log(f"  SHAP background loaded ({bg_data.shape[0]} samples, {bg_data.shape[1]} features)", G)
            else:
                log(f"  ⚠ SHAP background dimension mismatch ({bg_data.shape[1]} vs {expected})", Y)
        if explainer is None:
            fallback = build_features(["select 1"], vec1, fit=False)
            explainer = shap.LinearExplainer(model1, fallback)
            log("  Using single-sample SHAP fallback", Y)
    except ImportError:
        log("  ⚠ SHAP not installed — skipping XAI evaluation", Y)
        return
    except Exception as e:
        log(f"  ⚠ SHAP setup failed: {e}", Y)
        return

    # Get TF-IDF feature names + structural names
    tfidf_names = list(vec1.get_feature_names_out())
    all_names = tfidf_names + STRUCTURAL_FEATURE_NAMES

    # Sample SQLi test queries
    sqli_samples = [
        "' OR '1'='1",
        "1 UNION SELECT username, password FROM users--",
        "' AND SLEEP(5)--",
        "'; DROP TABLE users--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
    ]

    shap_results = []

    for query in sqli_samples:
        try:
            vec_features = build_features([query], vec1, fit=False)
            shap_values = explainer.shap_values(vec_features)
            sv = shap_values[0] if isinstance(shap_values, list) else shap_values[0]

            # Top positive features
            top_idx = np.argsort(sv)[::-1][:10]
            top_features = []
            for idx in top_idx:
                if idx < len(all_names) and sv[idx] > 0:
                    top_features.append((all_names[idx], round(float(sv[idx]), 4)))

            shap_results.append({
                "query": query[:100],
                "top_features": top_features[:6],
                "max_shap": round(float(sv.max()), 4),
                "mean_positive_shap": round(float(np.mean(sv[sv > 0])) if (sv > 0).any() else 0, 4),
            })
            log(f"  ✓ {query[:50]:<50} top={top_features[0][0] if top_features else 'N/A'}", G)

        except Exception as e:
            log(f"  ✗ SHAP failed for: {query[:40]}... — {e}", R)
            shap_results.append({"query": query[:100], "error": str(e)})

    # Save SHAP summary
    with open(os.path.join(out_dir, "shap_summary.txt"), "w") as f:
        f.write(f"SHAP / XAI Evaluation Summary\n{'='*60}\n\n")
        f.write(f"Explainer: LinearExplainer (SHAP)\n")
        f.write(f"Background samples: {bg_data.shape[0] if 'bg_data' in dir() else 'fallback'}\n")
        f.write(f"Total features: {len(all_names)}\n\n")
        for r in shap_results:
            f.write(f"Query: {r['query']}\n")
            if "error" in r:
                f.write(f"  Error: {r['error']}\n\n")
            else:
                f.write(f"  Max SHAP: {r['max_shap']}  Mean positive SHAP: {r['mean_positive_shap']}\n")
                f.write(f"  Top features:\n")
                for feat, val in r.get("top_features", []):
                    f.write(f"    {feat:<30} {val:.4f}\n")
                f.write("\n")

    with open(os.path.join(out_dir, "shap_summary.json"), "w") as f:
        json.dump(shap_results, f, indent=2, default=str)

    # SHAP bar plot for structural features
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # Aggregate structural feature importance across samples
        struct_importance = {name: 0.0 for name in STRUCTURAL_FEATURE_NAMES}
        for r in shap_results:
            for feat, val in r.get("top_features", []):
                if feat in struct_importance:
                    struct_importance[feat] += val

        names = list(struct_importance.keys())
        vals = [struct_importance[n] for n in names]
        sorted_pairs = sorted(zip(names, vals), key=lambda x: x[1], reverse=True)
        names, vals = zip(*sorted_pairs) if sorted_pairs else ([], [])

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.barh(range(len(names)), vals, color="#2563eb")
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=9)
        ax.set_xlabel("Cumulative SHAP Value", fontsize=11)
        ax.set_title("Structural Feature Importance (SHAP)", fontsize=13)
        ax.invert_yaxis()
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, "shap_structural_features.png"), dpi=150)
        plt.close(fig)
        log("  ✓ SHAP structural feature plot saved", G)
    except Exception as e:
        log(f"  ⚠ SHAP plot failed: {e}", Y)

    log("  ✓ SHAP evaluation saved", G)


# ══════════════════════════════════════════════════════════════════
# Final Summary Report
# ══════════════════════════════════════════════════════════════════

def generate_summary_report(m1_metrics, m2_metrics, baseline_df, out_dir):
    """Generate a markdown summary report."""
    log("\n" + "═" * 60)
    log("  Generating Final Summary Report")
    log("═" * 60)

    with open(os.path.join(out_dir, "final_summary_report.md"), "w") as f:
        f.write("# FileSense — Model Evaluation Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Model 1
        f.write("## Model 1 — Binary SQLi Detection\n\n")
        f.write("| Metric | Value |\n|--------|-------|\n")
        for key in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]:
            f.write(f"| {key.replace('_', ' ').title()} | {m1_metrics.get(key, 'N/A')} |\n")
        cm = m1_metrics.get("confusion_matrix", {})
        f.write(f"\n**Confusion Matrix:** TN={cm.get('TN', '?')} FP={cm.get('FP', '?')} FN={cm.get('FN', '?')} TP={cm.get('TP', '?')}\n\n")
        f.write(f"**False Positive Rate:** {m1_metrics.get('false_positive_rate', 'N/A')}\n")
        f.write(f"**False Negative Rate:** {m1_metrics.get('false_negative_rate', 'N/A')}\n\n")

        # Model 2
        f.write("## Model 2 — SQLi Subtype Classification\n\n")
        if m2_metrics:
            f.write("| Metric | Value |\n|--------|-------|\n")
            for key in ["accuracy", "macro_precision", "macro_recall", "macro_f1", "weighted_f1"]:
                f.write(f"| {key.replace('_', ' ').title()} | {m2_metrics.get(key, 'N/A')} |\n")
            f.write(f"\n**Classes:** {', '.join(m2_metrics.get('classes', []))}\n\n")

        # Baseline comparison
        f.write("## Baseline Comparison (Model 1)\n\n")
        if baseline_df is not None and len(baseline_df) > 0:
            f.write("| Model | Accuracy | Precision | Recall | F1 | AUC | FN | Train Time |\n")
            f.write("|-------|----------|-----------|--------|----|-----|----|-----------|\n")
            for _, row in baseline_df.iterrows():
                f.write(f"| {row['model']} | {row['accuracy']:.4f} | {row['precision']:.4f} | "
                        f"{row['recall']:.4f} | {row['f1_score']:.4f} | {row['roc_auc']:.4f} | "
                        f"{row.get('FN', '?')} | {row.get('train_time_s', '?')}s |\n")

        # File manifest
        f.write("\n## Generated Files\n\n")
        for fname in sorted(os.listdir(out_dir)):
            fpath = os.path.join(out_dir, fname)
            size = os.path.getsize(fpath)
            f.write(f"- `{fname}` ({size:,} bytes)\n")

    log("  ✓ final_summary_report.md saved", G)


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="FileSense — Comprehensive Model Evaluation")
    parser.add_argument("--output-dir", default=os.path.join(DETECTION_DIR, "evaluation"),
                        help="Output directory for evaluation artifacts")
    args = parser.parse_args()

    out_dir = args.output_dir
    os.makedirs(out_dir, exist_ok=True)

    log("\n╔══════════════════════════════════════════════════════╗", C)
    log("║   FileSense — Comprehensive Model Evaluation        ║", C)
    log("╚══════════════════════════════════════════════════════╝", C)
    log(f"\n  Output: {out_dir}", C)

    # Load dataset
    if not os.path.exists(DATA_PATH):
        log(f"  ✗ Dataset not found: {DATA_PATH}", R)
        log("  Run prepare.py first.", R)
        sys.exit(1)

    df = pd.read_csv(DATA_PATH)
    log(f"  Dataset: {len(df)} rows ({Counter(df['label'].astype(int))[0]} normal, {Counter(df['label'].astype(int))[1]} SQLi)", G)

    # Verify models exist
    for fname in ["model1.joblib", "vectorizer1.joblib", "model2.joblib", "vectorizer2.joblib"]:
        if not os.path.exists(os.path.join(MODEL_DIR, fname)):
            log(f"  ✗ Missing: {fname}", R)
            log("  Run train_one.py first.", R)
            sys.exit(1)

    t_start = time.time()

    # 1. Model 1 evaluation
    m1_ctx = evaluate_model1(df, out_dir)

    # 2. Model 2 evaluation
    m2_metrics = evaluate_model2(df, out_dir)

    # 3. Baseline comparison
    baseline_df = None
    if m1_ctx:
        baseline_df = run_baseline_comparison(m1_ctx, out_dir)

    # 4. SHAP / XAI
    if m1_ctx:
        run_shap_evaluation(m1_ctx, out_dir)

    # 5. Summary report
    m1_metrics = m1_ctx["metrics"] if m1_ctx else {}
    generate_summary_report(m1_metrics, m2_metrics, baseline_df, out_dir)

    elapsed = time.time() - t_start
    log(f"\n{'═'*60}", G)
    log(f"  ✓ Evaluation complete in {elapsed:.1f}s", G)
    log(f"  ✓ All artifacts saved to: {out_dir}", G)
    log(f"{'═'*60}\n", G)

    # Print file manifest
    log("  Generated files:", C)
    for fname in sorted(os.listdir(out_dir)):
        fpath = os.path.join(out_dir, fname)
        size = os.path.getsize(fpath)
        log(f"    {fname:<45} {size:>8,} bytes", G)


if __name__ == "__main__":
    main()
