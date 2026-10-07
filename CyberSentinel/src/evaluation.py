"""
CyberSentinel - Model Evaluation Engine
Provides metrics computation, confusion matrix generation,
and feature importance extraction for Decision Tree and Random Forest classifiers.
"""

from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


def compute_metrics(y_true, y_pred, model_name: str = "Model") -> Dict[str, Any]:
    """
    Computes comprehensive classification metrics.

    Args:
        y_true: Ground truth labels (1 = Legitimate, -1 = Phishing)
        y_pred: Predicted labels
        model_name: Descriptive name of the model

    Returns:
        Dictionary containing accuracy, precision, recall, f1,
        confusion matrix, and detailed per-class metrics.
    """
    acc = float(accuracy_score(y_true, y_pred))
    prec_weighted = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
    rec_weighted = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    # Binary metrics considering -1 as Phishing (positive detection target)
    prec_phishing = float(precision_score(y_true, y_pred, pos_label=-1, zero_division=0))
    rec_phishing = float(recall_score(y_true, y_pred, pos_label=-1, zero_division=0))
    f1_phishing = float(f1_score(y_true, y_pred, pos_label=-1, zero_division=0))

    prec_legit = float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
    rec_legit = float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
    f1_legit = float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))

    # Confusion matrix: rows = true [-1, 1], cols = pred [-1, 1]
    # labels=[-1, 1] ensures index 0 is Phishing, index 1 is Legitimate
    cm = confusion_matrix(y_true, y_pred, labels=[-1, 1])

    # Extract TN, FP, FN, TP where Phishing (-1) is positive:
    # cm[0, 0]: True Phishing (TP)
    # cm[0, 1]: False Legitimate (FN)
    # cm[1, 0]: False Phishing (FP)
    # cm[1, 1]: True Legitimate (TN)
    tp_phish = int(cm[0, 0])
    fn_phish = int(cm[0, 1])
    fp_phish = int(cm[1, 0])
    tn_phish = int(cm[1, 1])

    return {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec_weighted, 4),
        "recall": round(rec_weighted, 4),
        "f1_score": round(f1_weighted, 4),
        "phishing_class": {
            "precision": round(prec_phishing, 4),
            "recall": round(rec_phishing, 4),
            "f1": round(f1_phishing, 4),
        },
        "legitimate_class": {
            "precision": round(prec_legit, 4),
            "recall": round(rec_legit, 4),
            "f1": round(f1_legit, 4),
        },
        "confusion_matrix": {
            "raw": cm.tolist(),
            "labels": ["Phishing (-1)", "Legitimate (+1)"],
            "true_phishing": tp_phish,
            "false_legitimate": fn_phish,
            "false_phishing": fp_phish,
            "true_legitimate": tn_phish,
        }
    }


def extract_feature_importance(model, feature_names: List[str]) -> List[Dict[str, Any]]:
    """
    Extracts and ranks feature importances from a tree-based scikit-learn model.

    Returns:
        List of dicts with 'feature' and 'importance', sorted in descending order.
    """
    if not hasattr(model, "feature_importances_"):
        return []

    importances = model.feature_importances_
    ranked = sorted(
        [{"feature": name, "importance": round(float(imp), 4)}
         for name, imp in zip(feature_names, importances)],
        key=lambda x: x["importance"],
        reverse=True
    )
    return ranked


if __name__ == "__main__":
    y_t = [1, -1, 1, 1, -1, -1]
    y_p = [1, -1, 1, -1, -1, 1]
    metrics = compute_metrics(y_t, y_p, "Test Model")
    print(metrics)
