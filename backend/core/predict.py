"""
CyberSentinel Backend - ML Inference Pipeline
Loads trained Random Forest models and executes inference,
combining ML prediction probabilities with heuristic risk factors.
"""

import os
import json
import joblib
from typing import Dict, Any, Optional
import pandas as pd
import numpy as np

from backend.core.feature_extraction import extract_features, UCI_URL_FEATURE_NAMES
from backend.core.risk_scoring import calculate_composite_risk, determine_verdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
URL_MODEL_PATH = os.path.join(MODELS_DIR, "url_phishing_model.pkl")
BENCHMARK_MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model.pkl")
METADATA_PATH = os.path.join(MODELS_DIR, "metadata.json")

# In-memory model cache
_cached_url_model = None
_cached_benchmark_model = None
_cached_metadata = None


def get_metadata() -> Dict[str, Any]:
    """Loads and caches training metadata."""
    global _cached_metadata
    if _cached_metadata is None:
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                _cached_metadata = json.load(f)
        else:
            _cached_metadata = {}
    return _cached_metadata


def get_url_model():
    """Loads and caches the real-time URL Random Forest model."""
    global _cached_url_model
    if _cached_url_model is None:
        if not os.path.exists(URL_MODEL_PATH):
            raise FileNotFoundError(
                f"Model file not found at {URL_MODEL_PATH}."
            )
        _cached_url_model = joblib.load(URL_MODEL_PATH)
    return _cached_url_model


def get_benchmark_model():
    """Loads and caches the 30-feature benchmark Random Forest model."""
    global _cached_benchmark_model
    if _cached_benchmark_model is None:
        if not os.path.exists(BENCHMARK_MODEL_PATH):
            raise FileNotFoundError(
                f"Benchmark model not found at {BENCHMARK_MODEL_PATH}."
            )
        _cached_benchmark_model = joblib.load(BENCHMARK_MODEL_PATH)
    return _cached_benchmark_model


def preload_models():
    """Preloads all models and metadata into memory during application startup."""
    get_metadata()
    get_url_model()
    get_benchmark_model()


def predict_url(raw_url: str) -> Dict[str, Any]:
    """
    Analyzes a user-provided raw URL strictly via lexical parsing:
    1. Extracts URL features without network requests.
    2. Runs inference via cached URL Random Forest classifier.
    3. Calculates composite Risk Score and explainable flags.
    4. Formats comprehensive detection report.
    """
    if not raw_url or not raw_url.strip():
        raise ValueError("URL cannot be empty.")

    extraction = extract_features(raw_url)
    model = get_url_model()

    # Model inference
    feature_df = extraction["feature_df"]
    raw_pred = model.predict(feature_df)[0]  # -1 (Phishing) or 1 (Legitimate)

    # Class probabilities
    classes = list(model.classes_)
    phish_idx = classes.index(-1) if -1 in classes else 0
    legit_idx = classes.index(1) if 1 in classes else 1

    probabilities = model.predict_proba(feature_df)[0]
    prob_phishing = float(probabilities[phish_idx])
    prob_legitimate = float(probabilities[legit_idx])

    # Composite risk score and verdict
    risk_score = calculate_composite_risk(
        prob_phishing,
        extraction["red_flags"],
        extraction["green_flags"]
    )
    verdict_info = determine_verdict(risk_score)

    severity_weights = {
        "CRITICAL": 30.0,
        "HIGH": 18.0,
        "MEDIUM": 8.0,
        "LOW": 4.0
    }
    additive_risk = sum(
        severity_weights.get(f.get("severity", "MEDIUM"), 8.0)
        for f in extraction["red_flags"]
    )
    heuristic_score = round(float(min(additive_risk, 100.0)), 1)

    uci_feature_labels = {
        "having_ip_address": ("IP Address Host", "Bypasses DNS resolution using numeric IP"),
        "url_length": ("URL Length", "<54 Safe, 54-75 Suspicious, >75 Phishing"),
        "shortining_service": ("URL Shortener", "Obscures actual destination domain"),
        "having_at_symbol": ("@ Symbol", "Credential masking in URL authority"),
        "double_slash_redirecting": ("Double Slash //", "Redirection beyond protocol prefix"),
        "prefix_suffix": ("Prefix/Suffix Hyphen", "Deceptive hyphen in domain label"),
        "having_sub_domain": ("Subdomain Depth", "Excessive subdomains masking root domain"),
        "port": ("Port Specification", "Abnormal service port specified"),
        "https_token": ("HTTPS Token in Domain", "Deceptive 'https' word in domain"),
        "abnormal_url": ("Host Structure", "Abnormal hostname syntax or missing TLD"),
    }

    feature_table = []
    for feat_name, feat_val in extraction["uci_features"].items():
        name_desc = uci_feature_labels.get(feat_name, (feat_name, ""))
        status = "Safe" if feat_val == 1 else ("Suspicious" if feat_val == 0 else "Phishing Indicator")
        status_color = "green" if feat_val == 1 else ("orange" if feat_val == 0 else "red")
        feature_table.append({
            "Feature": name_desc[0],
            "Raw Value": feat_val,
            "Status": status,
            "Description": name_desc[1],
            "StatusColor": status_color
        })

    return {
        "url": raw_url,
        "clean_url": extraction["clean_url"],
        "domain": extraction["domain"],
        "verdict": verdict_info["verdict"],
        "badge_color": verdict_info["badge_color"],
        "risk_level": verdict_info["level"],
        "summary": verdict_info["summary"],
        "recommendation": verdict_info["recommendation"],
        "risk_score": risk_score,
        "phishing_probability": round(prob_phishing, 4),
        "heuristic_score": heuristic_score,
        "confidence": round(max(prob_phishing, prob_legitimate) * 100, 1),
        "ml_probabilities": {
            "phishing": round(prob_phishing * 100, 1),
            "legitimate": round(prob_legitimate * 100, 1)
        },
        "ml_raw_class": int(raw_pred),
        "red_flags": extraction["red_flags"],
        "green_flags": extraction["green_flags"],
        "feature_table": feature_table,
        "metadata": extraction["metadata"],
        "uci_features": extraction["uci_features"]
    }


def predict_benchmark_sample(features_dict: Dict[str, int]) -> Dict[str, Any]:
    """
    Evaluates a complete 30-feature sample using the 30-feature Benchmark model.
    """
    metadata = get_metadata()
    all_features = metadata.get("dataset", {}).get("all_features", [])
    model = get_benchmark_model()

    row = {col: features_dict.get(col, 1) for col in all_features}
    df = pd.DataFrame([row], columns=all_features)

    pred = model.predict(df)[0]
    classes = list(model.classes_)
    phish_idx = classes.index(-1) if -1 in classes else 0
    legit_idx = classes.index(1) if 1 in classes else 1
    probabilities = model.predict_proba(df)[0]

    return {
        "prediction": "Phishing" if pred == -1 else "Legitimate",
        "raw_prediction": int(pred),
        "phishing_prob": round(float(probabilities[phish_idx]) * 100, 2),
        "legitimate_prob": round(float(probabilities[legit_idx]) * 100, 2)
    }
