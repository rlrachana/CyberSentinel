"""
CyberSentinel Backend - Risk Scoring & Verdict Engine
Preserves exact composite risk formula, threat floors, dampening,
and verdict thresholds.
"""

from typing import Dict, List, Any
import numpy as np


def calculate_composite_risk(
    ml_phishing_prob: float,
    red_flags: List[Dict[str, Any]],
    green_flags: List[str]
) -> float:
    """
    Computes a calibrated 0-100 risk score combining ML prediction
    probability with detected rule-based threat vectors.
    """
    ml_score = ml_phishing_prob * 100.0

    severity_weights = {
        "CRITICAL": 30.0,
        "HIGH": 18.0,
        "MEDIUM": 8.0,
        "LOW": 4.0
    }

    additive_risk = sum(severity_weights.get(f.get("severity", "MEDIUM"), 8.0) for f in red_flags)

    has_critical = any(f.get("severity") == "CRITICAL" for f in red_flags)
    has_high_count = sum(1 for f in red_flags if f.get("severity") == "HIGH")

    # Weighted blend: 50% ML model probability, 50% rule threat score
    composite = (ml_score * 0.50) + (min(additive_risk, 100.0) * 0.50)

    # Threat floor guarantees
    if has_critical:
        composite = max(composite, 72.0)
    elif has_high_count >= 2:
        composite = max(composite, 58.0)
    elif has_high_count == 1 and len(red_flags) >= 2:
        composite = max(composite, 45.0)

    # Safe dampening for clean URLs
    if len(red_flags) == 0:
        composite = min(composite, 5.0)
    elif not has_critical and has_high_count == 0 and len(red_flags) <= 1 and len(green_flags) >= 5:
        composite = min(composite, 25.0)

    return round(float(np.clip(composite, 0.0, 100.0)), 1)


def determine_verdict(risk_score: float) -> Dict[str, str]:
    """Classifies risk score into Safe, Suspicious, or Phishing."""
    if risk_score < 35.0:
        return {
            "verdict": "Legitimate / Safe",
            "badge_color": "#10b981",  # Emerald Green
            "level": "Low Risk",
            "summary": "This URL exhibits characteristics consistent with legitimate, reputable web domains.",
            "recommendation": "This link appears standard and safe to open under normal circumstances."
        }
    elif risk_score < 65.0:
        return {
            "verdict": "Suspicious",
            "badge_color": "#f59e0b",  # Amber
            "level": "Moderate Risk",
            "summary": "This URL exhibits unusual structural patterns or potential evasion techniques. Exercise caution.",
            "recommendation": "Don't enter passwords, payment details, or personal information unless you are certain the website is genuine."
        }
    else:
        return {
            "verdict": "Phishing",
            "badge_color": "#ef4444",  # Crimson Red
            "level": "High Risk",
            "summary": "This URL matches known phishing heuristics and malicious structural profiles. Do NOT enter credentials or download files.",
            "recommendation": "Don't open this link or enter any personal information."
        }
