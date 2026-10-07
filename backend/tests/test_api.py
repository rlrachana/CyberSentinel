"""
CyberSentinel Backend - API Integration Tests
Tests /health, /api/analyze, validation, and error scenarios.
"""

import pytest
from starlette.testclient import TestClient
from backend.app import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "analyze_endpoint" in data


def test_analyze_legitimate_url():
    response = client.post(
        "/api/analyze",
        json={"url": "https://www.google.com"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://www.google.com"
    assert data["verdict"] == "Legitimate / Safe"
    assert data["risk_score"] < 35.0
    assert "red_flags" in data
    assert "green_flags" in data
    assert "feature_table" in data
    assert "phishing_probability" in data
    assert "heuristic_score" in data


def test_analyze_suspicious_url():
    response = client.post(
        "/api/analyze",
        json={"url": "http://192.168.1.1/login-account-update"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ["Suspicious", "Phishing"]
    assert data["risk_score"] >= 50.0
    assert len(data["red_flags"]) >= 1


def test_analyze_phishing_url():
    response = client.post(
        "/api/analyze",
        json={"url": "http://user:secret@evil-domain-phish.xyz//update-credentials-login"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "Phishing"
    assert data["risk_score"] >= 65.0
    assert len(data["red_flags"]) >= 2


def test_analyze_empty_url():
    response = client.post(
        "/api/analyze",
        json={"url": ""}
    )
    assert response.status_code in [400, 422]


def test_analyze_invalid_url_structure():
    response = client.post(
        "/api/analyze",
        json={"url": "a b"}
    )
    assert response.status_code in [400, 422]
