"""
CyberSentinel Backend - Unit & Integration Test Suite
Validates URL parsing, feature extraction encodings against UCI standards,
model loading, and end-to-end classification pipeline.
"""

import os
import sys
import pytest
import pandas as pd

from backend.core.heuristics import (
    calculate_entropy,
    check_ip_address,
    check_url_length,
    check_shortening_service,
    check_at_symbol,
    check_double_slash,
    check_prefix_suffix,
    check_sub_domains,
    check_port,
    check_https_token,
    check_abnormal_url,
)
from backend.core.feature_extraction import (
    extract_features,
    clean_url,
    UCI_URL_FEATURE_NAMES,
)
from backend.core.predict import (
    predict_url,
    predict_benchmark_sample,
    get_url_model,
    get_benchmark_model,
    get_metadata,
)


class TestFeatureExtraction:
    """Tests for individual URL feature extraction functions matching UCI specifications."""

    def test_clean_url_protocol(self):
        assert clean_url("google.com").startswith("http://")
        assert clean_url("https://example.org").startswith("https://")

    def test_entropy_calculation(self):
        low_ent = calculate_entropy("aaaaaaa")
        high_ent = calculate_entropy("q7z9!x#4LmK92")
        assert low_ent == 0.0
        assert high_ent > 3.0

    def test_ip_address_detection(self):
        # IPv4
        assert check_ip_address("192.168.1.1") == -1
        assert check_ip_address("10.0.0.1:8080") == -1
        # Legitimate hostname
        assert check_ip_address("google.com") == 1
        assert check_ip_address("portal.university.edu") == 1

    def test_url_length_encoding(self):
        # < 54 characters -> 1 (Legitimate)
        short_url = "https://example.com/home"
        assert len(short_url) < 54
        assert check_url_length(short_url) == 1

        # 54 - 75 characters -> 0 (Suspicious)
        medium_url = "https://example.com/section/category/article-about-security-today"
        assert 54 <= len(medium_url) <= 75
        assert check_url_length(medium_url) == 0

        # > 75 characters -> -1 (Phishing)
        long_url = "https://example.com/very/long/path/with/lots/of/parameters/and/tokens/that/exceeds/seventy/five/characters/total"
        assert len(long_url) > 75
        assert check_url_length(long_url) == -1

    def test_shortening_service_detection(self):
        assert check_shortening_service("bit.ly") == -1
        assert check_shortening_service("tinyurl.com") == -1
        assert check_shortening_service("t.co") == -1
        assert check_shortening_service("github.com") == 1
        assert check_shortening_service("google.com") == 1

    def test_at_symbol_detection(self):
        assert check_at_symbol("http://user:pass@evil.com/login") == -1
        assert check_at_symbol("https://legit.com/index.html") == 1

    def test_double_slash_redirect(self):
        assert check_double_slash("http://trusted.com//evil.com") == -1
        assert check_double_slash("https://example.com/path/to/page") == 1

    def test_prefix_suffix_hyphen(self):
        assert check_prefix_suffix("paypal-secure-update.com") == -1
        assert check_prefix_suffix("paypal.com") == 1

    def test_subdomain_depth(self):
        # 1 dot (root domain + tld) -> 1
        assert check_sub_domains("google.com") == 1
        assert check_sub_domains("www.google.com") == 1
        # 2 dots -> 0
        assert check_sub_domains("portal.university.edu") == 0
        # > 2 dots -> -1
        assert check_sub_domains("a.b.c.target.com") == -1

    def test_https_token_in_domain(self):
        assert check_https_token("https-account-verification.com") == -1
        assert check_https_token("paypal.com") == 1


class TestFullExtractionVector:
    """Tests complete feature vector output structure and types."""

    def test_vector_shape_and_keys(self):
        res = extract_features("https://www.google.com")
        assert "uci_features" in res
        assert "feature_df" in res
        assert "red_flags" in res
        assert "green_flags" in res

        assert len(res["uci_features"]) == len(UCI_URL_FEATURE_NAMES)
        for col in UCI_URL_FEATURE_NAMES:
            assert col in res["uci_features"]
            assert res["uci_features"][col] in [-1, 0, 1]

        assert res["feature_df"].shape == (1, 10)
        assert list(res["feature_df"].columns) == UCI_URL_FEATURE_NAMES


class TestInferencePipeline:
    """Tests end-to-end prediction engine and model loading."""

    def test_models_exist(self):
        model_url = get_url_model()
        model_bench = get_benchmark_model()
        metadata = get_metadata()

        assert model_url is not None
        assert model_bench is not None
        assert "benchmark_30_features" in metadata
        assert metadata["benchmark_30_features"]["random_forest"]["accuracy"] >= 0.97

    def test_predict_legitimate_url(self):
        result = predict_url("https://www.google.com")
        assert result["verdict"] == "Legitimate / Safe"
        assert result["risk_score"] < 35.0
        assert "confidence" in result
        assert "feature_table" in result
        assert len(result["feature_table"]) == 10

    def test_predict_suspicious_or_phishing_url(self):
        result = predict_url("http://192.168.1.1/login-account-update")
        assert result["verdict"] in ["Suspicious", "Phishing"]
        assert result["risk_score"] >= 50.0
        assert len(result["red_flags"]) >= 2

    def test_predict_30_feature_sample(self):
        sample = {f: 1 for f in UCI_URL_FEATURE_NAMES}
        pred = predict_benchmark_sample(sample)
        assert "prediction" in pred
        assert "phishing_prob" in pred
