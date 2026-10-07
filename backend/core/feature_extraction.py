"""
CyberSentinel Backend - Feature Extraction Engine
Extracts 10 UCI-aligned numerical features directly from raw URL string
without network fetching or external lookups.
"""

import re
from typing import Dict, Any
from urllib.parse import urlparse
import pandas as pd

from backend.core.heuristics import (
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
    evaluate_heuristic_flags,
)

# The 10 UCI features directly extractable from raw URL string
UCI_URL_FEATURE_NAMES = [
    "having_ip_address",
    "url_length",
    "shortining_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "port",
    "https_token",
    "abnormal_url",
]


def clean_url(url: str) -> str:
    """Standardizes URL by trimming and adding default protocol if missing."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url
    return url


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Parses and extracts all URL-level features from a raw URL string.
    Strictly performs lexical analysis only (NO requests/crawling).
    """
    url = clean_url(raw_url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Extract 10 UCI-aligned features
    ip_val = check_ip_address(domain)
    len_val = check_url_length(url)
    short_val = check_shortening_service(domain)
    at_val = check_at_symbol(url)
    slash_val = check_double_slash(url)
    prefix_val = check_prefix_suffix(domain)
    subdom_val = check_sub_domains(domain)
    port_val = check_port(parsed)
    https_tok_val = check_https_token(domain)
    abnormal_val = check_abnormal_url(parsed, domain)

    uci_features = {
        "having_ip_address": ip_val,
        "url_length": len_val,
        "shortining_service": short_val,
        "having_at_symbol": at_val,
        "double_slash_redirecting": slash_val,
        "prefix_suffix": prefix_val,
        "having_sub_domain": subdom_val,
        "port": port_val,
        "https_token": https_tok_val,
        "abnormal_url": abnormal_val,
    }

    feature_df = pd.DataFrame([uci_features], columns=UCI_URL_FEATURE_NAMES)

    red_flags, green_flags, metadata = evaluate_heuristic_flags(
        url=url,
        parsed_url=parsed,
        domain=domain,
        uci_features=uci_features
    )

    return {
        "clean_url": url,
        "domain": domain,
        "scheme": parsed.scheme,
        "uci_features": uci_features,
        "feature_df": feature_df,
        "red_flags": red_flags,
        "green_flags": green_flags,
        "metadata": metadata
    }
