"""
CyberSentinel - Real-Time URL Feature Extraction Engine
Extracts URL-level lexical and structural features without network overhead,
strictly maintaining compatibility with UCI Phishing Websites feature encodings.
"""

import math
import re
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse
import pandas as pd

# Known URL shorteners
SHORTENING_SERVICES = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bitly.com", "cur.lv", "tiny.cc", "ow.ly",
    "ity.im", "q.gs", "is.gd", "po.st", "bc.vc", "twitthis.com",
    "u.to", "j.mp", "buzurl.com", "cutt.ly", "v.gd", "tr.im",
    "link.zip", "rebrand.ly", "s.id", "shorturl.at"
}

# Suspicious keywords commonly seen in credential harvesting URLs
SUSPICIOUS_KEYWORDS = sorted(list({
    "login", "verify", "verification", "update", "banking", "secure",
    "account", "signin", "wallet", "confirm", "password", "authenticate",
    "service", "admin", "billing", "recover", "security", "ebayisapi",
    "webscr", "free", "gift", "prize", "support", "security-alert", "validate"
}))

# High-risk top-level domains frequently abused in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "buzz", "club", "loan", "fit", "click",
    "country", "stream", "gq", "ml", "cf", "ga", "tk", "rest", "surf"
}

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
        # Default to http:// for parsing if scheme omitted
        url = "http://" + url
    return url


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string (higher = more randomized)."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def check_ip_address(domain: str) -> int:
    """
    UCI Feature: having_ip_address
    -1 if domain is an IP address (IPv4 or IPv6 or hexadecimal/octal),
     1 if domain is a hostname.
    """
    # Standard IPv4 pattern
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    # IPv6 pattern
    ipv6_pattern = r"^(\[)?[0-9a-fA-F:]+(\])?$"
    # Hexadecimal IP pattern (e.g., 0x7f.0x00.0x00.0x01)
    hex_pattern = r"^0x[0-9a-fA-F]+(\.0x[0-9a-fA-F]+){3}$"

    # Strip port if present
    host = domain.split(":")[0]

    if re.match(ipv4_pattern, host) or re.match(hex_pattern, host):
        return -1
    if ":" in host and re.match(ipv6_pattern, host):
        return -1
    return 1


def check_url_length(url: str) -> int:
    """
    UCI Feature: url_length
     1: Length < 54 characters (Legitimate)
     0: 54 <= Length <= 75 characters (Suspicious)
    -1: Length > 75 characters (Phishing)
    """
    length = len(url)
    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    else:
        return -1


def check_shortening_service(domain: str) -> int:
    """
    UCI Feature: shortining_service
    -1 if domain is a known URL shortening service, 1 otherwise.
    """
    host = domain.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    if host in SHORTENING_SERVICES:
        return -1
    for shortener in SHORTENING_SERVICES:
        if host.endswith("." + shortener):
            return -1
    return 1


def check_at_symbol(url: str) -> int:
    """
    UCI Feature: having_at_symbol
    -1 if '@' is present in URL, 1 otherwise.
    """
    return -1 if "@" in url else 1


def check_double_slash(url: str) -> int:
    """
    UCI Feature: double_slash_redirecting
    -1 if '//' appears after the protocol prefix (e.g., position > 7), 1 otherwise.
    """
    # Find last occurrence of '//'
    last_double_slash = url.rfind("//")
    # If '//' appears beyond position 7 (e.g. beyond http:// or https://)
    if last_double_slash > 7:
        return -1
    return 1


def check_prefix_suffix(domain: str) -> int:
    """
    UCI Feature: prefix_suffix
    -1 if domain name contains a hyphen '-', 1 otherwise.
    """
    host = domain.split(":")[0]
    return -1 if "-" in host else 1


def check_sub_domains(domain: str) -> int:
    """
    UCI Feature: having_sub_domain
     1: 1 dot in domain (excluding www and country-code TLDs) (Legitimate)
     0: 2 dots in domain (Suspicious)
    -1: > 2 dots in domain (Phishing)
    """
    host = domain.lower().split(":")[0]
    if host.startswith("www."):
        host = host[4:]

    # Remove well-known second-level domains like .co.uk, .com.au, .ac.in
    compound_tlds = [
        ".co.uk", ".com.au", ".org.uk", ".gov.uk", ".ac.in", ".co.in",
        ".com.br", ".edu.au", ".co.jp", ".co.nz", ".com.sg"
    ]
    for ctld in compound_tlds:
        if host.endswith(ctld):
            host = host[:-len(ctld)]
            break

    dots = host.count(".")
    if dots <= 1:
        return 1
    elif dots == 2:
        return 0
    else:
        return -1


def check_port(parsed_url) -> int:
    """
    UCI Feature: port
    -1 if an abnormal/non-standard port is explicitly specified, 1 otherwise.
    """
    if parsed_url.port is not None:
        standard_ports = {80, 443, 8080}
        if parsed_url.port not in standard_ports:
            return -1
    return 1


def check_https_token(domain: str) -> int:
    """
    UCI Feature: https_token
    -1 if 'https' appears as part of the domain name (e.g. http://https-paypal.com), 1 otherwise.
    """
    host = domain.lower().split(":")[0]
    if "https" in host or "http" in host.replace("http://", ""):
        # Check if "https" or "http" appears in subdomain or domain label
        labels = host.split(".")
        for label in labels:
            if "https" in label or "http" in label:
                return -1
    return 1


def check_abnormal_url(parsed_url, domain: str) -> int:
    """
    UCI Feature: abnormal_url
    -1 if host is missing, invalid, or malformed, 1 otherwise.
    """
    if not domain or not parsed_url.netloc:
        return -1
    # Check for valid domain structure (at least host and TLD)
    host = domain.split(":")[0]
    if "." not in host and not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", host):
        return -1
    return 1


def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Parses and extracts all URL-level features from a raw URL.

    Returns a comprehensive dict containing:
    - 'uci_features': dict of 10 UCI-aligned numerical features (-1, 0, 1)
    - 'feature_df': single-row pandas DataFrame matching exact model columns
    - 'red_flags': list of detected threat indicators with severity and explanation
    - 'green_flags': list of positive safety indicators
    - 'metadata': lexical statistics (length, entropy, keywords, etc.)
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

    # Secondary lexical & contextual analysis
    url_lower = url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    entropy = calculate_entropy(url)
    tld = domain.split(".")[-1].split(":")[0] if "." in domain else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    is_https = parsed.scheme.lower() == "https"
    has_punycode = "xn--" in domain
    digit_count = sum(c.isdigit() for c in url)
    special_char_count = sum(not c.isalnum() for c in url)

    # Build explainable Red Flags
    red_flags: List[Dict[str, str]] = []
    green_flags: List[str] = []

    if ip_val == -1:
        red_flags.append({
            "indicator": "Raw IP Address Host",
            "severity": "CRITICAL",
            "description": f"The URL uses a raw IP address ({domain}) instead of a trusted domain name to bypass domain reputation checks."
        })
    else:
        green_flags.append("Domain uses a registered hostname instead of an IP address.")

    if len_val == -1:
        red_flags.append({
            "indicator": "Excessive URL Length",
            "severity": "HIGH",
            "description": f"URL length ({len(url)} chars) exceeds 75 characters, often used to hide payload strings or confuse users."
        })
    elif len_val == 0:
        red_flags.append({
            "indicator": "Moderate URL Length",
            "severity": "MEDIUM",
            "description": f"URL length ({len(url)} chars) is between 54 and 75 characters."
        })
    else:
        green_flags.append(f"Compact URL length ({len(url)} characters).")

    if short_val == -1:
        red_flags.append({
            "indicator": "URL Shortening Service",
            "severity": "HIGH",
            "description": f"The domain '{domain}' is a URL shortener, obscuring the true destination page."
        })
    else:
        green_flags.append("Direct destination URL (not using a known shortener).")

    if at_val == -1:
        red_flags.append({
            "indicator": "@ Symbol in URL",
            "severity": "CRITICAL",
            "description": "The URL contains an '@' symbol. Browsers interpret text before '@' as user authentication, leading the user to the destination after '@'."
        })
    else:
        green_flags.append("No '@' credential masking found.")

    if slash_val == -1:
        red_flags.append({
            "indicator": "Double Slash (//) Redirect",
            "severity": "HIGH",
            "description": "Double slash '//' occurs inside the URL path, commonly used in open-redirect attacks."
        })

    if prefix_val == -1:
        red_flags.append({
            "indicator": "Hyphen in Domain Name",
            "severity": "MEDIUM",
            "description": f"Domain '{domain}' contains hyphens, a frequent technique to spoof brand names (e.g., 'paypal-verification')."
        })
    else:
        green_flags.append("No deceptive hyphens in the domain name.")

    if ip_val != -1:
        if subdom_val == -1:
            red_flags.append({
                "indicator": "Multiple Subdomains",
                "severity": "HIGH",
                "description": f"Domain contains >2 subdomains, a technique to simulate legitimate corporate domain structures."
            })
        elif subdom_val == 0:
            red_flags.append({
                "indicator": "Two Subdomains Detected",
                "severity": "LOW",
                "description": "Domain contains 2 subdomains."
            })
        else:
            green_flags.append("Clean, standard subdomain structure.")

    if port_val == -1:
        red_flags.append({
            "indicator": "Non-Standard Port",
            "severity": "HIGH",
            "description": f"URL connects via unusual port '{parsed.port}', bypassing standard web security proxies."
        })

    if https_tok_val == -1:
        red_flags.append({
            "indicator": "Fake 'https' Token in Domain",
            "severity": "HIGH",
            "description": "The token 'https' is embedded within the domain label to fool users into assuming the site is secure."
        })

    if abnormal_val == -1:
        red_flags.append({
            "indicator": "Malformed/Abnormal Host",
            "severity": "HIGH",
            "description": "URL lacks a standard hostname or has abnormal structure."
        })

    if not is_https:
        red_flags.append({
            "indicator": "Insecure HTTP Protocol",
            "severity": "MEDIUM",
            "description": "URL uses unencrypted HTTP. Data sent across this connection is susceptible to interception."
        })
    else:
        green_flags.append("HTTPS protocol present.")

    if matched_keywords:
        red_flags.append({
            "indicator": f"Suspicious Keyword{'s' if len(matched_keywords)>1 else ''} Detected",
            "severity": "HIGH" if len(matched_keywords) >= 2 else "MEDIUM",
            "description": f"URL contains sensitive target keywords: {', '.join(matched_keywords[:4])}."
        })

    if is_suspicious_tld:
        red_flags.append({
            "indicator": f"Suspicious TLD (.{tld})",
            "severity": "MEDIUM",
            "description": f"The top-level domain '.{tld}' is statistically associated with high rates of malicious registrations."
        })

    if has_punycode:
        red_flags.append({
            "indicator": "Punycode / Homograph Threat",
            "severity": "CRITICAL",
            "description": "URL contains 'xn--', which may indicate an IDN Homograph attack mimicking a legitimate domain with Cyrillic/Greek characters."
        })

    if entropy > 4.6:
        red_flags.append({
            "indicator": f"High Information Entropy ({entropy})",
            "severity": "MEDIUM",
            "description": "The URL has unusually high character entropy, suggesting randomly generated or obfuscated tokens."
        })

    return {
        "clean_url": url,
        "domain": domain,
        "scheme": parsed.scheme,
        "uci_features": uci_features,
        "feature_df": feature_df,
        "red_flags": red_flags,
        "green_flags": green_flags,
        "metadata": {
            "url_length": len(url),
            "entropy": entropy,
            "digit_count": digit_count,
            "special_char_count": special_char_count,
            "matched_keywords": matched_keywords,
            "is_https": is_https,
            "tld": tld,
        }
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login-verify-account",
        "http://paypal-security-update.com/signin?user=test",
        "https://bit.ly/3xYzA9",
        "http://secure.account.verification.bank.evil-site.com//auth"
    ]
    for u in test_urls:
        res = extract_features(u)
        print("=" * 60)
        print(f"URL: {u}")
        print(f"UCI Vector: {res['uci_features']}")
        print(f"Red Flags: {len(res['red_flags'])} | Green Flags: {len(res['green_flags'])}")
        for rf in res["red_flags"]:
            print(f"  - [{rf['severity']}] {rf['indicator']}: {rf['description']}")
