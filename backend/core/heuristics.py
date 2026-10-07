"""
CyberSentinel Backend - Heuristics Engine
Defines security indicators, lexical patterns, and heuristic checks
without making any network requests to the target URL.
"""

import math
import re
from typing import Dict, List, Any, Tuple
from urllib.parse import urlparse

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
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ipv6_pattern = r"^(\[)?[0-9a-fA-F:]+(\])?$"
    hex_pattern = r"^0x[0-9a-fA-F]+(\.0x[0-9a-fA-F]+){3}$"

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
    -1 if '//' appears after the protocol prefix (position > 7), 1 otherwise.
    """
    last_double_slash = url.rfind("//")
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
    -1 if 'https' appears as part of the domain name, 1 otherwise.
    """
    host = domain.lower().split(":")[0]
    if "https" in host or "http" in host.replace("http://", ""):
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
    host = domain.split(":")[0]
    if "." not in host and not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", host):
        return -1
    return 1


def evaluate_heuristic_flags(
    url: str,
    parsed_url,
    domain: str,
    uci_features: Dict[str, int]
) -> Tuple[List[Dict[str, str]], List[str], Dict[str, Any]]:
    """
    Evaluates 15+ heuristic security indicators producing explainable
    red flags and green flags without network requests.
    """
    ip_val = uci_features["having_ip_address"]
    len_val = uci_features["url_length"]
    short_val = uci_features["shortining_service"]
    at_val = uci_features["having_at_symbol"]
    slash_val = uci_features["double_slash_redirecting"]
    prefix_val = uci_features["prefix_suffix"]
    subdom_val = uci_features["having_sub_domain"]
    port_val = uci_features["port"]
    https_tok_val = uci_features["https_token"]
    abnormal_val = uci_features["abnormal_url"]

    url_lower = url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    entropy = calculate_entropy(url)
    tld = domain.split(".")[-1].split(":")[0] if "." in domain else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    is_https = parsed_url.scheme.lower() == "https"
    has_punycode = "xn--" in domain
    digit_count = sum(c.isdigit() for c in url)
    special_char_count = sum(not c.isalnum() for c in url)

    red_flags: List[Dict[str, str]] = []
    green_flags: List[str] = []

    # 1. IP Address
    if ip_val == -1:
        red_flags.append({
            "indicator": "Raw IP Address Host",
            "severity": "CRITICAL",
            "description": f"The URL uses a raw IP address ({domain}) instead of a trusted domain name to bypass domain reputation checks."
        })
    else:
        green_flags.append("Domain uses a registered hostname instead of an IP address.")

    # 2. Length
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

    # 3. Shortener
    if short_val == -1:
        red_flags.append({
            "indicator": "URL Shortening Service",
            "severity": "HIGH",
            "description": f"The domain '{domain}' is a URL shortener, obscuring the true destination page."
        })
    else:
        green_flags.append("Direct destination URL (not using a known shortener).")

    # 4. @ Symbol
    if at_val == -1:
        red_flags.append({
            "indicator": "@ Symbol in URL",
            "severity": "CRITICAL",
            "description": "The URL contains an '@' symbol. Browsers interpret text before '@' as user authentication, leading the user to the destination after '@'."
        })
    else:
        green_flags.append("No '@' credential masking found.")

    # 5. Double Slash Redirect
    if slash_val == -1:
        red_flags.append({
            "indicator": "Double Slash (//) Redirect",
            "severity": "HIGH",
            "description": "Double slash '//' occurs inside the URL path, commonly used in open-redirect attacks."
        })

    # 6. Prefix / Suffix Hyphen
    if prefix_val == -1:
        red_flags.append({
            "indicator": "Hyphen in Domain Name",
            "severity": "MEDIUM",
            "description": f"Domain '{domain}' contains hyphens, a frequent technique to spoof brand names (e.g., 'paypal-verification')."
        })
    else:
        green_flags.append("No deceptive hyphens in the domain name.")

    # 7. Subdomains
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

    # 8. Non-Standard Port
    if port_val == -1:
        red_flags.append({
            "indicator": "Non-Standard Port",
            "severity": "HIGH",
            "description": f"URL connects via unusual port '{parsed_url.port}', bypassing standard web security proxies."
        })

    # 9. Fake HTTPS Token in Domain
    if https_tok_val == -1:
        red_flags.append({
            "indicator": "Fake 'https' Token in Domain",
            "severity": "HIGH",
            "description": "The token 'https' is embedded within the domain label to fool users into assuming the site is secure."
        })

    # 10. Abnormal Host
    if abnormal_val == -1:
        red_flags.append({
            "indicator": "Malformed/Abnormal Host",
            "severity": "HIGH",
            "description": "URL lacks a standard hostname or has abnormal structure."
        })

    # 11. Insecure HTTP
    if not is_https:
        red_flags.append({
            "indicator": "Insecure HTTP Protocol",
            "severity": "MEDIUM",
            "description": "URL uses unencrypted HTTP. Data sent across this connection is susceptible to interception."
        })
    else:
        green_flags.append("HTTPS protocol present.")

    # 12. Keywords
    if matched_keywords:
        red_flags.append({
            "indicator": f"Suspicious Keyword{'s' if len(matched_keywords)>1 else ''} Detected",
            "severity": "HIGH" if len(matched_keywords) >= 2 else "MEDIUM",
            "description": f"URL contains sensitive target keywords: {', '.join(matched_keywords[:4])}."
        })

    # 13. Suspicious TLD
    if is_suspicious_tld:
        red_flags.append({
            "indicator": f"Suspicious TLD (.{tld})",
            "severity": "MEDIUM",
            "description": f"The top-level domain '.{tld}' is statistically associated with high rates of malicious registrations."
        })

    # 14. Punycode / Homograph
    if has_punycode:
        red_flags.append({
            "indicator": "Punycode / Homograph Threat",
            "severity": "CRITICAL",
            "description": "URL contains 'xn--', which may indicate an IDN Homograph attack mimicking a legitimate domain with Cyrillic/Greek characters."
        })

    # 15. High Shannon Entropy
    if entropy > 4.6:
        red_flags.append({
            "indicator": f"High Information Entropy ({entropy})",
            "severity": "MEDIUM",
            "description": "The URL has unusually high character entropy, suggesting randomly generated or obfuscated tokens."
        })

    metadata = {
        "url_length": len(url),
        "entropy": entropy,
        "digit_count": digit_count,
        "special_char_count": special_char_count,
        "matched_keywords": matched_keywords,
        "is_https": is_https,
        "tld": tld,
    }

    return red_flags, green_flags, metadata
