"""
CyberSentinel - Consumer Link Safety Checker
Simple, fast, and transparent link safety inspection.
"""

import os
import sys
import re
from urllib.parse import urlparse
import streamlit as st
import streamlit.components.v1 as components

import requests
from dotenv import load_dotenv

# Load frontend environment variables
load_dotenv()
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")

# ==============================================================================
# STREAMLIT PAGE CONFIGURATION
# ==============================================================================
st.set_page_config(
    page_title="CyberSentinel — Don't click. Check first.",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Initialize session state early so container layout can respond dynamically
if "active_page" not in st.session_state:
    st.session_state.active_page = "home"

def render_html(content: str):
    """
    Renders HTML cleanly in Streamlit without CommonMark code-block indentation bugs.
    Strips leading whitespace from every line so CommonMark never triggers pre/code blocks.
    """
    cleaned = "\n".join(line.strip() for line in content.splitlines() if line.strip())
    st.markdown(cleaned, unsafe_allow_html=True)

# Determine container width based on active page
_is_wide = st.session_state.get("active_page") == "safety_tips"
_max_width = "1200px" if _is_wide else "860px"

st.markdown(f"""
<style>
    /* Force Streamlit to center the block container at all viewport sizes */
    section[data-testid="stMain"] > div.main > div.block-container,
    .main > div.block-container,
    .main .block-container {{
        max-width: {_max_width} !important;
        width: 100% !important;
        padding-top: 2rem !important;
        padding-bottom: 4rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        margin-left: auto !important;
        margin-right: auto !important;
    }}
    /* Streamlit wraps content in stMainBlockContainer in newer versions */
    [data-testid="stMainBlockContainer"] {{
        max-width: {_max_width} !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        margin-left: auto !important;
        margin-right: auto !important;
    }}
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# CONSUMER DESIGN SYSTEM (Black + Yellow CyberSentinel Identity)
# ==============================================================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

    /* Hide Streamlit default chrome */
    #MainMenu, footer, header {
        visibility: hidden;
        height: 0;
    }
    .stDeployButton {
        display: none;
    }

    /* Global reset & typography */
    html, body, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background-color: #0A0A0A !important;
        color: #F5F5F5 !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    [data-testid="stVerticalBlock"] {
        gap: 1rem;
    }

    /* CyberSentinel Header / Brand */
    .brand-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem 0 2rem 0;
        border-bottom: 1px solid #1E1E1E;
        margin-bottom: 2.25rem;
    }

    .brand-logo {
        font-size: 1.35rem;
        font-weight: 900;
        letter-spacing: 0.08em;
        color: #F5F5F5;
        text-transform: uppercase;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        cursor: pointer;
    }

    .brand-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        background-color: #FFD21F;
        border-radius: 50%;
    }

    /* Hero Typography */
    .hero-eyebrow {
        font-size: 1rem;
        font-weight: 700;
        color: #A6A6A6;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.6rem;
    }

    .hero-title-main {
        font-size: clamp(3rem, 6vw, 4.5rem);
        font-weight: 900;
        line-height: 1.05;
        letter-spacing: -0.03em;
        color: #F5F5F5;
        margin-bottom: 0.2rem;
    }

    .hero-title-yellow {
        font-size: clamp(3rem, 6vw, 4.5rem);
        font-weight: 900;
        line-height: 1.05;
        letter-spacing: -0.03em;
        color: #FFD21F;
        margin-bottom: 1.35rem;
    }

    .hero-subhead {
        font-size: 1.5rem;
        font-weight: 700;
        color: #F5F5F5;
        margin-bottom: 0.4rem;
    }

    .hero-body {
        font-size: 1.15rem;
        color: #A6A6A6;
        margin-bottom: 2rem;
        line-height: 1.55;
    }

    /* Streamlit Form Container */
    [data-testid="stForm"] {
        background-color: #111111 !important;
        border: 1.5px solid #282828 !important;
        border-radius: 20px !important;
        padding: 2rem 2.25rem !important;
        box-shadow: 0 16px 48px rgba(0, 0, 0, 0.45) !important;
        margin-bottom: 0.5rem !important;
    }

    /* Input Field Styling */
    .stTextInput > div > div > input {
        background-color: #171717 !important;
        border: 1.5px solid #333333 !important;
        border-radius: 14px !important;
        color: #F5F5F5 !important;
        font-size: 1.2rem !important;
        padding: 1.1rem 1.4rem !important;
        height: 62px !important;
        transition: all 0.2s ease !important;
    }

    .stTextInput > div > div > input:focus {
        border-color: #FFD21F !important;
        box-shadow: 0 0 0 2px #FFD21F33 !important;
        outline: none !important;
    }

    .stTextInput > div > div > input::placeholder {
        color: #666666 !important;
    }

    /* Primary Buttons */
    button[kind="primary"],
    button[kind="primaryFormSubmit"],
    .stButton > button[kind="primary"],
    .stFormSubmitButton > button,
    [data-testid*="primary"] {
        background-color: #FFD21F !important;
        color: #0A0A0A !important;
        border: none !important;
        border-radius: 14px !important;
        font-size: 1.15rem !important;
        font-weight: 800 !important;
        letter-spacing: 0.04em !important;
        padding: 1rem 2rem !important;
        height: 58px !important;
        width: 100% !important;
        transition: all 0.15s ease !important;
        cursor: pointer !important;
    }

    button[kind="primary"]:hover,
    button[kind="primaryFormSubmit"]:hover,
    .stButton > button[kind="primary"]:hover,
    .stFormSubmitButton > button:hover,
    [data-testid*="primary"]:hover {
        background-color: #FFE45C !important;
        color: #0A0A0A !important;
        transform: translateY(-1px) !important;
    }

    /* Secondary Buttons / Nav Buttons */
    button[kind="secondary"], .stButton > button[kind="secondary"], .stButton > button {
        background-color: #171717 !important;
        color: #F5F5F5 !important;
        border: 1px solid #2C2C2C !important;
        border-radius: 12px !important;
        font-size: 1rem !important;
        font-weight: 700 !important;
        padding: 0.75rem 1.25rem !important;
        min-height: 46px !important;
        transition: all 0.15s ease !important;
        cursor: pointer !important;
    }

    button[kind="secondary"]:hover, .stButton > button[kind="secondary"]:hover, .stButton > button:hover {
        background-color: #222222 !important;
        border-color: #FFD21F66 !important;
        color: #FFD21F !important;
    }

    /* Minimal Example Link Chips */
    .example-title {
        font-size: 0.92rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #888888;
        margin-top: 1.75rem;
        margin-bottom: 0.75rem;
    }

    /* Input helper note */
    .input-helper {
        font-size: 0.9rem;
        color: #777777;
        margin-top: 0.6rem;
        text-align: center;
    }

    /* Card Containers */
    .consumer-card {
        background-color: #111111;
        border: 1px solid #292929;
        border-radius: 16px;
        padding: 1.5rem;
        margin-bottom: 1.25rem;
    }

    .url-checked-box {
        background-color: #111111;
        border: 1px solid #292929;
        border-radius: 12px;
        padding: 0.85rem 1.15rem;
        margin-bottom: 1.5rem;
    }

    .url-checked-label {
        font-size: 0.78rem;
        font-weight: 700;
        color: #A6A6A6;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 0.3rem;
    }

    .url-checked-value {
        font-size: 0.98rem;
        color: #F5F5F5;
        word-break: break-all;
        font-family: -apple-system, BlinkMacSystemFont, monospace;
        line-height: 1.4;
    }

    /* Result State Banners */
    .result-banner {
        border-radius: 20px;
        padding: 2.25rem 2rem;
        margin-bottom: 1.75rem;
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        gap: 0.85rem;
    }

    .result-banner-safe {
        background-color: #0C1E14;
        border: 1.5px solid #1E5032;
    }

    .result-banner-suspicious {
        background-color: #211A04;
        border: 1.5px solid #54430D;
    }

    .result-banner-dangerous {
        background-color: #210C0F;
        border: 1.5px solid #571C23;
    }

    .result-icon-badge {
        font-size: 2.6rem;
        line-height: 1;
        margin-bottom: 0.25rem;
    }

    .result-heading-safe {
        font-size: clamp(2rem, 4.5vw, 2.7rem);
        font-weight: 900;
        letter-spacing: -0.02em;
        color: #22C55E;
        line-height: 1.15;
    }

    .result-heading-suspicious {
        font-size: clamp(2rem, 4.5vw, 2.7rem);
        font-weight: 900;
        letter-spacing: -0.02em;
        color: #FFD21F;
        line-height: 1.15;
    }

    .result-heading-dangerous {
        font-size: clamp(2rem, 4.5vw, 2.7rem);
        font-weight: 900;
        letter-spacing: -0.02em;
        color: #EF4444;
        line-height: 1.15;
    }

    .result-subheading {
        font-size: 1.3rem;
        font-weight: 700;
        color: #F5F5F5;
        margin-top: -0.2rem;
    }

    .result-explainer {
        font-size: 1.15rem;
        color: #D4D4D4;
        line-height: 1.55;
        margin-top: 0.25rem;
    }

    /* Score Bar */
    .score-container {
        background-color: #111111;
        border: 1px solid #292929;
        border-radius: 18px;
        padding: 1.5rem 1.75rem;
        margin-bottom: 1.75rem;
    }

    .score-header {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        margin-bottom: 0.85rem;
    }

    .score-label {
        font-size: 0.9rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #A6A6A6;
    }

    .score-num {
        font-size: 1.85rem;
        font-weight: 900;
        color: #F5F5F5;
    }

    .score-max {
        font-size: 1.05rem;
        font-weight: 600;
        color: #777777;
    }

    .score-track {
        width: 100%;
        height: 14px;
        background-color: #1F1F1F;
        border-radius: 999px;
        overflow: hidden;
    }

    .score-fill-safe {
        height: 100%;
        background-color: #22C55E;
        border-radius: 999px;
        transition: width 0.4s ease;
    }

    .score-fill-suspicious {
        height: 100%;
        background-color: #FFD21F;
        border-radius: 999px;
        transition: width 0.4s ease;
    }

    .score-fill-dangerous {
        height: 100%;
        background-color: #EF4444;
        border-radius: 999px;
        transition: width 0.4s ease;
    }

    /* Why Section Items */
    .section-title {
        font-size: 0.95rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #A6A6A6;
        margin-bottom: 1rem;
        margin-top: 1.75rem;
    }

    .signal-item {
        background-color: #141414;
        border: 1px solid #242424;
        border-radius: 14px;
        padding: 1.15rem 1.35rem;
        margin-bottom: 0.75rem;
    }

    .signal-title-safe {
        font-size: 1.05rem;
        font-weight: 700;
        color: #F5F5F5;
        margin-bottom: 0.25rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .signal-title-warn {
        font-size: 1.05rem;
        font-weight: 700;
        color: #F5F5F5;
        margin-bottom: 0.25rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .signal-desc {
        font-size: 0.95rem;
        color: #A6A6A6;
        line-height: 1.5;
    }

    /* Recommended Action Box */
    .action-box {
        background-color: #181818;
        border-left: 5px solid #FFD21F;
        border-radius: 0 14px 14px 0;
        padding: 1.35rem 1.6rem;
        margin-top: 1.75rem;
        margin-bottom: 2.25rem;
    }

    .action-box-dangerous {
        background-color: #181818;
        border-left: 5px solid #EF4444;
        border-radius: 0 14px 14px 0;
        padding: 1.35rem 1.6rem;
        margin-top: 1.75rem;
        margin-bottom: 2.25rem;
    }

    .action-label {
        font-size: 0.85rem;
        font-weight: 800;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #A6A6A6;
        margin-bottom: 0.4rem;
    }

    .action-text {
        font-size: 1.12rem;
        font-weight: 600;
        color: #F5F5F5;
        line-height: 1.5;
    }

    /* Consumer Education Cards */
    .edu-card {
        background-color: #111111;
        border: 1px solid #292929;
        border-radius: 16px;
        padding: 1.6rem;
        margin-bottom: 1.25rem;
    }

    .edu-num {
        font-size: 0.9rem;
        font-weight: 800;
        color: #FFD21F;
        margin-bottom: 0.4rem;
    }

    .edu-title {
        font-size: 1.25rem;
        font-weight: 800;
        color: #F5F5F5;
        margin-bottom: 0.4rem;
    }

    .edu-desc {
        font-size: 1.05rem;
        color: #A6A6A6;
        line-height: 1.55;
    }

    /* Disclaimer */
    .simple-footer {
        text-align: center;
        font-size: 0.82rem;
        color: #555555;
        margin-top: 3rem;
        line-height: 1.5;
    }

    /* Error Banner */
    .error-banner {
        background-color: #1F1012;
        border: 1px solid #4D1E25;
        border-radius: 10px;
        color: #F87171;
        padding: 0.85rem 1.15rem;
        font-size: 0.95rem;
        font-weight: 600;
        margin-bottom: 1.25rem;
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# HUMAN TRANSLATION HELPER FOR THREAT SIGNALS
# ==============================================================================
def humanize_threat_indicator(indicator: str, description: str) -> dict:
    """
    Translates raw technical finding into simple, friendly consumer language.
    Does not expose technical feature names.
    """
    ind_lower = indicator.lower()

    if "raw ip" in ind_lower or "ip address" in ind_lower:
        return {
            "title": "Number-only website address",
            "desc": "This link uses a raw number address instead of a recognized website name."
        }
    elif "shortening" in ind_lower or "shortener" in ind_lower:
        return {
            "title": "Hidden destination",
            "desc": "This link uses a shortening service that hides where it actually leads."
        }
    elif "@ symbol" in ind_lower or "@" in ind_lower:
        return {
            "title": "Deceptive address masking",
            "desc": "Contains an '@' symbol, which can hide the real destination you are being sent to."
        }
    elif "double slash" in ind_lower:
        return {
            "title": "Hidden address redirection",
            "desc": "Contains redirect markers in the address path that may send you to an unexpected page."
        }
    elif "hyphen" in ind_lower or "prefix" in ind_lower:
        return {
            "title": "Suspicious website name",
            "desc": "The website name contains hyphens, a pattern often used to mimic trusted brands."
        }
    elif "multiple subdomain" in ind_lower or "subdomain" in ind_lower:
        return {
            "title": "Unusual address structure",
            "desc": "The web address has multiple sub-names stacked together to appear authentic."
        }
    elif "excessive url length" in ind_lower or "length" in ind_lower:
        return {
            "title": "Unusually long link",
            "desc": "This web address is unusually long, which can be used to hide the true destination."
        }
    elif "non-standard port" in ind_lower or "port" in ind_lower:
        return {
            "title": "Unusual network port",
            "desc": "The link connects through an unusual port rather than normal website traffic."
        }
    elif "fake 'https'" in ind_lower or "https token" in ind_lower:
        return {
            "title": "Deceptive 'https' in name",
            "desc": "The letters 'https' are placed inside the website name itself to create a false impression of security."
        }
    elif "malformed" in ind_lower or "abnormal" in ind_lower:
        return {
            "title": "Unrecognized address format",
            "desc": "The web address structure doesn't match standard website naming rules."
        }
    elif "insecure http" in ind_lower or "http protocol" in ind_lower:
        return {
            "title": "Unsecured connection",
            "desc": "This link does not use secure HTTPS encryption, so data could be intercepted."
        }
    elif "keyword" in ind_lower:
        return {
            "title": "Deceptive words",
            "desc": "The link contains words commonly used to make fake login or account verification pages look official."
        }
    elif "tld" in ind_lower:
        return {
            "title": "High-risk domain ending",
            "desc": "The link ends in a domain extension frequently associated with spam or scam websites."
        }
    elif "punycode" in ind_lower or "homograph" in ind_lower:
        return {
            "title": "Lookalike character disguise",
            "desc": "Uses special character encoding that visually impersonates another website."
        }
    elif "entropy" in ind_lower:
        return {
            "title": "Scrambled character string",
            "desc": "Contains a scrambled sequence of random characters often used in automated attack links."
        }
    else:
        return {
            "title": "Unusual web address pattern",
            "desc": description if description else "This web address exhibits structural patterns commonly seen in suspicious links."
        }


def validate_input_url(url: str) -> tuple[bool, str]:
    """Basic validation for consumer input URL."""
    cleaned = url.strip()
    if not cleaned:
        return False, "Paste a link to check it."

    # Reject whitespace-only or single weird characters
    if len(cleaned) < 3 or " " in cleaned:
        return False, "That doesn't look like a valid web address. Check the link and try again."

    # Basic dot or scheme presence check
    if "." not in cleaned and not cleaned.startswith("http"):
        return False, "That doesn't look like a valid web address. Check the link and try again."

    return True, ""


# ==============================================================================
# SESSION STATE INITIALIZATION
# ==============================================================================
if "active_page" not in st.session_state:
    st.session_state.active_page = "home"

if "scanned_result" not in st.session_state:
    st.session_state.scanned_result = None

if "scanned_url" not in st.session_state:
    st.session_state.scanned_url = ""

if "input_url" not in st.session_state:
    st.session_state.input_url = ""

if "error_message" not in st.session_state:
    st.session_state.error_message = None


def navigate_to(page: str):
    st.session_state.active_page = page
    st.session_state.error_message = None
    if page == "home":
        st.session_state.scanned_result = None
        st.session_state.input_url = ""


def run_url_check(url_to_check: str):
    valid, err = validate_input_url(url_to_check)
    if not valid:
        st.session_state.error_message = err
        st.session_state.scanned_result = None
        return

    st.session_state.error_message = None
    try:
        with st.spinner("CHECKING LINK..."):
            endpoint = f"{BACKEND_URL}/api/analyze"
            response = requests.post(
                endpoint,
                json={"url": url_to_check},
                timeout=15
            )
            if response.status_code == 200:
                report = response.json()
                st.session_state.scanned_result = report
                st.session_state.scanned_url = url_to_check
                st.session_state.active_page = "home"
            elif response.status_code in (400, 422):
                detail = response.json().get("detail", "Invalid web address.")
                st.session_state.error_message = detail
                st.session_state.scanned_result = None
            else:
                st.session_state.error_message = f"Backend error ({response.status_code}). Please try again."
                st.session_state.scanned_result = None
    except requests.exceptions.ConnectionError:
        st.session_state.error_message = (
            f"Cannot reach CyberSentinel backend at {BACKEND_URL}. "
            "Please verify that the backend API server is running."
        )
        st.session_state.scanned_result = None
    except requests.exceptions.Timeout:
        st.session_state.error_message = "The request timed out. Please try again."
        st.session_state.scanned_result = None
    except Exception:
        st.session_state.error_message = "Something went wrong while checking this link. Please try again."
        st.session_state.scanned_result = None


# ==============================================================================
# MINIMAL BRAND HEADER & NAVIGATION
# ==============================================================================
col_logo, col_nav1, col_nav2, col_nav3 = st.columns([3.2, 1.2, 1.6, 1.4])

with col_logo:
    st.markdown("""
    <div class="brand-logo">
        <span class="brand-dot"></span> CYBERSENTINEL
    </div>
    """, unsafe_allow_html=True)

with col_nav1:
    if st.button("Home", key="nav_home", use_container_width=True):
        navigate_to("home")

with col_nav2:
    if st.button("How It Works", key="nav_how", use_container_width=True):
        navigate_to("how_it_works")

with col_nav3:
    if st.button("Safety Tips", key="nav_tips", use_container_width=True):
        navigate_to("safety_tips")

st.markdown('<div style="height: 1px; background-color: #1A1A1A; margin-bottom: 1.75rem;"></div>', unsafe_allow_html=True)


# ==============================================================================
# PAGE 1: HOW IT WORKS
# ==============================================================================
if st.session_state.active_page == "how_it_works":
    st.markdown('<div class="hero-eyebrow">SIMPLE & TRANSPARENT</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-title-main">HOW IT WORKS</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-body">Three simple steps to keep yourself safe before clicking unknown links.</div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="edu-card">
        <div class="edu-num">STEP 01</div>
        <div class="edu-title">PASTE YOUR LINK</div>
        <div class="edu-desc">Copy the link you want to check from your text message, email, or social media.</div>
    </div>

    <div class="edu-card">
        <div class="edu-num">STEP 02</div>
        <div class="edu-title">CHECK IT</div>
        <div class="edu-desc">CyberSentinel analyzes the web address looking for warning signs, hidden destinations, and deceptive tricks.</div>
    </div>

    <div class="edu-card">
        <div class="edu-num">STEP 03</div>
        <div class="edu-title">UNDERSTAND THE RESULT</div>
        <div class="edu-desc">We explain what the result means in plain English, give you an easy-to-read Safety Score, and tell you what you should do next.</div>
    </div>
    """, unsafe_allow_html=True)

    st.write("")
    if st.button("CHECK A LINK NOW", type="primary", key="how_btn"):
        navigate_to("home")


# ==============================================================================
# PAGE 2: SAFETY TIPS
# ==============================================================================
elif st.session_state.active_page == "safety_tips":
    # Wide layout override for Safety Tips page
    st.markdown("""
    <style>
        section[data-testid="stMain"] > div.main > div.block-container,
        .main > div.block-container,
        .main .block-container {
            max-width: 1240px !important;
            width: 100% !important;
            margin-left: auto !important;
            margin-right: auto !important;
            padding-left: 2rem !important;
            padding-right: 2rem !important;
        }
        [data-testid="stMainBlockContainer"] {
            max-width: 1240px !important;
            margin-left: auto !important;
            margin-right: auto !important;
        }
        /* Hide the Streamlit iframe border */
        iframe { border: none !important; }
    </style>
    """, unsafe_allow_html=True)

    # ==================================================================
    # GRANDPA SVG CHARACTER
    # ==================================================================
    GRANDPA_SVG = """<svg viewBox="0 0 320 420" xmlns="http://www.w3.org/2000/svg" width="220" style="filter: drop-shadow(0 20px 60px rgba(0,0,0,0.85));">
<defs>
<radialGradient id="gpSpot" cx="50%" cy="40%" r="50%"><stop offset="0%" stop-color="#FFD21F" stop-opacity="0.12"/><stop offset="100%" stop-color="#000" stop-opacity="0"/></radialGradient>
<radialGradient id="skinG" cx="40%" cy="35%" r="60%"><stop offset="0%" stop-color="#f5c8a8"/><stop offset="100%" stop-color="#d49070"/></radialGradient>
<radialGradient id="cheekG" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#e86050" stop-opacity="0.75"/><stop offset="100%" stop-color="#e86050" stop-opacity="0"/></radialGradient>
</defs>
<!-- Spotlight & Body Shadow -->
<ellipse cx="160" cy="180" rx="140" ry="160" fill="url(#gpSpot)"/>
<ellipse cx="160" cy="365" rx="95" ry="65" fill="#141414"/>

<!-- Torso / Dark Jacket -->
<rect x="76" y="300" width="168" height="100" rx="20" fill="#1A1A1A"/>
<path d="M145 302 Q160 295 175 302 L172 320 Q160 315 148 320 Z" fill="#EBEBEB"/>
<path d="M145 302 L108 345 L130 345 L148 320 Z" fill="#222"/>
<path d="M175 302 L212 345 L190 345 L172 320 Z" fill="#222"/>
<path d="M148 310 L160 318 L172 310 L165 303 L160 307 L155 303 Z" fill="#141414"/>
<circle cx="160" cy="312" r="3" fill="#FFD21F"/>
<rect x="143" y="305" width="7" height="75" rx="3" fill="#2A2A2A" transform="rotate(-5, 143 305)"/>
<rect x="170" y="305" width="7" height="75" rx="3" fill="#2A2A2A" transform="rotate(5, 177 305)"/>
<rect x="139" y="340" width="14" height="8" rx="2" fill="#FFD21F"/>
<rect x="167" y="340" width="14" height="8" rx="2" fill="#FFD21F"/>
<path d="M152 330 L160 326 L168 330 L168 340 Q160 345 152 340 Z" fill="#FFD21F"/>
<path d="M155 334 L158 338 L165 331" stroke="#0A0A0A" stroke-width="2" fill="none" stroke-linecap="round"/>

<!-- LEFT ARM & FIST: Aggressively planted on hip -->
<path d="M106 304 L52 336 Q42 344 48 355 L72 368 L88 344 L114 322 Z" fill="#181818"/>
<path d="M52 336 L48 355 L72 368 L78 354 Z" fill="#111"/>
<!-- Left Shirt Cuff -->
<path d="M68 358 L82 350 L87 358 L73 366 Z" fill="#EBEBEB"/>
<!-- Left Clenched Fist on Hip -->
<g transform="translate(80, 362)">
  <ellipse cx="6" cy="6" rx="13" ry="11" fill="#d99872"/>
  <rect x="-4" y="0" width="8" height="10" rx="3" fill="#f0b896" stroke="#b07048" stroke-width="1.2"/>
  <rect x="3" y="0" width="8" height="10" rx="3" fill="#f0b896" stroke="#b07048" stroke-width="1.2"/>
  <rect x="10" y="1" width="7" height="9" rx="3" fill="#e8ad88" stroke="#b07048" stroke-width="1.2"/>
  <path d="M-5 4 Q2 -2 10 2" stroke="#9e4822" stroke-width="2.2" fill="none" stroke-linecap="round"/>
</g>

<!-- RIGHT ARM & RAISED LECTURING FINGER (The Angry Warning Hand) -->
<path d="M210 308 L244 266 Q250 258 260 264 L274 280 L232 328 Z" fill="#181818"/>
<path d="M220 314 L248 274 L264 288 L232 328 Z" fill="#242424"/>
<!-- White Shirt Cuff -->
<path d="M242 264 L258 248 L268 258 L252 274 Z" fill="#EBEBEB"/>

<!-- Animated Scolding Right Hand Group -->
<g class="grandpa-hand" style="transform-origin: 256px 255px;">
  <!-- Motion Swoosh Accents for stern lecturing wag -->
  <path d="M232 135 Q224 145 228 156" stroke="#FFD21F" stroke-width="2.5" fill="none" stroke-linecap="round" opacity="0.9"/>
  <path d="M276 135 Q284 145 280 156" stroke="#FFD21F" stroke-width="2.5" fill="none" stroke-linecap="round" opacity="0.9"/>
  <path d="M228 126 Q218 138 222 150" stroke="#FFD21F" stroke-width="1.5" fill="none" stroke-linecap="round" opacity="0.5"/>
  <path d="M280 126 Q290 138 286 150" stroke="#FFD21F" stroke-width="1.5" fill="none" stroke-linecap="round" opacity="0.5"/>

  <!-- Fist base palm -->
  <path d="M244 226 Q238 246 250 256 Q264 260 274 250 Q280 236 272 224 Z" fill="#dda07c"/>

  <!-- Curled fingers (Middle, Ring, Pinky) -->
  <rect x="254" y="214" width="23" height="13" rx="6" fill="#f0b896" stroke="#b07048" stroke-width="1.4"/>
  <line x1="264" y1="220" x2="273" y2="220" stroke="#b07048" stroke-width="1.2"/>
  <rect x="253" y="226" width="22" height="13" rx="6" fill="#e8ad88" stroke="#b07048" stroke-width="1.4"/>
  <line x1="263" y1="232" x2="272" y2="232" stroke="#b07048" stroke-width="1.2"/>
  <rect x="251" y="238" width="20" height="12" rx="5" fill="#dda07c" stroke="#b07048" stroke-width="1.4"/>
  <line x1="261" y1="244" x2="269" y2="244" stroke="#b07048" stroke-width="1.2"/>

  <!-- Thumb locked over fist -->
  <path d="M242 228 Q236 214 246 210 Q258 208 264 220 Q256 232 244 232 Z" fill="#f5c0a0" stroke="#b07048" stroke-width="1.5"/>
  <path d="M246 218 Q252 216 258 219" stroke="#b07048" stroke-width="1.4" fill="none"/>

  <!-- Sharp, Accusing Index Finger Raised High -->
  <path d="M241 216 L245 148 Q247 136 256 136 Q265 136 264 148 L259 216 Z" fill="#f5c2a2" stroke="#b07048" stroke-width="1.6"/>
  <!-- Fingernail -->
  <path d="M248 144 Q255 140 262 144 Q262 153 248 153 Z" fill="#fff" stroke="#c08058" stroke-width="0.8" opacity="0.9"/>
  <!-- Knuckle crease lines -->
  <line x1="244" y1="168" x2="263" y2="168" stroke="#a05830" stroke-width="1.8" stroke-linecap="round"/>
  <line x1="243" y1="192" x2="261" y2="192" stroke="#a05830" stroke-width="1.8" stroke-linecap="round"/>
</g>

<!-- Neck -->
<rect x="148" y="272" width="24" height="35" rx="10" fill="#d89a74"/>

<!-- Head Base -->
<rect x="105" y="155" width="110" height="125" rx="38" fill="url(#skinG)"/>

<!-- Angry Forehead Wrinkle Lines -->
<path d="M125 168 Q160 160 195 168" stroke="#9e4c25" stroke-width="2.2" fill="none" stroke-linecap="round"/>
<path d="M130 176 Q160 168 190 176" stroke="#9e4c25" stroke-width="2.2" fill="none" stroke-linecap="round"/>

<!-- Red Anger Stress Vein on Forehead / Temple (💢) -->
<g transform="translate(198, 154)">
  <path d="M4 1 L14 1 M9 -4 L9 6" stroke="#ff2a2a" stroke-width="2.4" stroke-linecap="round"/>
  <path d="M6 -2 L12 4 M12 -2 L6 4" stroke="#ff2a2a" stroke-width="2" stroke-linecap="round"/>
</g>

<!-- Flushed Angry Cheeks & Ears -->
<ellipse cx="118" cy="225" rx="15" ry="16" fill="#e85040" opacity="0.45"/>
<ellipse cx="202" cy="225" rx="15" ry="16" fill="#e85040" opacity="0.45"/>
<ellipse cx="122" cy="228" rx="10" ry="7" fill="url(#cheekG)"/>
<ellipse cx="198" cy="228" rx="10" ry="7" fill="url(#cheekG)"/>

<!-- Intense Furious Eyebrows (Steep V-Angled Scowl) -->
<!-- Shadow under brows -->
<path d="M106 186 L154 209 L150 215 L108 192 Z" fill="#6a2510" opacity="0.25"/>
<path d="M214 186 L166 209 L170 215 L212 192 Z" fill="#6a2510" opacity="0.25"/>
<!-- Main Heavy Eyebrows -->
<path d="M106 185 L154 208" stroke="#221208" stroke-width="8" stroke-linecap="round"/>
<path d="M214 185 L166 208" stroke="#221208" stroke-width="8" stroke-linecap="round"/>
<!-- Bristly Gray/White Eyebrow Hairs -->
<path d="M110 183 L116 177 M122 185 L128 178 M136 193 L142 186 M146 200 L152 193" stroke="#e0e0e0" stroke-width="2.2" stroke-linecap="round"/>
<path d="M210 183 L204 177 M198 185 L192 178 M184 193 L178 186 M174 200 L168 193" stroke="#e0e0e0" stroke-width="2.2" stroke-linecap="round"/>

<!-- Vertical Scowl Furrow Between Brows -->
<path d="M156 192 L156 212" stroke="#681808" stroke-width="3" stroke-linecap="round"/>
<path d="M164 192 L164 212" stroke="#681808" stroke-width="3" stroke-linecap="round"/>
<path d="M151 198 L155 208" stroke="#7a2410" stroke-width="2" stroke-linecap="round"/>
<path d="M169 198 L165 208" stroke="#7a2410" stroke-width="2" stroke-linecap="round"/>

<!-- Eyes Glaring Narrowed & Furious -->
<!-- Eye Socket Shadow -->
<ellipse cx="138" cy="216" rx="17" ry="13" fill="#a05030" opacity="0.3"/>
<ellipse cx="182" cy="216" rx="17" ry="13" fill="#a05030" opacity="0.3"/>
<!-- Eye White -->
<ellipse cx="138" cy="217" rx="12" ry="9" fill="white"/>
<ellipse cx="182" cy="217" rx="12" ry="9" fill="white"/>
<!-- Iris Glaring Downward-Forward -->
<ellipse cx="139" cy="218" rx="7" ry="7" fill="#2a456c"/>
<ellipse cx="183" cy="218" rx="7" ry="7" fill="#2a456c"/>
<!-- Pupil (Pinpoint intense anger) -->
<circle cx="140" cy="218" r="4.5" fill="#0A0A0A"/>
<circle cx="184" cy="218" r="4.5" fill="#0A0A0A"/>
<circle cx="142" cy="215" r="1.5" fill="white"/>
<circle cx="186" cy="215" r="1.5" fill="white"/>

<!-- Heavy Angry Eyelids pressing down into a sharp scowl -->
<path d="M125 210 Q140 220 152 222 L152 210 Z" fill="#d49070"/>
<path d="M125 210 Q140 220 152 222" stroke="#4a1a08" stroke-width="1.8" fill="none"/>
<path d="M195 210 Q180 220 168 222 L168 210 Z" fill="#d49070"/>
<path d="M195 210 Q180 220 168 222" stroke="#4a1a08" stroke-width="1.8" fill="none"/>

<!-- Under-eye Tension Bags -->
<path d="M127 225 Q138 230 149 226" stroke="#8a3c1c" stroke-width="1.8" fill="none" stroke-linecap="round"/>
<path d="M171 226 Q182 230 193 225" stroke="#8a3c1c" stroke-width="1.8" fill="none" stroke-linecap="round"/>

<!-- Thick Dark Glasses -->
<rect x="118" y="205" width="42" height="28" rx="6" fill="none" stroke="#111" stroke-width="6"/>
<rect x="160" y="205" width="42" height="28" rx="6" fill="none" stroke="#111" stroke-width="6"/>
<rect x="158" y="215" width="6" height="6" rx="1" fill="#111"/>
<line x1="118" y1="218" x2="105" y2="222" stroke="#111" stroke-width="5" stroke-linecap="round"/>
<line x1="202" y1="218" x2="215" y2="222" stroke="#111" stroke-width="5" stroke-linecap="round"/>
<rect x="121" y="208" width="36" height="22" rx="4" fill="#ff4000" opacity="0.08"/>
<rect x="163" y="208" width="36" height="22" rx="4" fill="#ff4000" opacity="0.08"/>

<!-- Red Flushed Nose -->
<ellipse cx="160" cy="239" rx="15" ry="12" fill="#d86048"/>
<circle cx="152" cy="243" r="5" fill="#b84838"/>
<circle cx="168" cy="243" r="5" fill="#b84838"/>
<path d="M152 235 Q160 231 168 235" stroke="#ff9080" stroke-width="1.5" fill="none"/>

<!-- YELLING / SCOLDING MOUTH (Bared Teeth Furious Grimace) -->
<g class="grandpa-head">
  <!-- Mouth Cavity -->
  <path d="M135 254 Q160 248 185 254 Q188 274 178 283 Q160 288 142 283 Q132 274 135 254 Z" fill="#220404" stroke="#5a1008" stroke-width="2.2"/>
  <!-- Top Teeth Row -->
  <path d="M138 255 Q160 252 182 255 L180 264 Q160 260 140 264 Z" fill="#FFFFFF"/>
  <line x1="147" y1="255" x2="147" y2="263" stroke="#a0a0a0" stroke-width="1.2"/>
  <line x1="155" y1="254" x2="155" y2="262" stroke="#a0a0a0" stroke-width="1.2"/>
  <line x1="165" y1="254" x2="165" y2="262" stroke="#a0a0a0" stroke-width="1.2"/>
  <line x1="173" y1="255" x2="173" y2="263" stroke="#a0a0a0" stroke-width="1.2"/>
  <!-- Bottom Teeth Row -->
  <path d="M145 278 Q160 274 175 278 L173 273 Q160 270 147 273 Z" fill="#ECECEC"/>
  <line x1="153" y1="273" x2="153" y2="278" stroke="#a0a0a0" stroke-width="1"/>
  <line x1="161" y1="272" x2="161" y2="277" stroke="#a0a0a0" stroke-width="1"/>
  <line x1="167" y1="273" x2="167" y2="278" stroke="#a0a0a0" stroke-width="1"/>
  <!-- Angry Tongue -->
  <path d="M150 280 Q160 274 170 280 Q160 287 150 280 Z" fill="#9e2828"/>
  <!-- Deep Scowl / Marionette Lines -->
  <path d="M129 250 Q124 266 133 282" stroke="#681808" stroke-width="2.5" fill="none" stroke-linecap="round"/>
  <path d="M191 250 Q196 266 187 282" stroke="#681808" stroke-width="2.5" fill="none" stroke-linecap="round"/>
  <!-- Chin Frown Crease -->
  <path d="M150 290 Q160 294 170 290" stroke="#7a2410" stroke-width="2.5" fill="none" stroke-linecap="round"/>
</g>

<!-- White Hair on Sides -->
<ellipse cx="160" cy="155" rx="58" ry="32" fill="#E8E8E8"/>
<ellipse cx="106" cy="175" rx="22" ry="30" fill="#DFDFDF"/>
<ellipse cx="214" cy="175" rx="22" ry="30" fill="#DFDFDF"/>
<path d="M120 155 Q130 130 145 140 Q155 125 175 140 Q190 130 200 155" fill="#EBEBEB"/>
<path d="M138 143 Q155 133 175 143" stroke="white" stroke-width="4" fill="none" stroke-linecap="round" opacity="0.6"/>

<!-- Ears -->
<ellipse cx="106" cy="220" rx="10" ry="14" fill="#d4946a"/>
<ellipse cx="107" cy="220" rx="6" ry="9" fill="#c48060"/>
<ellipse cx="214" cy="220" rx="10" ry="14" fill="#d4946a"/>
<ellipse cx="213" cy="220" rx="6" ry="9" fill="#c48060"/>
</svg>"""

    # ==================================================================
    # GRANDMA SVG CHARACTER
    # ==================================================================
    GRANDMA_SVG = """<svg viewBox="0 0 300 440" xmlns="http://www.w3.org/2000/svg" width="220" style="filter: drop-shadow(0 20px 50px rgba(0,0,0,0.8));">
<defs>
<radialGradient id="gmSpot" cx="50%" cy="40%" r="50%"><stop offset="0%" stop-color="#E8E8E8" stop-opacity="0.06"/><stop offset="100%" stop-color="#000" stop-opacity="0"/></radialGradient>
<radialGradient id="gmSkin" cx="40%" cy="30%" r="60%"><stop offset="0%" stop-color="#f8d0b0"/><stop offset="100%" stop-color="#e0a888"/></radialGradient>
<radialGradient id="gmCheek" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="#f09090" stop-opacity="0.55"/><stop offset="100%" stop-color="#f09090" stop-opacity="0"/></radialGradient>
</defs>
<ellipse cx="150" cy="200" rx="130" ry="180" fill="url(#gmSpot)"/>
<ellipse cx="150" cy="380" rx="80" ry="65" fill="#181818"/>
<rect x="78" y="315" width="144" height="90" rx="20" fill="#1E1E1E"/>
<circle cx="122" cy="310" r="4" fill="#E8E6E0"/>
<circle cx="132" cy="313" r="4.5" fill="#F0EEEA"/>
<circle cx="142" cy="315" r="4.5" fill="#E8E6E0"/>
<circle cx="152" cy="316" r="5" fill="#F0EEEA"/>
<circle cx="162" cy="315" r="4.5" fill="#E8E6E0"/>
<circle cx="172" cy="313" r="4.5" fill="#F0EEEA"/>
<circle cx="181" cy="310" r="4" fill="#E8E6E0"/>
<path d="M140 316 Q150 322 160 316 L157 335 Q150 330 143 335 Z" fill="#EBEBEB" opacity="0.9"/>
<circle cx="150" cy="326" r="7" fill="#FFD21F"/>
<circle cx="150" cy="326" r="4" fill="#0A0A0A"/>
<circle cx="150" cy="326" r="2" fill="#FFD21F"/>
<rect x="60" y="315" width="30" height="55" rx="15" fill="#1E1E1E" transform="rotate(20 75 342)"/>
<rect x="42" y="340" width="40" height="65" rx="8" fill="#1a1a1a"/>
<rect x="45" y="344" width="34" height="56" rx="5" fill="#0f0f1a"/>
<rect x="47" y="347" width="30" height="28" rx="3" fill="#1a3a5c"/>
<rect x="49" y="350" width="26" height="4" rx="2" fill="#4080c0" opacity="0.7"/>
<rect x="49" y="357" width="20" height="3" rx="2" fill="#2060a0" opacity="0.5"/>
<rect x="210" y="315" width="30" height="50" rx="14" fill="#1E1E1E" transform="rotate(-15 225 340)"/>
<g class="grandma-wave">
<ellipse cx="232" cy="358" rx="15" ry="13" fill="#f0c09a"/>
<rect x="225" y="338" width="10" height="26" rx="5" fill="#f0c09a" transform="rotate(-10 230 351)"/>
<rect x="235" y="335" width="9" height="26" rx="5" fill="#f0c09a" transform="rotate(5 239 348)"/>
</g>
<rect x="138" y="283" width="24" height="38" rx="11" fill="#e8b890"/>
<ellipse cx="150" cy="210" rx="68" ry="78" fill="url(#gmSkin)"/>
<ellipse cx="100" cy="230" rx="22" ry="20" fill="#f0b090" opacity="0.4"/>
<ellipse cx="200" cy="230" rx="22" ry="20" fill="#f0b090" opacity="0.4"/>
<ellipse cx="104" cy="233" rx="14" ry="9" fill="url(#gmCheek)"/>
<ellipse cx="196" cy="233" rx="14" ry="9" fill="url(#gmCheek)"/>
<path d="M106 188 Q120 180 135 186" stroke="#6a4030" stroke-width="4" fill="none" stroke-linecap="round"/>
<path d="M165 186 Q180 180 194 188" stroke="#6a4030" stroke-width="4" fill="none" stroke-linecap="round"/>
<ellipse cx="125" cy="215" rx="20" ry="19" fill="white"/>
<ellipse cx="126" cy="216" rx="12" ry="12" fill="#4a90c8"/>
<circle cx="127" cy="215" r="8" fill="#1a2a3a"/>
<circle cx="130" cy="212" r="2.5" fill="white"/>
<circle cx="124" cy="219" r="1.5" fill="white" opacity="0.6"/>
<ellipse cx="175" cy="215" rx="20" ry="19" fill="white"/>
<ellipse cx="176" cy="216" rx="12" ry="12" fill="#4a90c8"/>
<circle cx="177" cy="215" r="8" fill="#1a2a3a"/>
<circle cx="180" cy="212" r="2.5" fill="white"/>
<circle cx="174" cy="219" r="1.5" fill="white" opacity="0.6"/>
<path d="M106 208 Q115 200 124 207" stroke="#3a2520" stroke-width="2.5" fill="none" stroke-linecap="round"/>
<path d="M157 207 Q165 200 174 208" stroke="#3a2520" stroke-width="2.5" fill="none" stroke-linecap="round"/>
<circle cx="125" cy="215" r="24" fill="none" stroke="#C8A020" stroke-width="5"/>
<circle cx="175" cy="215" r="24" fill="none" stroke="#C8A020" stroke-width="5"/>
<line x1="149" y1="215" x2="151" y2="215" stroke="#C8A020" stroke-width="5"/>
<line x1="102" y1="210" x2="87" y2="217" stroke="#C8A020" stroke-width="4" stroke-linecap="round"/>
<line x1="198" y1="210" x2="213" y2="217" stroke="#C8A020" stroke-width="4" stroke-linecap="round"/>
<circle cx="125" cy="215" r="20" fill="#ffd21f" opacity="0.04"/>
<circle cx="175" cy="215" r="20" fill="#ffd21f" opacity="0.04"/>
<ellipse cx="150" cy="240" rx="8" ry="6" fill="#dda88a"/>
<circle cx="146" cy="242" r="3" fill="#cc9878"/>
<circle cx="154" cy="242" r="3" fill="#cc9878"/>
<path d="M126 258 Q150 276 174 258" stroke="#c07060" stroke-width="3" fill="none" stroke-linecap="round"/>
<path d="M130 260 Q150 273 170 260" stroke="#e09080" stroke-width="1.5" fill="#f0a890" opacity="0.4"/>
<circle cx="124" cy="258" r="3" fill="#e09888"/>
<circle cx="176" cy="258" r="3" fill="#e09888"/>
<ellipse cx="150" cy="148" rx="40" ry="34" fill="#C8C8C8"/>
<ellipse cx="150" cy="145" rx="30" ry="26" fill="#D8D8D8"/>
<ellipse cx="143" cy="139" rx="12" ry="8" fill="white" opacity="0.3"/>
<path d="M83 215 Q88 165 115 155 Q100 200 102 230 Z" fill="#C0C0C0"/>
<path d="M217 215 Q212 165 185 155 Q200 200 198 230 Z" fill="#C0C0C0"/>
<path d="M95 195 Q105 188 115 195" stroke="#B0B0B0" stroke-width="2" fill="none" stroke-linecap="round"/>
<path d="M185 195 Q195 188 205 195" stroke="#B0B0B0" stroke-width="2" fill="none" stroke-linecap="round"/>
<path d="M120 153 Q150 138 180 153" stroke="#C8A020" stroke-width="3.5" fill="none" stroke-linecap="round"/>
<circle cx="150" cy="140" r="6" fill="#FFD21F"/>
<circle cx="135" cy="146" r="4" fill="#C8A020"/>
<circle cx="165" cy="146" r="4" fill="#C8A020"/>
<ellipse cx="83" cy="226" rx="7" ry="9" fill="none" stroke="#C8A020" stroke-width="3"/>
<ellipse cx="217" cy="226" rx="7" ry="9" fill="none" stroke="#C8A020" stroke-width="3"/>
<ellipse cx="83" cy="220" rx="10" ry="14" fill="#e8b080"/>
<ellipse cx="217" cy="220" rx="10" ry="14" fill="#e8b080"/>
</svg>"""

    # ==================================================================
    # WARNING SIGN SVG
    # ==================================================================
    WARNING_SVG = """<svg viewBox="0 0 100 90" xmlns="http://www.w3.org/2000/svg" width="70" class="warning-triangle">
<polygon points="50,5 95,82 5,82" fill="#FFD21F" stroke="#0A0A0A" stroke-width="2"/>
<polygon points="50,15 87,78 13,78" fill="#FFD21F"/>
<rect x="44" y="30" width="12" height="24" rx="4" fill="#0A0A0A"/>
<circle cx="50" cy="63" r="6" fill="#0A0A0A"/>
</svg>"""

    # ==================================================================
    # BUILD THE FULL INTERACTIVE PAGE AS ONE HTML DOCUMENT
    # ==================================================================
    safety_tips_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap');

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  background: #0A0A0A;
  color: #F5F5F5;
  -webkit-font-smoothing: antialiased;
  overflow-x: hidden;
}}

/* ===== HERO SECTION ===== */
.hero {{
  display: grid;
  grid-template-columns: 1.2fr 0.8fr;
  gap: 3rem;
  align-items: center;
  padding: 2.5rem 2rem 2rem 2rem;
  max-width: 1200px;
  margin: 0 auto;
}}
.hero-left {{}}
.hero-eyebrow {{
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #888;
  margin-bottom: 0.75rem;
}}
.hero-title {{
  font-size: clamp(2.2rem, 4.5vw, 3.4rem);
  font-weight: 900;
  line-height: 1.08;
  letter-spacing: -0.03em;
  color: #F5F5F5;
  margin-bottom: 1rem;
}}
.hero-title span {{ color: #FFD21F; }}
.hero-subtitle {{
  font-size: 1.05rem;
  color: #999;
  line-height: 1.6;
  max-width: 420px;
}}
.hero-right {{
  position: relative;
  display: flex;
  justify-content: center;
  align-items: flex-end;
  min-height: 340px;
}}

/* ===== GRANDPA ANIMATIONS ===== */
.grandpa-container {{
  position: relative;
  animation: grandpaEntrance 0.8s ease-out;
}}
@keyframes grandpaEntrance {{
  0% {{ opacity: 0; transform: translateY(20px); }}
  100% {{ opacity: 1; transform: translateY(0); }}
}}
.grandpa-container svg {{
  animation: grandpaIdle 4s ease-in-out infinite;
}}
@keyframes grandpaIdle {{
  0%, 100% {{ transform: translateY(0); }}
  50% {{ transform: translateY(-3px); }}
}}
.grandpa-hand {{
  animation: handWarn 2.5s ease-in-out infinite;
  transform-origin: 256px 255px;
}}
@keyframes handWarn {{
  0%, 55%, 100% {{ transform: rotate(0deg); }}
  60% {{ transform: rotate(-8deg); }}
  65% {{ transform: rotate(7deg); }}
  70% {{ transform: rotate(-7deg); }}
  75% {{ transform: rotate(6deg); }}
  80% {{ transform: rotate(-4deg); }}
  85% {{ transform: rotate(0deg); }}
}}
.grandpa-head {{
  animation: headShake 5s ease-in-out infinite;
  transform-origin: 160px 270px;
}}
@keyframes headShake {{
  0%, 75%, 100% {{ transform: rotate(0deg); }}
  78% {{ transform: rotate(-3.5deg); }}
  82% {{ transform: rotate(3.5deg); }}
  86% {{ transform: rotate(-2.5deg); }}
  90% {{ transform: rotate(2deg); }}
  94% {{ transform: rotate(0deg); }}
}}

/* Warning triangle pulse */
.warning-triangle {{
  animation: warnPulse 2.5s ease-in-out infinite;
  filter: drop-shadow(0 4px 20px rgba(255,210,31,0.3));
  cursor: pointer;
  transition: transform 0.2s ease;
}}
@keyframes warnPulse {{
  0%, 100% {{ filter: drop-shadow(0 4px 15px rgba(255,210,31,0.2)); }}
  50% {{ filter: drop-shadow(0 4px 28px rgba(255,210,31,0.5)); }}
}}
.warning-pos {{
  position: absolute;
  bottom: 12px;
  right: 8px;
}}
.warning-pos:hover .warning-triangle {{
  animation: warnShake 0.4s ease-in-out;
}}
@keyframes warnShake {{
  0%, 100% {{ transform: rotate(0); }}
  25% {{ transform: rotate(-5deg); }}
  75% {{ transform: rotate(5deg); }}
}}
.warning-tooltip {{
  display: none;
  position: absolute;
  bottom: 100%;
  right: 0;
  background: #1A1A1A;
  border: 1.5px solid #FFD21F;
  border-radius: 10px;
  padding: 0.6rem 0.9rem;
  font-size: 0.8rem;
  font-weight: 600;
  color: #FFD21F;
  white-space: nowrap;
  margin-bottom: 6px;
  z-index: 20;
}}
.warning-pos:hover .warning-tooltip {{
  display: block;
  animation: fadeIn 0.2s ease;
}}

/* Grandpa speech bubble — rotating messages */
.gp-bubble {{
  position: absolute;
  top: 6px;
  right: 0;
  background: #141414;
  border: 2px solid #FFD21F;
  border-radius: 14px 14px 4px 14px;
  padding: 0.55rem 1rem;
  z-index: 10;
  min-width: 180px;
  text-align: center;
}}
.gp-bubble::after {{
  content: '';
  position: absolute;
  bottom: -9px;
  right: 18px;
  border: 5px solid transparent;
  border-top-color: #FFD21F;
}}
.gp-bubble-text {{
  font-size: 0.82rem;
  font-weight: 800;
  color: #FFD21F;
  letter-spacing: 0.02em;
  transition: opacity 0.4s ease;
}}

/* ===== DIVIDER ===== */
.divider {{
  width: 100%;
  height: 1px;
  background: linear-gradient(90deg, transparent, #292929, transparent);
  margin: 2rem auto;
  max-width: 1200px;
}}

/* ===== GRANDPA WARNING SECTION ===== */
.warning-section {{
  display: grid;
  grid-template-columns: 0.75fr 1.25fr;
  gap: 3rem;
  align-items: center;
  padding: 2rem 2rem;
  max-width: 1200px;
  margin: 0 auto;
}}
.warning-char {{ text-align: center; }}
.warning-char-bubble {{
  margin-top: 0.8rem;
  background: #141414;
  border: 1.5px solid #FFD21F;
  border-radius: 12px 12px 4px 12px;
  padding: 0.6rem 0.9rem;
  text-align: center;
  max-width: 210px;
  margin-left: auto;
  margin-right: auto;
}}
.warning-char-bubble span {{
  font-size: 0.85rem;
  font-weight: 800;
  color: #FFD21F;
  font-style: italic;
}}
.warning-content h2 {{
  font-size: clamp(1.6rem, 3vw, 2.2rem);
  font-weight: 900;
  letter-spacing: -0.02em;
  color: #F5F5F5;
  margin-bottom: 0.3rem;
}}
.warning-content .quote {{
  font-size: clamp(1.2rem, 2.2vw, 1.6rem);
  font-weight: 800;
  color: #FFD21F;
  font-style: italic;
  margin-bottom: 1.25rem;
}}
.warning-content > p {{
  font-size: 1rem;
  color: #999;
  line-height: 1.6;
  margin-bottom: 1.25rem;
}}
.warn-card {{
  display: flex;
  align-items: flex-start;
  gap: 0.85rem;
  background: #131313;
  border: 1px solid rgba(255,210,31,0.15);
  border-radius: 12px;
  padding: 1rem 1.15rem;
  margin-bottom: 0.75rem;
  transition: border-color 0.25s ease, transform 0.2s ease;
}}
.warn-card:hover {{
  border-color: rgba(255,210,31,0.35);
  transform: translateY(-1px);
}}
.warn-card .icon {{ font-size: 1.4rem; flex-shrink: 0; padding-top: 2px; }}
.warn-card .text {{ font-size: 0.92rem; color: #ccc; line-height: 1.5; }}
.warn-card .text strong {{ color: #FFD21F; }}

/* ===== GRANDMA LESSON SECTION ===== */
.lesson-section {{
  display: grid;
  grid-template-columns: 1.3fr 0.7fr;
  gap: 3rem;
  align-items: start;
  padding: 2rem 2rem;
  max-width: 1200px;
  margin: 0 auto;
}}
.lesson-left h2 {{
  font-size: clamp(1.5rem, 3vw, 2.1rem);
  font-weight: 900;
  letter-spacing: -0.02em;
  color: #F5F5F5;
  margin-bottom: 0.3rem;
}}
.lesson-intro {{
  font-size: 1rem;
  color: #999;
  font-style: italic;
  margin-bottom: 1.5rem;
  line-height: 1.5;
}}

/* Progress dots */
.progress-bar {{
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
}}
.progress-dot {{
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #2A2A2A;
  border: 1.5px solid #444;
  transition: all 0.35s ease;
}}
.progress-dot.active {{
  background: #FFD21F;
  border-color: #FFD21F;
  box-shadow: 0 0 8px rgba(255,210,31,0.4);
}}
.progress-dot.done {{
  background: #555;
  border-color: #666;
}}
.progress-counter {{
  font-size: 0.75rem;
  font-weight: 700;
  color: #666;
  letter-spacing: 0.08em;
  margin-left: 0.5rem;
}}

/* Tip card — single active tip */
.tip-display {{
  position: relative;
  min-height: 180px;
}}
.tip-card {{
  background: #111;
  border: 1px solid #252525;
  border-radius: 16px;
  padding: 1.75rem 2rem;
  animation: tipEnter 0.45s ease-out;
  transition: border-color 0.25s ease;
}}
.tip-card:hover {{
  border-color: rgba(255,210,31,0.3);
}}
@keyframes tipEnter {{
  0% {{ opacity: 0; transform: translateX(30px); }}
  100% {{ opacity: 1; transform: translateX(0); }}
}}
.tip-number {{
  font-size: 0.75rem;
  font-weight: 900;
  color: #FFD21F;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  margin-bottom: 0.5rem;
}}
.tip-title {{
  font-size: 1.2rem;
  font-weight: 800;
  color: #F5F5F5;
  margin-bottom: 0.65rem;
  letter-spacing: -0.01em;
}}
.tip-desc {{
  font-size: 0.95rem;
  color: #999;
  line-height: 1.65;
}}

/* Nav buttons */
.tip-nav {{
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-top: 1.25rem;
}}
.tip-btn {{
  background: #151515;
  border: 1.5px solid #333;
  border-radius: 10px;
  padding: 0.6rem 1.3rem;
  font-family: 'Inter', sans-serif;
  font-size: 0.85rem;
  font-weight: 700;
  color: #ccc;
  cursor: pointer;
  transition: all 0.25s ease;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
}}
.tip-btn:hover {{
  border-color: #FFD21F;
  color: #FFD21F;
  transform: translateY(-1px);
}}
.tip-btn:hover .arrow {{
  transform: translateX(3px);
}}
.tip-btn .arrow {{
  transition: transform 0.2s ease;
  font-size: 0.9rem;
}}
.tip-btn.primary {{
  background: #FFD21F;
  border-color: #FFD21F;
  color: #0A0A0A;
}}
.tip-btn.primary:hover {{
  background: #ffe34d;
  color: #0A0A0A;
  transform: translateY(-1px);
}}

/* Completion state */
.tip-complete {{
  text-align: center;
  padding: 2rem;
  animation: tipEnter 0.5s ease-out;
}}
.tip-complete .emoji {{ font-size: 2rem; margin-bottom: 0.75rem; }}
.tip-complete h3 {{
  font-size: 1.1rem;
  font-weight: 800;
  color: #FFD21F;
  margin-bottom: 0.4rem;
}}
.tip-complete p {{ font-size: 0.95rem; color: #999; }}

/* ===== GRANDMA CHARACTER COLUMN ===== */
.grandma-col {{
  display: flex;
  flex-direction: column;
  align-items: center;
  padding-top: 1rem;
}}
.gm-bubble {{
  background: #141414;
  border: 1.5px solid #555;
  border-radius: 14px 14px 14px 4px;
  padding: 0.6rem 1rem;
  text-align: center;
  max-width: 220px;
  margin-bottom: 1rem;
  transition: opacity 0.4s ease;
}}
.gm-bubble-text {{
  font-size: 0.82rem;
  font-weight: 700;
  color: #ddd;
  font-style: italic;
  line-height: 1.45;
}}
.grandma-container {{
  animation: grandmaEntrance 0.8s ease-out 0.2s both;
}}
@keyframes grandmaEntrance {{
  0% {{ opacity: 0; transform: translateY(20px); }}
  100% {{ opacity: 1; transform: translateY(0); }}
}}
.grandma-container svg {{
  transition: transform 0.4s ease;
}}
.grandma-react {{
  animation: grandmaReact 0.6s ease-out;
}}
@keyframes grandmaReact {{
  0% {{ transform: scale(1); }}
  30% {{ transform: scale(1.02) rotate(-1deg); }}
  60% {{ transform: scale(1) rotate(0.5deg); }}
  100% {{ transform: scale(1) rotate(0); }}
}}
.grandma-wave {{
  animation: waveGesture 3.5s ease-in-out infinite;
  transform-origin: 232px 358px;
}}
@keyframes waveGesture {{
  0%, 70%, 100% {{ transform: rotate(0deg); }}
  75% {{ transform: rotate(-4deg); }}
  80% {{ transform: rotate(4deg); }}
  85% {{ transform: rotate(-2deg); }}
  90% {{ transform: rotate(0deg); }}
}}
.grandma-nod {{
  animation: grandmaNod 0.5s ease-in-out;
}}
@keyframes grandmaNod {{
  0%, 100% {{ transform: translateY(0); }}
  40% {{ transform: translateY(4px); }}
  70% {{ transform: translateY(-2px); }}
}}

/* ===== FINAL CTA ===== */
.final-cta {{
  text-align: center;
  padding: 3rem 2rem 2rem 2rem;
  max-width: 1200px;
  margin: 0 auto;
}}
.final-callout {{
  display: inline-flex;
  align-items: center;
  gap: 0.7rem;
  background: #131313;
  border: 1.5px solid rgba(255,210,31,0.2);
  border-radius: 50px;
  padding: 0.55rem 1.4rem;
  margin-bottom: 1.5rem;
}}
.final-callout .label {{
  font-size: 0.75rem;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #FFD21F;
}}
.final-callout .text {{
  font-size: 0.92rem;
  color: #ccc;
  font-weight: 600;
  font-style: italic;
}}
.final-cta h2 {{
  font-size: clamp(2rem, 4vw, 2.8rem);
  font-weight: 900;
  letter-spacing: -0.03em;
  color: #F5F5F5;
  margin-bottom: 0.4rem;
}}
.final-cta h2 span {{ color: #FFD21F; }}
.final-cta > p {{
  font-size: 1rem;
  color: #999;
  margin-bottom: 0;
}}
.footer {{
  text-align: center;
  padding: 2.5rem 1rem 1.5rem;
  font-size: 0.78rem;
  color: #555;
  letter-spacing: 0.03em;
}}

/* ===== GENERIC UTILITIES ===== */
@keyframes fadeIn {{
  0% {{ opacity: 0; }}
  100% {{ opacity: 1; }}
}}
@media (max-width: 800px) {{
  .hero, .warning-section, .lesson-section {{
    grid-template-columns: 1fr !important;
  }}
  .hero-right, .warning-char, .grandma-col {{
    order: -1;
  }}
}}
</style>
</head>
<body>

<!-- ==================== HERO SECTION ==================== -->
<div class="hero">
  <div class="hero-left">
    <div class="hero-eyebrow">SCAM AWARENESS</div>
    <h1 class="hero-title">SAFETY<br>STARTS WITH<br>A <span>SECOND LOOK.</span></h1>
    <p class="hero-subtitle">Scammers only need one click. Learn how to spot the warning signs before you open an unknown link.</p>
  </div>
  <div class="hero-right">
    <div class="gp-bubble">
      <div class="gp-bubble-text" id="gpBubbleText">ARE YOU BLIND?! DON'T CLICK THAT!</div>
    </div>
    <div class="grandpa-container">
      {GRANDPA_SVG}
    </div>
    <div class="warning-pos">
      <div class="warning-tooltip">Are you really about to click that? Check it first, genius.</div>
      {WARNING_SVG}
    </div>
  </div>
</div>

<div class="divider"></div>

<!-- ==================== GRANDPA WARNING SECTION ==================== -->
<div class="warning-section">
  <div class="warning-char">
    <div class="grandpa-container" style="transform:scale(0.85);">
      {GRANDPA_SVG}
    </div>
    <div class="warning-char-bubble">
      <span>"Think with your brain, not your mouse, kid!"</span>
    </div>
  </div>
  <div class="warning-content">
    <h2>GRANDPA'S SCATHING LECTURE:</h2>
    <div class="quote">"STOP BEING RECKLESS. LOOK FIRST."</div>
    <p>Grandpa has zero patience for stupid clicks. He's seen every trick in the book, and he's not about to watch you hand over your passwords and money just because you were too careless to inspect a URL.</p>
    <div class="warn-card">
      <div class="icon">&#9888;&#65039;</div>
      <div class="text"><strong>You only need to mess up once.</strong><br>One careless click and you've handed your life savings to some scammer in a basement. Wake up!</div>
    </div>
    <div class="warn-card">
      <div class="icon">&#128269;</div>
      <div class="text"><strong>The warning signs are screaming at you.</strong><br>Misspellings, bizarre subdomains, urgent countdowns &mdash; learn to read before you click!</div>
    </div>
    <div class="warn-card">
      <div class="icon">&#9208;&#65039;</div>
      <div class="text"><strong>Take five seconds to think.</strong><br>Is that emergency email really from your bank? No, it's not. Stop being gullible.</div>
    </div>
  </div>
</div>

<div class="divider"></div>

<!-- ==================== GRANDMA LESSON SECTION ==================== -->
<div class="lesson-section">
  <div class="lesson-left">
    <h2>GRANDMA'S SAFETY LESSON</h2>
    <div class="lesson-intro" id="lessonIntro">"Come here, dear. Let me show you how to stay safe online."</div>

    <div class="progress-bar" id="progressBar">
      <div class="progress-dot active" data-idx="0"></div>
      <div class="progress-dot" data-idx="1"></div>
      <div class="progress-dot" data-idx="2"></div>
      <div class="progress-dot" data-idx="3"></div>
      <div class="progress-dot" data-idx="4"></div>
      <div class="progress-dot" data-idx="5"></div>
      <span class="progress-counter" id="progressCounter">01 / 06</span>
    </div>

    <div class="tip-display" id="tipDisplay">
      <!-- Tips rendered dynamically by JS -->
    </div>

    <div class="tip-nav" id="tipNav">
      <button class="tip-btn" id="prevBtn" style="display:none;">
        <span class="arrow">&larr;</span> PREVIOUS
      </button>
      <button class="tip-btn primary" id="nextBtn">
        NEXT TIP <span class="arrow">&rarr;</span>
      </button>
    </div>
  </div>

  <div class="grandma-col">
    <div class="gm-bubble" id="gmBubble">
      <div class="gm-bubble-text" id="gmBubbleText">Look closely at that web address, dear.</div>
    </div>
    <div class="grandma-container" id="grandmaContainer">
      {GRANDMA_SVG}
    </div>
  </div>
</div>

<div class="divider"></div>

<!-- ==================== FINAL CTA ==================== -->
<div class="final-cta">
  <div class="final-callout">
    <span class="label">GRANDPA YELLS:</span>
    <span class="text">"DON'T MAKE ME REPEAT MYSELF. CHECK THE DAMN LINK!"</span>
  </div>
  <h2>CHECK BEFORE<br>YOU <span>CLICK.</span></h2>
  <p>CyberSentinel helps you decide in seconds. Paste any link and see what we find.</p>
</div>

<div class="footer">CyberSentinel &middot; Simple, private, instant link safety checks.</div>

<!-- ==================== JAVASCRIPT ==================== -->
<script>
(function() {{
  // ===== GRANDPA SPEECH BUBBLE ROTATION =====
  const gpMessages = [
    "ARE YOU BLIND?! DON'T CLICK THAT!",
    "DID YOU EVEN READ THE URL, GENIUS?!",
    "USE YOUR BRAIN BEFORE YOUR FINGER!",
    "STOP CLICKING LIKE AN AMATEUR!",
    "ONE DUMB CLICK AND YOU'RE SCREWED!",
    "WHAT PART OF 'SUSPICIOUS' DON'T YOU GET?!"
  ];
  let gpIdx = 0;
  const gpBubble = document.getElementById('gpBubbleText');

  setInterval(() => {{
    gpBubble.style.opacity = '0';
    setTimeout(() => {{
      gpIdx = (gpIdx + 1) % gpMessages.length;
      gpBubble.textContent = gpMessages[gpIdx];
      gpBubble.style.opacity = '1';
    }}, 400);
  }}, 4000);

  // ===== TIPS DATA =====
  const tips = [
    {{
      num: "01",
      title: "CHECK THE WEBSITE NAME",
      desc: "Scammers often use names that look almost like the real thing \\u2014 like paypa1.com instead of paypal.com. Always read the address carefully.",
      bubble: "Look closely at that web address, dear."
    }},
    {{
      num: "02",
      title: "DON\\u2019T TRUST URGENT MESSAGES",
      desc: "Messages telling you to \\u201Cact immediately\\u201D or \\u201Cyour account is suspended\\u201D are designed to panic you into clicking without thinking.",
      bubble: "Don\\u2019t let anyone rush you into clicking."
    }},
    {{
      num: "03",
      title: "BE CAREFUL WITH LOGIN LINKS",
      desc: "Before entering your password, make sure you are really on the website you intended to visit \\u2014 not a fake copy.",
      bubble: "Always check where you\\u2019re entering your password."
    }},
    {{
      num: "04",
      title: "DON\\u2019T SHARE SENSITIVE INFORMATION",
      desc: "Never enter your passwords, payment card details, or personal ID through an unfamiliar or unsolicited link.",
      bubble: "Your password belongs to you. Keep it private."
    }},
    {{
      num: "05",
      title: "WATCH FOR STRANGE WEB ADDRESSES",
      desc: "Long, confusing, or garbled web addresses deserve a closer look. Check the link before you open it.",
      bubble: "Strange-looking links deserve a second look."
    }},
    {{
      num: "06",
      title: "WHEN IN DOUBT, DON\\u2019T CLICK",
      desc: "If something feels even slightly off, stop. Trust your instincts and verify through an official app or phone number.",
      bubble: "If you\\u2019re unsure, simply don\\u2019t click."
    }}
  ];

  let currentTip = 0;
  const tipDisplay = document.getElementById('tipDisplay');
  const prevBtn = document.getElementById('prevBtn');
  const nextBtn = document.getElementById('nextBtn');
  const progressCounter = document.getElementById('progressCounter');
  const dots = document.querySelectorAll('.progress-dot');
  const gmBubbleText = document.getElementById('gmBubbleText');
  const grandmaContainer = document.getElementById('grandmaContainer');
  const lessonIntro = document.getElementById('lessonIntro');

  function padNum(n) {{ return String(n).padStart(2, '0'); }}

  function renderTip(idx, completed) {{
    if (completed) {{
      tipDisplay.innerHTML = `
        <div class="tip-complete">
          <div class="emoji">\\u2728</div>
          <h3>That's all, dear. Stay safe out there.</h3>
          <p>Grandma is proud of you for learning these tips!</p>
        </div>
      `;
      prevBtn.style.display = 'inline-flex';
      nextBtn.style.display = 'none';
      lessonIntro.textContent = '"You did so well, dear. Now you know what to look for."';
      gmBubbleText.textContent = "I'm so proud of you, dear!";

      // Grandma happy nod
      grandmaContainer.classList.remove('grandma-nod');
      void grandmaContainer.offsetWidth;
      grandmaContainer.classList.add('grandma-nod');
      return;
    }}

    const tip = tips[idx];
    tipDisplay.innerHTML = `
      <div class="tip-card" key="${{idx}}">
        <div class="tip-number">${{tip.num}}</div>
        <div class="tip-title">${{tip.title}}</div>
        <div class="tip-desc">${{tip.desc}}</div>
      </div>
    `;

    // Update progress
    progressCounter.textContent = padNum(idx + 1) + ' / 06';
    dots.forEach((dot, i) => {{
      dot.className = 'progress-dot';
      if (i < idx) dot.classList.add('done');
      if (i === idx) dot.classList.add('active');
    }});

    // Update navigation
    prevBtn.style.display = idx > 0 ? 'inline-flex' : 'none';
    nextBtn.innerHTML = idx < tips.length - 1
      ? 'NEXT TIP <span class="arrow">&rarr;</span>'
      : 'FINISH <span class="arrow">&#10003;</span>';
    nextBtn.style.display = 'inline-flex';

    // Update grandma speech bubble
    gmBubbleText.style.opacity = '0';
    setTimeout(() => {{
      gmBubbleText.textContent = tip.bubble;
      gmBubbleText.style.opacity = '1';
    }}, 250);

    // Grandma react animation
    grandmaContainer.classList.remove('grandma-react');
    void grandmaContainer.offsetWidth;
    grandmaContainer.classList.add('grandma-react');

    // Reset intro text
    lessonIntro.textContent = '"Come here, dear. Let me show you how to stay safe online."';
  }}

  // Initialize first tip
  renderTip(0, false);

  nextBtn.addEventListener('click', () => {{
    if (currentTip < tips.length - 1) {{
      currentTip++;
      renderTip(currentTip, false);
    }} else {{
      // Completed
      dots.forEach(dot => dot.classList.add('done'));
      dots.forEach(dot => dot.classList.remove('active'));
      progressCounter.textContent = '06 / 06';
      renderTip(currentTip, true);
    }}
  }});

  prevBtn.addEventListener('click', () => {{
    if (currentTip > 0) {{
      currentTip--;
      renderTip(currentTip, false);
    }}
  }});

}})();
</script>
</body>
</html>
"""

    components.html(safety_tips_html, height=2200, scrolling=False)


# ==============================================================================
# PAGE 3: HOME / SCANNER & RESULT PAGE
# ==============================================================================
else:
    # --------------------------------------------------------------------------
    # VIEW A: SHOW SCAN RESULT (If a link was checked)
    # --------------------------------------------------------------------------
    if st.session_state.scanned_result is not None:
        report = st.session_state.scanned_result
        checked_url = st.session_state.scanned_url

        # Back / New check action
        if st.button("← Check another link", key="btn_back_top"):
            st.session_state.scanned_result = None
            st.session_state.scanned_url = ""
            st.rerun()

        # 1. Link you checked card
        st.markdown(f"""
        <div class="url-checked-box">
            <div class="url-checked-label">LINK YOU CHECKED</div>
            <div class="url-checked-value">{checked_url}</div>
        </div>
        """, unsafe_allow_html=True)

        # Compute consumer Safety Score (0 - 100, where 100 is cleanest)
        risk = report.get("risk_score", 0.0)
        safety_score = max(0, min(100, int(round(100.0 - risk))))
        verdict = report.get("verdict", "")

        # 2. Result State Display
        if verdict == "Legitimate / Safe":
            # SAFE STATE
            st.markdown(f"""
            <div class="result-banner result-banner-safe">
                <div class="result-icon-badge">🛡️</div>
                <div class="result-heading-safe">THIS LINK LOOKS SAFE</div>
                <div class="result-explainer">We didn't find obvious warning signs in this web address.</div>
            </div>
            """, unsafe_allow_html=True)

            # Safety Score Card
            st.markdown(f"""
            <div class="score-container">
                <div class="score-header">
                    <span class="score-label">SAFETY SCORE</span>
                    <span><span class="score-num">{safety_score}</span><span class="score-max"> / 100</span></span>
                </div>
                <div class="score-track">
                    <div class="score-fill-safe" style="width: {safety_score}%;"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Why does it look safe?
            st.markdown('<div class="section-title">WHY DOES IT LOOK SAFE?</div>', unsafe_allow_html=True)

            safe_signals = [
                ("No suspicious symbols detected", "Does not contain misleading characters like '@' or hidden redirects."),
                ("Website address has a familiar structure", "The address follows recognized domain naming conventions."),
                ("Direct destination", "Not hidden behind a temporary link shortening service."),
                ("No deceptive hyphens or lookalike names", "Does not use deceptive hyphens to imitate another brand."),
                ("No obvious warning signs found", "The address structure appears standard and consistent.")
            ]

            for s_title, s_desc in safe_signals:
                st.markdown(f"""
                <div class="signal-item">
                    <div class="signal-title-safe">✓ {s_title}</div>
                    <div class="signal-desc">{s_desc}</div>
                </div>
                """, unsafe_allow_html=True)

            # Buttons
            st.write("")
            col_b1, col_b2 = st.columns([1, 1])
            with col_b1:
                if st.button("CHECK ANOTHER LINK", type="primary", key="safe_btn_another"):
                    st.session_state.scanned_result = None
                    st.session_state.scanned_url = ""
                    st.rerun()
            with col_b2:
                if st.button("LEARN HOW TO STAY SAFE", type="secondary", key="safe_btn_learn"):
                    navigate_to("safety_tips")
                    st.rerun()

        elif verdict == "Suspicious":
            # SUSPICIOUS STATE (CyberSentinel Yellow)
            st.markdown(f"""
            <div class="result-banner result-banner-suspicious">
                <div class="result-icon-badge">⚠️</div>
                <div class="result-heading-suspicious">BE CAREFUL</div>
                <div class="result-subheading">This link looks suspicious.</div>
                <div class="result-explainer">We found some warning signs in this web address. Check it carefully before opening it.</div>
            </div>
            """, unsafe_allow_html=True)

            # Safety Score Card
            st.markdown(f"""
            <div class="score-container">
                <div class="score-header">
                    <span class="score-label">SAFETY SCORE</span>
                    <span><span class="score-num">{safety_score}</span><span class="score-max"> / 100</span></span>
                </div>
                <div class="score-track">
                    <div class="score-fill-suspicious" style="width: {safety_score}%;"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Why are we warning you?
            st.markdown('<div class="section-title">WHY ARE WE WARNING YOU?</div>', unsafe_allow_html=True)

            red_flags = report.get("red_flags", [])
            if red_flags:
                for rf in red_flags:
                    item = humanize_threat_indicator(rf.get("indicator", ""), rf.get("description", ""))
                    st.markdown(f"""
                    <div class="signal-item">
                        <div class="signal-title-warn">⚠ {item['title']}</div>
                        <div class="signal-desc">{item['desc']}</div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="signal-item">
                    <div class="signal-title-warn">⚠ Unusual address characteristics</div>
                    <div class="signal-desc">Parts of this web address structure differ from standard legitimate websites.</div>
                </div>
                """, unsafe_allow_html=True)

            # Recommended Action
            st.markdown("""
            <div class="action-box">
                <div class="action-label">RECOMMENDED ACTION</div>
                <div class="action-text">Don't enter passwords, payment details, or personal information unless you are certain the website is genuine.</div>
            </div>
            """, unsafe_allow_html=True)

            # Buttons
            col_b1, col_b2 = st.columns([1, 1])
            with col_b1:
                if st.button("CHECK ANOTHER LINK", type="primary", key="susp_btn_another"):
                    st.session_state.scanned_result = None
                    st.session_state.scanned_url = ""
                    st.rerun()
            with col_b2:
                if st.button("LEARN HOW TO SPOT SUSPICIOUS LINKS", type="secondary", key="susp_btn_learn"):
                    navigate_to("safety_tips")
                    st.rerun()

        else:
            # DANGEROUS STATE (Restrained Red)
            st.markdown(f"""
            <div class="result-banner result-banner-dangerous">
                <div class="result-icon-badge">🚫</div>
                <div class="result-heading-dangerous">THIS LINK LOOKS DANGEROUS</div>
                <div class="result-explainer">We found several warning signs in this web address. We recommend not opening it.</div>
            </div>
            """, unsafe_allow_html=True)

            # Safety Score Card
            st.markdown(f"""
            <div class="score-container">
                <div class="score-header">
                    <span class="score-label">SAFETY SCORE</span>
                    <span><span class="score-num">{safety_score}</span><span class="score-max"> / 100</span></span>
                </div>
                <div class="score-track">
                    <div class="score-fill-dangerous" style="width: {safety_score}%;"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Why are we warning you?
            st.markdown('<div class="section-title">WHY ARE WE WARNING YOU?</div>', unsafe_allow_html=True)

            red_flags = report.get("red_flags", [])
            if red_flags:
                for rf in red_flags:
                    item = humanize_threat_indicator(rf.get("indicator", ""), rf.get("description", ""))
                    st.markdown(f"""
                    <div class="signal-item">
                        <div class="signal-title-warn" style="color: #F87171;">⚠ {item['title']}</div>
                        <div class="signal-desc">{item['desc']}</div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div class="signal-item">
                    <div class="signal-title-warn" style="color: #F87171;">⚠ High risk address patterns detected</div>
                    <div class="signal-desc">This web address matches structural techniques frequently used in phishing attacks.</div>
                </div>
                """, unsafe_allow_html=True)

            # Recommended Action (Strict: No proceed anyway)
            st.markdown("""
            <div class="action-box-dangerous">
                <div class="action-label" style="color: #F87171;">RECOMMENDED ACTION</div>
                <div class="action-text">Don't open this link or enter any personal information.</div>
            </div>
            """, unsafe_allow_html=True)

            # Buttons
            col_b1, col_b2 = st.columns([1, 1])
            with col_b1:
                if st.button("CHECK ANOTHER LINK", type="primary", key="dang_btn_another"):
                    st.session_state.scanned_result = None
                    st.session_state.scanned_url = ""
                    st.rerun()
            with col_b2:
                if st.button("LEARN HOW TO STAY SAFE", type="secondary", key="dang_btn_learn"):
                    navigate_to("safety_tips")
                    st.rerun()

        # Education footer
        st.markdown("""
        <div class="simple-footer">
            CyberSentinel inspects web address structure to help you make informed decisions.<br/>
            Always verify unfamiliar links before sharing personal data.
        </div>
        """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # VIEW B: HOME HERO & SEARCH INPUT (Default State)
    # --------------------------------------------------------------------------
    else:
        st.markdown('<div class="hero-title-main">DON\'T CLICK.</div>', unsafe_allow_html=True)
        st.markdown('<div class="hero-title-yellow">CHECK FIRST.</div>', unsafe_allow_html=True)
        st.markdown('<div class="hero-subhead">Is this link safe?</div>', unsafe_allow_html=True)
        st.markdown('<div class="hero-body">Check a link before you open it.</div>', unsafe_allow_html=True)

        # Show error message if any
        if st.session_state.error_message:
            st.markdown(f'<div class="error-banner">{st.session_state.error_message}</div>', unsafe_allow_html=True)

        # Search Form
        with st.form("check_link_form", clear_on_submit=False):
            url_input = st.text_input(
                label="Enter URL to check",
                value=st.session_state.input_url,
                placeholder="Paste a link here...",
                label_visibility="collapsed"
            )

            submit_clicked = st.form_submit_button("CHECK LINK", type="primary")

        st.markdown('<div class="input-helper">Don\'t click it yet. Check it first.</div>', unsafe_allow_html=True)

        if submit_clicked:
            run_url_check(url_input)
            st.rerun()

        # Quick Example Chips
        st.markdown('<div class="example-title">Try an example</div>', unsafe_allow_html=True)
        ex_col1, ex_col2, ex_col3 = st.columns(3)

        with ex_col1:
            if st.button("google.com", key="ex_google", use_container_width=True):
                st.session_state.input_url = "https://www.google.com"
                run_url_check("https://www.google.com")
                st.rerun()

        with ex_col2:
            if st.button("bit.ly/secure-account", key="ex_bitly", use_container_width=True):
                st.session_state.input_url = "https://bit.ly/secure-account"
                run_url_check("https://bit.ly/secure-account")
                st.rerun()

        with ex_col3:
            if st.button("paypal-security.com", key="ex_paypal", use_container_width=True):
                st.session_state.input_url = "http://paypal-security-update.com/verify"
                run_url_check("http://paypal-security-update.com/verify")
                st.rerun()

        # Simple Footer
        st.markdown("""
        <div class="simple-footer">
            CyberSentinel is designed to protect people from deceptive links.<br/>
            Simple, private, and instant.
        </div>
        """, unsafe_allow_html=True)
