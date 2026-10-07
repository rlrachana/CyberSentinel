# 🛡️ CyberSentinel — Phishing URL Detection System using Machine Learning

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn-F7931E.svg)](https://scikit-learn.org/)
[![Benchmark Accuracy](https://img.shields.io/badge/Benchmark%20Accuracy-97.42%25-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

> **University Hackathon Project:** CyberSentinel is an AI-powered cybersecurity defense platform that analyzes URLs in real time to detect phishing attacks, deceptive structures, and social engineering patterns before users can be compromised.

---

## 📌 Table of Contents
- [Problem Statement](#-problem-statement)
- [Key Features](#-key-features)
- [System Architecture & Dual-Model Design](#-system-architecture--dual-model-design)
- [Dataset Overview (UCI ID 327)](#-dataset-overview-uci-id-327)
- [Feature Engineering & Encodings](#-feature-engineering--encodings)
- [Machine Learning Benchmark & Comparison](#-machine-learning-benchmark--comparison)
- [Why Random Forest was Selected](#-why-random-forest-was-selected)
- [Crucial Distinction: Benchmark vs. Real-Time URL Analysis](#-crucial-distinction-benchmark-vs-real-time-url-analysis)
- [Installation & Setup](#-installation--setup)
- [Running Locally](#-running-locally)
- [Cloud Deployment (Streamlit Community Cloud)](#-cloud-deployment-streamlit-community-cloud)
- [Demo Workflow for Hackathon Judges](#-demo-workflow-for-hackathon-judges)
- [Chrome Browser Extension (Proof-of-Concept)](#-chrome-browser-extension-proof-of-concept)
- [Future Scope & Roadmap](#-future-scope--roadmap)
- [Engineering & Security Disclaimer](#-engineering--security-disclaimer)

---

## 🚨 Problem Statement
Phishing remains the primary vector for data breaches and ransomware, responsible for over **85% of initial organizational compromises**. Attackers continuously register lookalike domains, obfuscate destinations with URL shorteners, utilize raw IP hosts, and stack subdomains to trick mobile and desktop users.

Traditional static blacklists (such as Google Safe Browsing or PhishTank) suffer from **zero-hour lag**: new phishing domains stay active for an average of 4 to 8 hours before appearing on global blacklists. 

**CyberSentinel** addresses this gap by performing instant lexical, structural, and machine-learning threat scoring on the raw URL string itself—providing zero-latency defense before credentials can be harvested.

---

## 🌟 Key Features
- **Instant Real-Time URL Scanner**: Evaluates raw URLs safely without making external network connections to dangerous servers.
- **Explainable Threat Indicators ("Why?"):** Highlights detected red flags with severity classifications (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and plain-English threat breakdowns.
- **Dual-Model ML Architecture**: Separates the academic 30-feature benchmark from honest, static real-time URL analysis.
- **Calibrated Composite Risk Score (0–100%):** Merges Scikit-Learn Random Forest probabilistic confidence with rule-based threat floor heuristics.
- **Model Comparison Dashboard**: Visualizes Decision Tree vs. Random Forest side-by-side with full confusion matrices and Gini feature importances.
- **30-Feature Dataset Simulator**: Allows judges to test arbitrary UCI feature combinations against the full 97.42% benchmark classifier.
- **Educational Threat Cheat Sheet**: In-depth explanations of IP obfuscation, credential masking (`@`), homograph punycode attacks, and brand typosquatting.
- **Pre-packaged Chrome Extension PoC**: Unpacked Manifest V3 browser extension for live tab threat scanning.

---

## 🏗️ System Architecture & Dual-Model Design

```
Raw User URL
    │
    ▼
┌────────────────────────────────────────────────────────┐
│  src/feature_extraction.py                             │
│  - URL Parsing & Canonicalization                      │
│  - 10 UCI-Aligned Feature Encodings (-1, 0, +1)        │
│  - Lexical Telemetry (Entropy, Digits, Keywords, TLD)  │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌──────────────────────────┐   ┌──────────────────────────┐
│  ML Inference Engine     │   │  Heuristic Rule Engine   │
│  models/url_phishing.pkl │   │  - Critical Threat Floors│
│  (Random Forest: 74.81%) │   │  - Positive Damping      │
└────────────┬─────────────┘   └─────────────┬────────────┘
             │                               │
             └─────────────┬─────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│  src/predict.py                                        │
│  - Calibrated Composite Risk Score (0 - 100%)          │
│  - Verdict Classification (Safe / Suspicious / Phish)  │
│  - Structured Explainability Report                    │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│  app.py (Streamlit Dark Dashboard Interface)           │
│  - Live Telemetry & Gauges                             │
│  - Red & Green Flags                                   │
│  - Confusion Matrix & Benchmark Visualizations         │
└────────────────────────────────────────────────────────┘
```

---

## 📊 Dataset Overview (UCI ID 327)
CyberSentinel is trained on the **UCI Phishing Websites Dataset** (`ucimlrepo` dataset ID 327):
- **Total Samples:** 11,055 web instances
- **Total Features:** 30 engineered categorical attributes
- **Target Variable (`result`):**
  - `+1`: Legitimate (6,157 samples — 55.7%)
  - `-1`: Phishing (4,898 samples — 44.3%)
- **Data Split:** Stratified 80% Training (8,844 samples) and 20% Testing (2,211 samples) using `random_state=42`.
- **Missing Values:** Zero missing values across all features.

---

## ⚙️ Feature Engineering & Encodings

Features follow the exact ternary / binary encodings defined in the original UCI study:
- `+1`: Legitimate / Low Risk
- `0`: Suspicious / Ambiguous
- `-1`: Phishing / High Risk

### The 10 URL-Extractable Features:
| # | Feature Name | Encodings & Logic |
|---|---|---|
| 1 | `having_ip_address` | `-1` if IPv4, IPv6, or Hex IP in host; `+1` if hostname |
| 2 | `url_length` | `+1` if < 54 chars; `0` if 54–75 chars; `-1` if > 75 chars |
| 3 | `shortining_service` | `-1` if domain is `bit.ly`, `tinyurl`, `goo.gl`, etc.; `+1` otherwise |
| 4 | `having_at_symbol` | `-1` if `@` is in URL; `+1` otherwise |
| 5 | `double_slash_redirecting` | `-1` if `//` appears after character position 7; `+1` otherwise |
| 6 | `prefix_suffix` | `-1` if domain contains hyphen `-`; `+1` otherwise |
| 7 | `having_sub_domain` | `+1` if 1 dot; `0` if 2 dots; `-1` if > 2 dots |
| 8 | `port` | `+1` if standard 80/443; `-1` if abnormal open port explicitly specified |
| 9 | `https_token` | `-1` if `https` token appears in domain label; `+1` otherwise |
| 10 | `abnormal_url` | `+1` if standard host syntax; `-1` if malformed or missing hostname |

---

## 📈 Machine Learning Benchmark & Comparison

Trained on 8,844 samples, evaluated on 2,211 unseen test samples:

### A) 30-Feature Complete Benchmark
| Metric | Decision Tree | Random Forest (100 Trees) | Winner |
|---|---|---|---|
| **Accuracy** | 97.11% | **97.42%** | 🏆 **Random Forest (+0.31%)** |
| **Precision (Weighted)** | 97.11% | **97.43%** | 🏆 **Random Forest (+0.32%)** |
| **Recall (Weighted)** | 97.11% | **97.42%** | 🏆 **Random Forest (+0.31%)** |
| **F1 Score (Weighted)** | 97.10% | **97.42%** | 🏆 **Random Forest (+0.32%)** |
| **Phishing Precision** | 97.22% | **98.02%** | 🏆 **Random Forest (+0.80%)** |
| **Phishing Recall** | 96.22% | **96.12%** | Decision Tree |
| **Phishing F1** | 96.72% | **97.06%** | 🏆 **Random Forest (+0.34%)** |
| **Test Set Misclassifications** | 64 | **57** | 🏆 **Random Forest (-7 errors)** |

### B) URL-Only Real-Time Feature Model (10 Features)
| Metric | Decision Tree | Random Forest |
|---|---|---|
| **Accuracy** | 74.90% | **74.81%** |
| **Precision** | 75.05% | **77.26%** |
| **Recall** | 74.90% | **74.81%** |
| **F1 Score** | 74.89% | **74.82%** |

---

## 🧠 Why Random Forest was Selected
1. **Variance Reduction & Generalization:** Individual decision trees suffer from high variance and quickly overfit to specific depth thresholds. Random Forest trains 100 randomized bagged estimators, smoothing the decision boundaries.
2. **Superior Precision on Malicious URLs (98.02% vs 97.22%):** In cybersecurity applications, False Positives (blocking legitimate domains) degrade user trust. Random Forest achieves higher precision.
3. **Feature Resilience:** Random sub-sampling of features at each split prevents dominant features (`sslfinal_state`, `url_of_anchor`) from suppressing subtle structural indicators.

---

## ⚖️ Crucial Distinction: Benchmark vs. Real-Time URL Analysis
A common pitfall in phishing detection prototypes is falsely claiming a 30-feature academic model runs in real time on raw URLs. 

In reality, 20 of the 30 UCI features require **actively loading the web page or querying private third-party services**:
- `url_of_anchor`, `links_in_tags`, `sfh`, `iframe`: Requires downloading and executing HTML/JavaScript from a potentially dangerous server.
- `web_traffic`, `page_rank`: Requires querying commercial rank APIs (Alexa/SimilarWeb) that charge fees or are decommissioned.
- `age_of_domain`, `domain_registration_length`: Requires querying rate-limited WHOIS servers.

**CyberSentinel's Honest Engineering Approach:**
1. We preserve the full 30-feature benchmark in `models/phishing_model.pkl` to validate against state-of-the-art research benchmarks (97.42%).
2. For real-time user input, we train and deploy `models/url_phishing_model.pkl` strictly on features safely extractable from the URL string itself.
3. We augment the ML probability with deterministic threat heuristics (IP detection, keyword matching, entropy analysis, and punycode inspection) to deliver defense-in-depth risk scoring.

---

## 💻 Installation & Setup

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Git

### 1. Clone Repository
```bash
git clone https://github.com/your-username/CyberSentinel.git
cd CyberSentinel
```

### 2. Create Virtual Environment
```bash
# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Running Locally

### Step 1: Run Training Pipeline (Already Pre-trained)
To re-run the training pipeline and generate fresh models/metadata:
```bash
python src/train_model.py
```

### Step 2: Run Unit Tests
Verify that all 16 feature extraction and inference tests pass:
```bash
pytest tests/test_features.py -p no:cacheprovider -v
```

### Step 3: Launch Streamlit Web Application
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## ☁️ Cloud Deployment (Streamlit Community Cloud)

CyberSentinel is configured for zero-configuration deployment to [Streamlit Community Cloud](https://streamlit.io/cloud):

1. Push your repository to GitHub:
   ```bash
   git add .
   git commit -m "feat: complete CyberSentinel ML phishing detection platform"
   git push origin main
   ```
2. Log in to [share.streamlit.io](https://share.streamlit.io/).
3. Click **"New app"**.
4. Select your repository: `your-username/CyberSentinel`.
5. Set **Main file path** to: `app.py`.
6. Click **"Deploy!"**.
7. Streamlit Cloud automatically installs dependencies from `requirements.txt` and starts the app.

---

## 🎬 Demo Workflow for Hackathon Judges

When presenting to judges, follow this 3-minute sequence:

1. **The Hook:**
   - Open Tab 1: **"Real-Time URL Scanner"**.
   - Click the preset `🟢 Google (Legit)` button → show `Legitimate / Safe (0% Risk)` and green flags.
2. **The Threat Vectors:**
   - Click the preset `🔴 IP Address Host` button (`http://192.168.1.1/...`) → show instant escalation to `Phishing (72% Risk)` and explain the `[CRITICAL] Raw IP Address` indicator.
   - Click `🔴 Hyphen Spoof` (`paypal-security-update.com`) → show `Suspicious/Phishing` with brand spoofing and keyword flags.
3. **The ML Benchmark:**
   - Switch to Tab 2: **"ML Benchmark & Evaluation"**.
   - Show the **97.42% accuracy** metric card and side-by-side Confusion Matrices.
   - Explain the feature importance chart and detail why Random Forest was selected over Decision Tree.
4. **Engineering Honesty (Winning Edge):**
   - Explain the distinction between the 30-feature benchmark and the 10-feature static URL scanner. Judges respect teams that do not fake DOM-level features from URL strings.
5. **Interactive Simulator:**
   - Switch to Tab 3: **"30-Feature Dataset Simulator"** and flip SSL or Anchor tags to show how page-level features influence the ensemble.

---

## 🧩 Chrome Browser Extension (Proof-of-Concept)

Included in `extension/`:
1. Navigate to `chrome://extensions/` in Chrome or Brave.
2. Toggle on **Developer mode** in the top right.
3. Click **Load unpacked** and select `CyberSentinel/extension`.
4. Click the CyberSentinel icon in the toolbar on any active tab for live scanning.

---

## 🚀 Future Scope & Roadmap
- [ ] **WHOIS & RDAP Integration**: Query domain registration age asynchronously with background caching.
- [ ] **TLS Certificate Telemetry**: Query certificate issuer and validity dates via non-blocking SSL handshakes.
- [ ] **DNS Over HTTPS (DoH)**: Check DNS TXT, SPF, and MX record presence.
- [ ] **Transformer-based URL Embeddings**: Experiment with character-level CNNs and RoBERTa embeddings.
- [ ] **Telegram / Slack Bot**: Incident-response bot for employee link verification.

---

## ⚖️ Engineering & Security Disclaimer
CyberSentinel utilizes probabilistic machine learning models and structural heuristics. While highly effective at identifying common and evasive phishing patterns, **no machine learning system provides 100% detection guarantees**. Attackers continuously devise novel evasion techniques. Always inspect digital certificates and enforce multi-factor authentication.

---

## 👨‍💻 Team & Acknowledgments
Built with ❤️ for the University Hackathon.
- **Dataset:** UCI Machine Learning Repository (Phishing Websites Dataset ID: 327)
- **Libraries:** Scikit-Learn, Streamlit, Pandas, NumPy, Matplotlib, Seaborn, Pytest
