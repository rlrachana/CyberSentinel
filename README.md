# CyberSentinel — Link Safety Inspector

CyberSentinel is an end-to-end link safety inspection platform that detects phishing and deceptive websites using lexical URL feature extraction, an explainable heuristic rules engine, and a trained scikit-learn Random Forest classifier.

The system is partitioned into a **two-tier, decoupled architecture**:
1. **Backend API (`/backend`)**: Asynchronous FastAPI service containing all feature extraction, heuristic evaluations, model inference, risk scoring, and verdict generation.
2. **Frontend UI (`/frontend`)**: Streamlit application providing the consumer interface. Contains zero ML or heuristic logic; communicates strictly via REST API.

---

## Architecture Overview

```
USER
  │
  ▼
STREAMLIT FRONTEND (Port 8501)
  │
  │ HTTP POST /api/analyze {"url": "..."}
  ▼
FASTAPI BACKEND API (Port 8000)
  ├── Pre-loaded Random Forest Classifier (`models/url_phishing_model.pkl`)
  ├── 10 UCI-Aligned Numerical URL Features
  ├── 15+ Heuristic Rules & Threat Vector Checks
  ├── Calibrated Composite Risk Scoring (50% ML + 50% Heuristics + Threat Floors)
  └── Verdict Classifier (Safe / Suspicious / Phishing)
  │
  ▼ JSON Response
STREAMLIT FRONTEND
  │
  ▼
Consumer Safety Report & Plain-English Explanations
```

> **Security Guarantee**: The backend performs strictly static, lexical URL inspection. It **never** visits, downloads, opens, or crawls submitted links.

---

## Directory Structure

```
CyberSentinel/
├── backend/
│   ├── app.py                     # FastAPI application & startup lifecycle
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py              # POST /api/analyze & Pydantic schemas
│   ├── core/
│   │   ├── __init__.py
│   │   ├── feature_extraction.py  # 10 UCI feature extractors
│   │   ├── heuristics.py          # 15+ security heuristic indicators
│   │   ├── risk_scoring.py        # Composite risk calculation & thresholds
│   │   └── predict.py             # Model loading & inference pipeline
│   ├── models/
│   │   ├── url_phishing_model.pkl # Trained URL Random Forest model
│   │   ├── phishing_model.pkl     # Benchmark 30-feature model
│   │   ├── dt_phishing_model.pkl  # Decision Tree model
│   │   └── metadata.json          # Model metadata & evaluation metrics
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_api.py            # API integration tests
│   │   └── test_features.py       # Unit tests for feature extraction
│   ├── requirements.txt           # Backend dependencies
│   ├── .env.example               # Backend environment variables template
│   └── README.md
│
├── frontend/
│   ├── app.py                     # Streamlit consumer interface
│   ├── components/                # Reusable UI presentation components
│   ├── assets/                    # Graphic assets
│   ├── requirements.txt           # Frontend dependencies (Streamlit, Requests)
│   ├── .env.example               # Frontend environment variables template
│   └── README.md
│
├── README.md                      # Project architecture & setup documentation
└── .gitignore
```

---

## Quickstart: Local Development

The system runs as two independent processes.

### Prerequisites

- Python 3.10+ (tested on Python 3.11)

### 1. Backend Setup & Run

Open **Terminal 1**:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

# Start FastAPI on port 8000
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Verify backend health:
```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

### 2. Frontend Setup & Run

Open **Terminal 2**:

```bash
cd frontend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

# Verify BACKEND_URL in frontend/.env points to http://localhost:8000
streamlit run app.py --server.port 8501
```

Access the frontend at: `http://localhost:8501`

---

## Running Automated Tests

Run the backend test suite:

```bash
pytest backend/tests
```

All 22 unit and integration tests validate:
- URL protocol standardization
- Shannon entropy calculations
- IP address detection, shortening services, `@` credential masking, double slashes, and punycode detection
- Pre-trained `.pkl` model deserialization
- `/health` endpoint and `/api/analyze` response contracts
- Safe, Suspicious, and Phishing classification thresholds

---

## Deployment Guide (Two Independent Deployments)

To obtain **TWO separate public URLs**, deploy backend and frontend independently.

### Option A: Render / Railway / Fly.io (Backend) + Streamlit Community Cloud (Frontend)

#### 1. Backend Deployment (e.g., Render)
- **Service Type**: Web Service
- **Root Directory**: `backend`
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn app:app --host 0.0.0.0 --port $PORT`
- **Environment Variables**:
  - `ALLOWED_ORIGINS`: `https://<YOUR-FRONTEND-SUBDOMAIN>.streamlit.app`
- **Backend Public URL**: `https://<YOUR-BACKEND-APP>.onrender.com`

#### 2. Frontend Deployment (Streamlit Community Cloud)
- **Repository**: Your GitHub repository
- **Main file path**: `frontend/app.py`
- **Environment Variables (Secrets)**:
  ```toml
  BACKEND_URL = "https://<YOUR-BACKEND-APP>.onrender.com"
  ```
- **Frontend Public URL**: `https://<YOUR-FRONTEND-SUBDOMAIN>.streamlit.app`

---

## API Reference

### `GET /health`
Returns service availability status.

### `POST /api/analyze`
Submits a URL for lexical link safety assessment.

#### Request
```json
{
  "url": "http://192.168.1.1/login-account-update"
}
```

#### Response
```json
{
  "url": "http://192.168.1.1/login-account-update",
  "clean_url": "http://192.168.1.1/login-account-update",
  "domain": "192.168.1.1",
  "verdict": "Phishing",
  "badge_color": "#ef4444",
  "risk_level": "High Risk",
  "summary": "This URL matches known phishing heuristics and malicious structural profiles. Do NOT enter credentials or download files.",
  "recommendation": "Don't open this link or enter any personal information.",
  "risk_score": 72.0,
  "phishing_probability": 0.88,
  "heuristic_score": 38.0,
  "confidence": 88.0,
  "ml_probabilities": {
    "phishing": 88.0,
    "legitimate": 12.0
  },
  "ml_raw_class": -1,
  "red_flags": [
    {
      "indicator": "Raw IP Address Host",
      "severity": "CRITICAL",
      "description": "The URL uses a raw IP address (192.168.1.1) instead of a trusted domain name to bypass domain reputation checks."
    }
  ],
  "green_flags": [],
  "feature_table": [...],
  "metadata": {...},
  "uci_features": {...}
}
```