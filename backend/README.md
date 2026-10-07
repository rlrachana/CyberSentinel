# CyberSentinel Backend API

High-performance, decoupled link safety and phishing detection API powered by FastAPI, lexical URL feature extraction, and pre-trained Random Forest models.

## Architecture

- **Framework**: FastAPI (Asynchronous Python REST API)
- **Engine**: Static & lexical URL feature extraction (10 UCI-aligned features + 15 heuristic indicators)
- **Inference**: Cached scikit-learn Random Forest model (`models/url_phishing_model.pkl`)
- **Risk Evaluation**: Calibrated 0-100 composite risk calculation with threat-floor guarantees
- **Safety Policy**: Strictly static lexical analysis — the engine **never** visits, crawls, or opens suspicious destination URLs.

---

## Directory Structure

```
backend/
├── app.py                 # FastAPI application & lifecycle startup
├── api/
│   ├── __init__.py
│   └── routes.py          # /api/analyze endpoint & Pydantic models
├── core/
│   ├── __init__.py
│   ├── feature_extraction.py  # 10 UCI URL features extraction
│   ├── heuristics.py          # 15+ heuristic detection checks
│   ├── risk_scoring.py        # Composite risk & verdict thresholds
│   └── predict.py             # Model loading & inference pipeline
├── models/
│   ├── url_phishing_model.pkl # Trained URL Random Forest model
│   ├── phishing_model.pkl     # Benchmark 30-feature model
│   ├── dt_phishing_model.pkl  # Decision Tree model
│   └── metadata.json          # Training metrics & dataset metadata
├── tests/
│   ├── test_api.py            # Integration tests for REST endpoints
│   └── test_features.py       # Unit tests for feature extractors
├── requirements.txt       # Backend Python dependencies
├── .env.example           # Environment variables template
└── README.md
```

---

## Local Setup & Run

### 1. Install Dependencies

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Available environment variables:
- `HOST`: Host interface to bind (default: `0.0.0.0`)
- `PORT`: Port to listen on (default: `8000`)
- `ALLOWED_ORIGINS`: Comma-separated CORS allowed origins (default: `http://localhost:8501,http://127.0.0.1:8501`)

### 3. Start Backend API

```bash
uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```
Or when running from within `backend/`:
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

---

## API Endpoints

### 1. Health Check
`GET /health`
```json
{
  "status": "ok"
}
```

### 2. Analyze URL
`POST /api/analyze`

**Request Body**:
```json
{
  "url": "http://example.com/login"
}
```

**Response Body**:
```json
{
  "url": "http://example.com/login",
  "clean_url": "http://example.com/login",
  "domain": "example.com",
  "verdict": "Legitimate / Safe",
  "badge_color": "#10b981",
  "risk_level": "Low Risk",
  "summary": "This URL exhibits characteristics consistent with legitimate, reputable web domains.",
  "recommendation": "This link appears standard and safe to open under normal circumstances.",
  "risk_score": 5.0,
  "phishing_probability": 0.0412,
  "heuristic_score": 8.0,
  "confidence": 95.9,
  "ml_probabilities": {
    "phishing": 4.1,
    "legitimate": 95.9
  },
  "ml_raw_class": 1,
  "red_flags": [],
  "green_flags": [
    "Domain uses a registered hostname instead of an IP address.",
    "Compact URL length (24 characters).",
    "Direct destination URL (not using a known shortener)."
  ],
  "feature_table": [...],
  "metadata": {...},
  "uci_features": {...}
}
```

---

## Running Tests

```bash
pytest backend/tests
```
