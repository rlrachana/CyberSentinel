# CyberSentinel Frontend

Modern, consumer-friendly link safety inspector built with Streamlit.

The frontend contains **only** presentation and UI logic. It does **not** load machine learning models, execute inference, or evaluate heuristic rules locally. All inspection requests are dispatched via HTTP REST API to the independent CyberSentinel Backend.

---

## Directory Structure

```
frontend/
├── app.py                 # Streamlit UI & user interaction controller
├── components/            # Reusable UI component modules
├── assets/                # Visual assets & static resources
├── requirements.txt       # Frontend dependencies (Streamlit, Requests)
├── .env.example           # Environment variables template
└── README.md
```

---

## Configuration

Set the `BACKEND_URL` environment variable to point to your deployed or local backend API:

```bash
cp .env.example .env
```

`.env`:
```ini
BACKEND_URL=http://localhost:8000
```

In production, set `BACKEND_URL` to your live backend endpoint (e.g., `https://cybersentinel-api.onrender.com`).

---

## Local Setup & Run

### 1. Install Dependencies

```bash
cd frontend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start Frontend

```bash
streamlit run app.py --server.port 8501
```

Access the frontend in your browser at `http://localhost:8501`.
