"""
CyberSentinel Backend - FastAPI Application
Provides REST API endpoints for lexical phishing detection and link safety scoring.
"""

import os
from contextlib import asynccontextmanager
from typing import List
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load local environment variables if present
load_dotenv()

from backend.core.predict import preload_models
from backend.api.routes import router as api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Preload trained models and metadata into memory on startup."""
    try:
        preload_models()
        print("[CyberSentinel Backend] Models and metadata loaded into memory.")
    except Exception as e:
        print(f"[CyberSentinel Backend] WARNING: Model preload error: {e}")
    yield


app = FastAPI(
    title="CyberSentinel Link Safety API",
    description="Decoupled link inspection engine combining lexical feature extraction with Random Forest inference.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501")
if raw_origins.strip() == "*":
    allow_origins = ["*"]
else:
    allow_origins = [orig.strip() for orig in raw_origins.split(",") if orig.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True if allow_origins != ["*"] else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API endpoints
app.include_router(api_router)


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint for container orchestrators and status monitoring."""
    return {"status": "ok"}


@app.get("/", tags=["Info"])
async def root():
    """Service information root."""
    return {
        "service": "CyberSentinel Link Safety API",
        "status": "online",
        "docs_url": "/docs",
        "health_url": "/health",
        "analyze_endpoint": "/api/analyze"
    }


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("backend.app:app", host=host, port=port, reload=True)
