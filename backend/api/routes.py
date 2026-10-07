"""
CyberSentinel Backend - API Routes
Defines REST endpoints for link security inspection.
"""

from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.core.predict import predict_url

router = APIRouter(prefix="/api", tags=["Analysis"])


class AnalyzeRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="The raw web address / URL to analyze (strictly lexical inspection)",
        examples=["https://example.com/login"]
    )


class ThreatIndicator(BaseModel):
    indicator: str
    severity: str
    description: str


class FeatureTableEntry(BaseModel):
    Feature: str
    RawValue: int = Field(alias="Raw Value")
    Status: str
    Description: str
    StatusColor: str

    model_config = {"populate_by_name": True}


class MLProbabilities(BaseModel):
    phishing: float
    legitimate: float


class AnalyzeResponse(BaseModel):
    url: str
    clean_url: str
    domain: str
    verdict: str
    badge_color: str
    risk_level: str
    summary: str
    recommendation: str
    risk_score: float
    phishing_probability: float
    heuristic_score: float
    confidence: float
    ml_probabilities: MLProbabilities
    ml_raw_class: int
    red_flags: List[ThreatIndicator]
    green_flags: List[str]
    feature_table: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    uci_features: Dict[str, int]


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze URL Safety",
    description="Analyzes URL lexical and structural patterns without fetching or visiting the destination."
)
async def analyze_url(payload: AnalyzeRequest):
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL cannot be empty."
        )

    # Basic validity sanity checks without requesting network resources
    if len(raw_url) < 3 or (" " in raw_url and not raw_url.startswith("http")):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Input does not appear to be a valid URL format."
        )

    try:
        report = predict_url(raw_url)
        return report
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )
