from __future__ import annotations

from fastapi import FastAPI, HTTPException

from inference import build_service
from models import HealthResponse, PredictionRequest, PredictionResponse


app = FastAPI(
    title="SENTRYX Security API",
    version="1.0.0",
    description="Minimal Hugging Face Docker Space for AI prompt security screening.",
)

service = build_service()


@app.get("/", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="sentryx-security-api")


@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest) -> PredictionResponse:
    prompt = request.prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="prompt must not be empty")
    return service.predict(prompt)
