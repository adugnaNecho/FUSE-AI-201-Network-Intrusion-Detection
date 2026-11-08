"""FastAPI inference and authenticated live telemetry endpoints for Group 19 NIDS."""
from __future__ import annotations

import hmac
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from nids_core import DEFAULT_MODEL_PATH, FEATURE_COLUMNS, load_model, predict_records
from telemetry_store import get_live_stats, store_predictions, validate_source_id

app = FastAPI(
    title="Group 19 NSL-KDD NIDS API",
    version="1.1.0",
    description="Prototype inference and authenticated producer-submitted telemetry API.",
)
_model = None


def get_model():
    global _model
    if _model is None:
        _model = load_model(DEFAULT_MODEL_PATH)
    return _model


class PredictionRequest(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class TelemetryIngestRequest(BaseModel):
    source_id: str = Field(min_length=1, max_length=64)
    records: list[dict[str, Any]] = Field(min_length=1, max_length=100)


def require_telemetry_token(x_api_key: str = Header(default="", alias="X-API-Key")) -> None:
    expected = os.getenv("LIVE_INGEST_API_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Live telemetry is not configured on this API service.")
    if not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid telemetry API key.")


@app.get("/health")
def health():
    return {
        "status": "ready" if DEFAULT_MODEL_PATH.is_file() else "model_missing",
        "live_telemetry_configured": bool(os.getenv("LIVE_INGEST_API_TOKEN")),
    }


@app.get("/schema")
def schema():
    return {
        "required_features": FEATURE_COLUMNS,
        "feature_count": len(FEATURE_COLUMNS),
        "telemetry_ingest_max_records": 100,
        "telemetry_ingest_requires_api_key": True,
    }


@app.post("/predict")
def predict(request: PredictionRequest):
    try:
        results = predict_records(get_model(), request.records)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="The trained model is unavailable.") from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Prediction failed. Check server logs.") from exc
    return {"predictions": results.to_dict(orient="records")}


@app.post("/telemetry/ingest", status_code=202)
def ingest_telemetry(request: TelemetryIngestRequest, _auth: None = Depends(require_telemetry_token)):
    """Classify up to 100 external feature records; persist prediction summaries only."""
    try:
        source_id = validate_source_id(request.source_id)
        predictions = predict_records(get_model(), request.records)
        count = store_predictions(predictions.to_dict(orient="records"), source_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="The trained model is unavailable on the telemetry API.") from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Telemetry ingestion failed. Check server logs.") from exc

    counts = predictions["predicted_class"].value_counts().to_dict()
    return {
        "accepted": count,
        "source_id": source_id,
        "received_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "predicted_class_counts": {
            name: int(counts.get(name, 0)) for name in ("Normal", "DoS", "Probe", "U2R", "R2L")
        },
        "raw_features_stored": False,
    }


@app.get("/telemetry/stats")
def telemetry_stats(
    window_hours: int = Query(default=24, ge=1, le=720),
    _auth: None = Depends(require_telemetry_token),
):
    try:
        return get_live_stats(window_hours=window_hours)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Telemetry statistics are temporarily unavailable.") from exc
