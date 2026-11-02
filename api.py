"""Optional FastAPI endpoint for the Group 19 NIDS model."""
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from nids_core import DEFAULT_MODEL_PATH, FEATURE_COLUMNS, load_model, predict_records

app = FastAPI(
    title="Group 19 NSL-KDD NIDS API",
    version="1.0.0",
    description="Prototype inference API for NSL-KDD-style connection records.",
)

_model = None


def get_model():
    global _model
    if _model is None:
        _model = load_model(DEFAULT_MODEL_PATH)
    return _model


class PredictionRequest(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


@app.get("/health")
def health():
    return {
        "status": "ready" if DEFAULT_MODEL_PATH.is_file() else "model_missing",
        "model_path": str(DEFAULT_MODEL_PATH),
    }


@app.get("/schema")
def schema():
    return {"required_features": FEATURE_COLUMNS, "feature_count": len(FEATURE_COLUMNS)}


@app.post("/predict")
def predict(request: PredictionRequest):
    try:
        results = predict_records(get_model(), request.records)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        # Do not return internal file paths, model internals, or raw traceback to clients.
        raise HTTPException(status_code=500, detail="Prediction failed. Check server logs.") from exc
    return {"predictions": results.to_dict(orient="records")}
