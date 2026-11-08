"""Validated, fail-closed inference adapter for a trained Windows-specific model."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from windows_nids.schema import FEATURE_COLUMNS, SCHEMA_VERSION, validate_snapshot

DEFAULT_WINDOWS_MODEL_PATH = Path("artifacts/windows_nids_model.joblib")
DEFAULT_WINDOWS_METADATA_PATH = Path("artifacts/windows_nids_model.json")


@dataclass
class WindowsModelBundle:
    model: Any
    model_version: str
    classes: list[str]
    severity_mapping: dict[str, str]
    window_seconds: int = 60


def _estimator_classes(model: Any) -> list[str]:
    estimator = model
    if hasattr(model, "named_steps"):
        estimator = list(model.named_steps.values())[-1]
    raw = getattr(estimator, "classes_", None)
    if raw is None:
        raise ValueError("Windows model must expose classes_ after fitting.")
    return [str(value) for value in raw]


def load_windows_model(
    model_path: str | Path | None = None,
    metadata_path: str | Path | None = None,
) -> WindowsModelBundle:
    """Load a trusted model only when its metadata matches the feature contract."""
    model_path = Path(model_path or os.getenv("WINDOWS_MODEL_PATH", DEFAULT_WINDOWS_MODEL_PATH))
    metadata_path = Path(metadata_path or os.getenv("WINDOWS_MODEL_METADATA_PATH", DEFAULT_WINDOWS_METADATA_PATH))
    if not model_path.is_file():
        raise FileNotFoundError(f"Windows model is not installed: {model_path}")
    if not metadata_path.is_file():
        raise FileNotFoundError(f"Windows model metadata is not installed: {metadata_path}")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Windows model metadata is unreadable or invalid JSON.") from exc
    if metadata.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"Model metadata schema_version must be '{SCHEMA_VERSION}'.")
    if metadata.get("feature_columns") != FEATURE_COLUMNS:
        raise ValueError("Windows model feature_columns do not match the current feature schema.")
    try:
        window_seconds = int(metadata.get("window_seconds", 60))
    except (TypeError, ValueError) as exc:
        raise ValueError("Model metadata window_seconds must be a positive integer.") from exc
    if window_seconds <= 0:
        raise ValueError("Model metadata window_seconds must be a positive integer.")
    classes = metadata.get("classes")
    if not isinstance(classes, list) or len(classes) < 2 or not all(isinstance(v, str) and v for v in classes):
        raise ValueError("Model metadata must declare at least two string class labels.")
    if len(set(classes)) != len(classes):
        raise ValueError("Model metadata contains duplicate class labels.")
    expected_hash = metadata.get("model_sha256")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        raise ValueError("Model metadata must declare the artifact SHA-256 checksum.")
    digest = hashlib.sha256()
    with model_path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest().lower() != expected_hash.lower():
        raise ValueError("Windows model artifact SHA-256 does not match its metadata.")
    try:
        model = joblib.load(model_path)
    except Exception as exc:
        raise ValueError("Windows model artifact could not be loaded.") from exc
    if not callable(getattr(model, "predict", None)) or not callable(getattr(model, "predict_proba", None)):
        raise ValueError("Windows model must implement predict() and predict_proba().")
    actual_classes = _estimator_classes(model)
    if actual_classes != classes:
        raise ValueError(f"Model classes {actual_classes!r} do not match metadata classes {classes!r}.")
    severity_mapping = metadata.get("severity_mapping", {})
    if not isinstance(severity_mapping, dict):
        raise ValueError("severity_mapping must be a JSON object.")
    return WindowsModelBundle(
        model=model,
        model_version=str(metadata.get("model_version", "unversioned")),
        classes=classes,
        severity_mapping={str(k): str(v) for k, v in severity_mapping.items()},
        window_seconds=window_seconds,
    )


def predict_snapshots(bundle: WindowsModelBundle, snapshots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Classify validated snapshots. Maximum class probability is not calibrated."""
    if not snapshots:
        return []
    validated = [validate_snapshot(item) for item in snapshots]
    wrong_windows = sorted({item["window_seconds"] for item in validated if item["window_seconds"] != bundle.window_seconds})
    if wrong_windows:
        raise ValueError(
            f"Snapshot window_seconds {wrong_windows} does not match the model's "
            f"{bundle.window_seconds}-second training window."
        )
    ids = [item["snapshot_id"] for item in validated]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate snapshot_id values in one inference batch.")
    frame = pd.DataFrame([item["features"] for item in validated], columns=FEATURE_COLUMNS)
    predicted = bundle.model.predict(frame)
    probabilities = bundle.model.predict_proba(frame)
    if len(predicted) != len(validated) or probabilities.shape != (len(validated), len(bundle.classes)):
        raise ValueError("Model returned an unexpected prediction/probability shape.")
    results = []
    for index, snapshot in enumerate(validated):
        label = str(predicted[index])
        if label not in bundle.classes:
            raise ValueError(f"Model produced undeclared class label: {label}")
        row_probabilities = {
            name: float(probabilities[index, class_index])
            for class_index, name in enumerate(bundle.classes)
        }
        results.append({
            "snapshot_id": snapshot["snapshot_id"],
            "source_id": snapshot["source_id"],
            "window_end_utc": snapshot["window_end_utc"],
            "process_name": snapshot["process_name"],
            "process_instance_id": snapshot["process_instance_id"],
            "predicted_class": label,
            "confidence": max(row_probabilities.values()),
            "severity": bundle.severity_mapping.get(label, "Review"),
            "class_probabilities": row_probabilities,
            "model_version": bundle.model_version,
            "ground_truth_available": False,
        })
    return results
