"""Local dashboard helpers for Windows endpoint prediction JSONL streams."""
from __future__ import annotations

from collections import deque
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from windows_nids.schema import FEATURE_COLUMNS, SCHEMA_VERSION, parse_utc


PREDICTION_REQUIRED_FIELDS = (
    "snapshot_id",
    "source_id",
    "window_end_utc",
    "process_name",
    "predicted_class",
    "confidence",
    "severity",
    "class_probabilities",
    "model_version",
)


def _validated_prediction(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError("Prediction line must contain a JSON object.")
    missing = [key for key in PREDICTION_REQUIRED_FIELDS if key not in record]
    if missing:
        raise ValueError(f"Missing prediction field(s): {', '.join(missing)}")

    for key in ("snapshot_id", "source_id", "process_name", "predicted_class", "severity", "model_version"):
        if not isinstance(record[key], str) or not record[key].strip():
            raise ValueError(f"{key} must be a non-empty string.")

    timestamp = parse_utc(record["window_end_utc"])
    try:
        confidence = float(record["confidence"])
    except (TypeError, ValueError) as exc:
        raise ValueError("confidence must be numeric.") from exc
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1.")

    raw_probabilities = record["class_probabilities"]
    if not isinstance(raw_probabilities, dict) or not raw_probabilities:
        raise ValueError("class_probabilities must be a non-empty object.")
    probabilities: dict[str, float] = {}
    for label, value in raw_probabilities.items():
        if not isinstance(label, str) or not label:
            raise ValueError("Probability class names must be non-empty strings.")
        try:
            probability = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Probability for {label!r} must be numeric.") from exc
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise ValueError(f"Probability for {label!r} must be between 0 and 1.")
        probabilities[label] = probability
    if record["predicted_class"] not in probabilities:
        raise ValueError("predicted_class must be present in class_probabilities.")

    return {
        **record,
        "window_end_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "confidence": confidence,
        "class_probabilities": probabilities,
    }


def read_prediction_stream(path: str | Path, limit: int = 5000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read and validate the most recent JSONL prediction records with bounded memory."""
    if limit < 1:
        raise ValueError("limit must be at least 1.")
    source = Path(path)
    diagnostics: dict[str, Any] = {
        "path": str(source),
        "exists": source.is_file(),
        "lines_seen": 0,
        "valid_records": 0,
        "malformed_lines": 0,
        "skipped_records": 0,
        "records_limited": False,
    }
    if not source.is_file():
        return [], diagnostics

    tail: deque[str] = deque(maxlen=limit)
    try:
        with source.open("r", encoding="utf-8-sig") as handle:
            for line in handle:
                diagnostics["lines_seen"] += 1
                tail.append(line)
    except OSError as exc:
        diagnostics["read_error"] = str(exc)
        return [], diagnostics

    diagnostics["records_limited"] = diagnostics["lines_seen"] > limit
    records: list[dict[str, Any]] = []
    for line in tail:
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            diagnostics["malformed_lines"] += 1
            continue
        try:
            records.append(_validated_prediction(parsed))
        except (TypeError, ValueError):
            diagnostics["skipped_records"] += 1

    records.sort(key=lambda item: item["window_end_utc"])
    diagnostics["valid_records"] = len(records)
    return records, diagnostics


def inspect_windows_model(model_path: str | Path, metadata_path: str | Path) -> dict[str, Any]:
    """Check model files, schema metadata and artifact checksum without unpickling."""
    artifact = Path(model_path)
    metadata_file = Path(metadata_path)
    result: dict[str, Any] = {
        "available": False,
        "model_path": str(artifact),
        "metadata_path": str(metadata_file),
        "model_version": None,
        "classes": [],
        "window_seconds": None,
        "message": "",
    }
    if not artifact.is_file():
        result["message"] = f"Windows model artifact is missing: {artifact}"
        return result
    if not metadata_file.is_file():
        result["message"] = f"Windows model metadata is missing: {metadata_file}"
        return result

    try:
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result["message"] = "Windows model metadata is unreadable or invalid JSON."
        return result

    if not isinstance(metadata, dict):
        result["message"] = "Windows model metadata must be a JSON object."
        return result
    if metadata.get("schema_version") != SCHEMA_VERSION:
        result["message"] = f"Model schema must be {SCHEMA_VERSION}."
        return result
    if metadata.get("feature_columns") != FEATURE_COLUMNS:
        result["message"] = "Model feature order does not match the current Windows schema."
        return result
    classes = metadata.get("classes")
    if not isinstance(classes, list) or len(classes) < 2 or not all(isinstance(item, str) and item for item in classes):
        result["message"] = "Model metadata must contain at least two class labels."
        return result
    try:
        window_seconds = int(metadata.get("window_seconds"))
    except (TypeError, ValueError):
        result["message"] = "Model metadata has no valid window_seconds value."
        return result
    if window_seconds < 1:
        result["message"] = "Model metadata window_seconds must be positive."
        return result

    expected_hash = metadata.get("model_sha256")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        result["message"] = "Model metadata has no valid SHA-256 checksum."
        return result
    digest = hashlib.sha256()
    try:
        with artifact.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        result["message"] = f"Could not read Windows model artifact: {exc}"
        return result
    if digest.hexdigest().lower() != expected_hash.lower():
        result["message"] = "Windows model SHA-256 does not match its metadata."
        return result

    result.update({
        "available": True,
        "model_version": str(metadata.get("model_version", "unversioned")),
        "classes": classes,
        "window_seconds": window_seconds,
        "message": "Model artifact checksum and feature metadata are consistent. The inference runner performs the full estimator validation when it starts.",
    })
    return result
