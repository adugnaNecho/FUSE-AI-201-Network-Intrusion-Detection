"""Shared schema, validation, and inference helpers for Group 19's NSL-KDD NIDS."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib

import joblib
import pandas as pd

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERIC_FEATURES = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_FEATURES]
CLASS_NAMES = ["Normal", "DoS", "Probe", "U2R", "R2L"]
ID_TO_LABEL = {i: label for i, label in enumerate(CLASS_NAMES)}
LABEL_TO_ID = {label: i for i, label in ID_TO_LABEL.items()}
SEVERITY = {
    "Normal": "Low",
    "Probe": "Medium",
    "DoS": "High",
    "R2L": "High",
    "U2R": "Critical",
}

DEFAULT_MODEL_PATH = Path("artifacts/group19_final_nids_random_forest_pipeline.joblib")
OPTIONAL_NON_FEATURE_COLUMNS = {"class", "target", "target_id", "difficulty_level"}


def prepare_features(records: pd.DataFrame | list[dict[str, Any]]) -> pd.DataFrame:
    """Validate user-supplied connection records and return features in model order.

    Known target/metadata columns are removed. Missing required features, unexpected
    columns, non-numeric values in numeric fields, and empty inputs are rejected.
    Missing cells are left as NaN so the fitted pipeline's imputers can handle them.
    """
    if isinstance(records, pd.DataFrame):
        frame = records.copy()
    else:
        if not records:
            raise ValueError("Provide at least one connection record.")
        frame = pd.DataFrame(records)

    if frame.empty:
        raise ValueError("The input contains no records.")

    frame.columns = [str(c).strip() for c in frame.columns]
    frame = frame.drop(columns=[c for c in OPTIONAL_NON_FEATURE_COLUMNS if c in frame.columns], errors="ignore")

    missing = [c for c in FEATURE_COLUMNS if c not in frame.columns]
    extra = [c for c in frame.columns if c not in FEATURE_COLUMNS]
    if missing:
        preview = ", ".join(missing[:8])
        suffix = " ..." if len(missing) > 8 else ""
        raise ValueError(f"Missing {len(missing)} required feature column(s): {preview}{suffix}")
    if extra:
        preview = ", ".join(extra[:8])
        suffix = " ..." if len(extra) > 8 else ""
        raise ValueError(f"Unexpected input column(s): {preview}{suffix}. Use the supplied 41-feature template.")

    frame = frame[FEATURE_COLUMNS].copy()
    for col in NUMERIC_FEATURES:
        original = frame[col]
        converted = pd.to_numeric(original, errors="coerce")
        invalid = original.notna() & converted.isna()
        if invalid.any():
            examples = original[invalid].astype(str).head(3).tolist()
            raise ValueError(f"Feature '{col}' must be numeric. Invalid value(s): {examples}")
        frame[col] = converted

    for col in CATEGORICAL_FEATURES:
        frame[col] = frame[col].map(lambda x: x.strip() if isinstance(x, str) else x)

    return frame


def load_model(model_path: str | Path = DEFAULT_MODEL_PATH):
    """Load a model artifact created by this project's trusted training script."""
    path = Path(model_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"Model artifact not found: {path}. Run 'python train_model.py' first, "
            "or place the trusted exported model at this path."
        )
    # joblib uses pickle internally: never load model files from untrusted sources.
    # The sidecar detects accidental corruption; it is not a cryptographic signature
    # and does not make an untrusted model safe to deserialize.
    checksum_path = path.parent / "model.sha256"
    if checksum_path.is_file():
        parts = checksum_path.read_text(encoding="utf-8").strip().split()
        if len(parts) >= 2 and parts[1] == path.name:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual.lower() != parts[0].lower():
                raise ValueError("Model SHA-256 checksum does not match the sidecar file.")
    return joblib.load(path)


def predict_records(model, records: pd.DataFrame | list[dict[str, Any]]) -> pd.DataFrame:
    """Return class, confidence, severity, and per-class probabilities."""
    features = prepare_features(records)
    predicted_ids = model.predict(features)
    probabilities = model.predict_proba(features)

    # scikit-learn estimators expose the class IDs in probability-column order.
    estimator = model
    if hasattr(model, "named_steps") and "model" in model.named_steps:
        estimator = model.named_steps["model"]
    model_classes = list(getattr(estimator, "classes_", range(len(CLASS_NAMES))))

    rows: list[dict[str, Any]] = []
    for idx, predicted_id in enumerate(predicted_ids):
        label = ID_TO_LABEL[int(predicted_id)]
        row: dict[str, Any] = {
            "predicted_class": label,
            "confidence": float(probabilities[idx].max()),
            "threat_severity": SEVERITY[label],
        }
        for p_col, class_id in enumerate(model_classes):
            row[f"probability_{ID_TO_LABEL[int(class_id)]}"] = float(probabilities[idx, p_col])
        rows.append(row)
    return pd.DataFrame(rows)
