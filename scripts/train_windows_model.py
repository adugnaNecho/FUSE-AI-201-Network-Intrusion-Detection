#!/usr/bin/env python3
"""Train and independently evaluate a Windows Sysmon 19-feature classifier."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from windows_nids.model_training import (
    build_windows_classifier,
    classification_metrics,
    make_group_holdout,
)
from windows_nids.schema import FEATURE_COLUMNS, SCHEMA_VERSION, validate_feature_vector


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="CSV with 19 features, label, session_id and label_source")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--group-column", default="session_id", help="Capture-session ID used for leakage-resistant splitting")
    parser.add_argument("--label-source-column", default="label_source", help="Provenance for each ground-truth label")
    parser.add_argument("--positive-label", default=None, help="Optional positive class for binary ROC-AUC and PR-AUC")
    parser.add_argument("--model-version", default=None)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def clean_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): clean_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_json(v) for v in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    return value


def severity_for(label: str) -> str:
    normalized = label.strip().lower()
    if normalized in {"benign", "normal", "goodware"}:
        return "Low"
    if normalized in {"malicious", "ransomware", "attack", "intrusion"}:
        return "High"
    return "Review"


def main() -> int:
    args = parse_args()
    if not args.input.is_file():
        print(f"Training CSV not found: {args.input}", file=sys.stderr)
        return 2

    try:
        frame = pd.read_csv(args.input)
        required = [*FEATURE_COLUMNS, args.label_column, args.group_column, args.label_source_column]
        missing = [name for name in required if name not in frame.columns]
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")
        if "window_seconds" not in frame.columns:
            raise ValueError("CSV must include window_seconds so the model is tied to its aggregation window.")
        window_values = pd.to_numeric(frame["window_seconds"], errors="coerce")
        if window_values.isna().any() or window_values.nunique() != 1 or float(window_values.iloc[0]) != 60.0:
            raise ValueError("This model version requires exactly 60-second feature windows in every row.")
        if frame.empty:
            raise ValueError("Training CSV is empty.")
        if frame[[args.label_column, args.group_column, args.label_source_column]].isna().any().any():
            raise ValueError("label, session_id and label_source cannot be blank; label the rows before training.")

        labels = frame[args.label_column].astype(str).str.strip()
        groups = frame[args.group_column].astype(str).str.strip()
        sources = frame[args.label_source_column].astype(str).str.strip()
        if (labels == "").any() or (groups == "").any() or (sources == "").any():
            raise ValueError("label, session_id and label_source cannot be empty strings.")
        if "snapshot_id" in frame.columns and frame["snapshot_id"].duplicated().any():
            raise ValueError("Duplicate snapshot_id values found; deduplicate repeated exported windows first.")

        X = frame[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
        if X.isna().any().any():
            raise ValueError("Feature columns contain missing or non-numeric values.")
        if not np.isfinite(X.to_numpy(dtype=float)).all():
            raise ValueError("Feature columns contain non-finite values.")
        # Reuse API-side domain checks so training and inference enforce identical feature rules.
        for row_number, (_, row) in enumerate(X.iterrows(), start=2):
            try:
                validate_feature_vector(row.to_dict())
            except ValueError as exc:
                raise ValueError(f"Invalid feature row {row_number}: {exc}") from exc

        classes = sorted(labels.unique().tolist())
        if len(classes) < 2:
            raise ValueError("At least two independently labelled classes are required.")
        if args.positive_label and (len(classes) != 2 or args.positive_label not in classes):
            raise ValueError("--positive-label must match one of exactly two labels in the CSV.")

        train_idx, test_idx, split_info = make_group_holdout(
            labels, groups, random_state=args.random_state
        )
        model = build_windows_classifier(args.random_state)
        model.fit(X.iloc[train_idx], labels.iloc[train_idx])
        predictions = model.predict(X.iloc[test_idx]).astype(str)
        probabilities = model.predict_proba(X.iloc[test_idx])
        model_classes = [str(item) for item in model.named_steps["classifier"].classes_]
        metrics = classification_metrics(
            labels.iloc[test_idx].to_numpy(),
            predictions,
            probabilities,
            model_classes,
            positive_label=args.positive_label,
        )

        output_dir = args.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        model_path = output_dir / "windows_nids_model.joblib"
        metadata_path = output_dir / "windows_nids_model.json"
        evaluation_path = output_dir / "windows_nids_evaluation.json"
        predictions_path = output_dir / "windows_nids_holdout_predictions.csv"
        checksum_path = output_dir / "windows_nids_model.sha256"

        joblib.dump(model, model_path, compress=3)
        model_hash = sha256_file(model_path)
        checksum_path.write_text(f"{model_hash}  {model_path.name}\n", encoding="utf-8")

        metadata = {
            "schema_version": SCHEMA_VERSION,
            "model_version": args.model_version or datetime.now(timezone.utc).strftime("windows-rf-%Y%m%dT%H%M%SZ"),
            "trained_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "feature_columns": FEATURE_COLUMNS,
            "window_seconds": 60,
            "classes": model_classes,
            "severity_mapping": {label: severity_for(label) for label in model_classes},
            "model_type": "RandomForestClassifier",
            "training_rows": int(len(train_idx)),
            "holdout_rows": int(len(test_idx)),
            "training_groups": split_info["train_groups"],
            "holdout_groups": split_info["test_groups"],
            "split_strategy": split_info["strategy"],
            "training_data_sha256": sha256_file(args.input),
            "model_sha256": model_hash,
            "label_sources": sorted(sources.unique().tolist()),
            "class_counts_all_rows": {k: int(v) for k, v in labels.value_counts().to_dict().items()},
            "holdout_evaluation": metrics,
            "limitations": [
                "Labels and their provenance must be independently verified by the dataset owner.",
                "Predictions are limited to the classes and 19 Sysmon network/DNS features represented in this dataset.",
                "Estimator class probabilities are not calibrated threat probabilities.",
                "The model is not a general-purpose malware detector and must not trigger automatic blocking.",
            ],
        }
        metadata_path.write_text(json.dumps(clean_json(metadata), indent=2, allow_nan=False) + "\n", encoding="utf-8")

        holdout = frame.iloc[test_idx][[args.group_column, args.label_source_column]].copy()
        if "snapshot_id" in frame.columns:
            holdout.insert(0, "snapshot_id", frame.iloc[test_idx]["snapshot_id"].astype(str).values)
        holdout["true_label"] = labels.iloc[test_idx].values
        holdout["predicted_class"] = predictions
        holdout["max_class_probability"] = probabilities.max(axis=1)
        for index, label in enumerate(model_classes):
            safe_name = "probability_" + "_".join(ch for ch in label if ch.isalnum() or ch in "-_ ").strip().replace(" ", "_")
            holdout[safe_name] = probabilities[:, index]
        holdout.to_csv(predictions_path, index=False)

        evaluation = {
            "schema_version": SCHEMA_VERSION,
            "evaluation_type": "group_holdout",
            "split": split_info,
            "metrics": metrics,
            "model_version": metadata["model_version"],
            "training_data_sha256": metadata["training_data_sha256"],
            "model_sha256": model_hash,
        }
        evaluation_path.write_text(json.dumps(clean_json(evaluation), indent=2, allow_nan=False) + "\n", encoding="utf-8")

        print(f"Model saved: {model_path}")
        print(f"Metadata saved: {metadata_path}")
        print(f"Independent holdout evaluation: {evaluation_path}")
        print(f"Holdout rows: {len(test_idx)}; training rows: {len(train_idx)}")
        print(json.dumps(metrics, indent=2))
        print("The saved model is trained only on training sessions; holdout sessions were not used for fitting.")
        return 0
    except (ValueError, OSError, KeyError) as exc:
        print(f"Windows model training stopped: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
