"""Evidence-based analytics helpers for the Group 19 NSL-KDD dashboard.

The dashboard uses the evaluation.json emitted by train_model.py whenever it is
available. A small, explicitly labelled snapshot of the latest user-reported
training run is provided as a fallback for deployments where that file is absent.
No confusion matrix or per-class metric is fabricated when the source does not
contain it.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pandas as pd

from nids_core import CLASS_NAMES

# Values transcribed from the successful 2026-11-02/03 `python train_model.py`
# console output supplied by the project group. This snapshot intentionally has
# no confusion matrix or precision/F1 by class because those values were not
# present in that console output. The full evaluation.json from train_model.py
# contains these richer measurements and takes precedence when available.
REPORTED_RUN_SNAPSHOT: dict[str, Any] = {
    "project": "Group 19 NSL-KDD multi-class NIDS",
    "model": "RandomForestClassifier with SMOTENC preprocessing pipeline",
    "dataset": "NSL-KDD KDDTrain+ / KDDTest+",
    "classes": CLASS_NAMES,
    "validation": {
        "split": "validation",
        "accuracy": 0.9989206206431303,
        "macro_precision": 0.9716600806368865,
        "macro_recall": 0.9946199242091588,
        "macro_f1": 0.9825997382981807,
        "records": 22235,
    },
    "official_test": {
        "split": "official_test",
        "accuracy": 0.7461852377572746,
        "macro_precision": 0.7934698030314955,
        "macro_recall": 0.48706823299637936,
        "macro_f1": 0.5151010737642621,
        "records": 22544,
        "per_class_recall": {
            "Normal": 0.9728143342601174,
            "DoS": 0.7656836461126005,
            "Probe": 0.5352470930232558,
            "U2R": 0.08955223880597014,
            "R2L": 0.07204385277995301,
        },
    },
    "snapshot_source": "Values transcribed from the group's successful train_model.py console output; full evaluation.json is preferred.",
}

METRIC_LABELS = {
    "accuracy": "Accuracy",
    "macro_precision": "Macro precision",
    "macro_recall": "Macro recall",
    "macro_f1": "Macro F1",
}


def load_evaluation(path: str | Path) -> tuple[dict[str, Any], str]:
    """Load the generated evaluation artifact, or use the disclosed run snapshot."""
    eval_path = Path(path)
    if eval_path.is_file():
        try:
            payload = json.loads(eval_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and isinstance(payload.get("official_test"), dict):
                return payload, "evaluation_artifact"
        except (OSError, json.JSONDecodeError):
            pass
    return REPORTED_RUN_SNAPSHOT.copy(), "reported_run_snapshot"


def metrics_comparison_frame(evaluation: dict[str, Any]) -> pd.DataFrame:
    """Return validation/test metrics in long form for grouped comparison charts.

    Scores remain proportions in the inclusive range [0, 1]. The returned
    columns are ``Metric``, ``Dataset`` and ``Score``, which can be passed
    directly to Plotly Express with ``barmode="group"``. Long form avoids the
    misleading stacked-bar interpretation of summing validation and test scores.
    """
    rows: list[dict[str, Any]] = []
    for key, label in METRIC_LABELS.items():
        for split_key, split_label in (("validation", "Validation"), ("official_test", "KDDTest+")):
            split = evaluation.get(split_key, {})
            value = split.get(key) if isinstance(split, dict) else None
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                score = float(value)
                if math.isfinite(score) and 0.0 <= score <= 1.0:
                    rows.append({"Metric": label, "Dataset": split_label, "Score": score})

    return pd.DataFrame(rows, columns=["Metric", "Dataset", "Score"])


def class_metrics_frame(evaluation: dict[str, Any], split_key: str = "official_test") -> pd.DataFrame:
    """Build class-wise metrics only from values present in evaluation evidence."""
    split = evaluation.get(split_key, {})
    per_class = split.get("per_class", {}) if isinstance(split, dict) else {}
    fallback_recall = split.get("per_class_recall", {}) if isinstance(split, dict) else {}

    if not fallback_recall and split_key == "official_test":
        fallback_recall = evaluation.get("test_class_recall", {}) or {}

    rows: list[dict[str, Any]] = []
    for class_name in evaluation.get("classes", CLASS_NAMES):
        metrics = per_class.get(class_name, {}) if isinstance(per_class, dict) else {}
        row: dict[str, Any] = {"Class": class_name}
        for source_key, target_key in (
            ("precision", "Precision"),
            ("recall", "Recall"),
            ("f1-score", "F1-score"),
            ("support", "Support"),
        ):
            value = metrics.get(source_key)
            if isinstance(value, (int, float)):
                row[target_key] = float(value)
        if "Recall" not in row and class_name in fallback_recall:
            row["Recall"] = float(fallback_recall[class_name])
        if len(row) > 1:
            rows.append(row)
    return pd.DataFrame(rows).set_index("Class") if rows else pd.DataFrame()


def confusion_matrix_frame(evaluation: dict[str, Any], split_key: str = "official_test") -> pd.DataFrame | None:
    """Return the actual stored confusion matrix, or None if not recorded."""
    split = evaluation.get(split_key, {})
    matrix = split.get("confusion_matrix") if isinstance(split, dict) else None
    classes = evaluation.get("classes", CLASS_NAMES)
    if not isinstance(matrix, list) or len(matrix) != len(classes):
        return None
    if any(not isinstance(row, list) or len(row) != len(classes) for row in matrix):
        return None
    return pd.DataFrame(matrix, index=classes, columns=classes).astype(int)


def fpr_frame(evaluation: dict[str, Any], split_key: str = "official_test") -> pd.DataFrame:
    split = evaluation.get(split_key, {})
    fpr = split.get("false_positive_rate_ovr", {}) if isinstance(split, dict) else {}
    if not isinstance(fpr, dict) or not fpr:
        return pd.DataFrame(columns=["False positive rate"])
    return pd.DataFrame.from_dict(fpr, orient="index", columns=["False positive rate"])


def prediction_distribution(predictions: pd.DataFrame) -> pd.DataFrame:
    """Count predictions for all five classes, retaining zero-count classes."""
    if "predicted_class" not in predictions.columns:
        return pd.DataFrame(columns=["Predicted records"])
    counts = predictions["predicted_class"].value_counts().reindex(CLASS_NAMES, fill_value=0)
    return counts.to_frame("Predicted records")


def severity_distribution(predictions: pd.DataFrame) -> pd.DataFrame:
    if "threat_severity" not in predictions.columns:
        return pd.DataFrame(columns=["Records"])
    order = ["Low", "Medium", "High", "Critical"]
    counts = predictions["threat_severity"].value_counts().reindex(order, fill_value=0)
    return counts.to_frame("Records")


def traffic_profile(records: pd.DataFrame, max_points: int = 500) -> pd.DataFrame:
    """Prepare uploaded-record traffic features for a record-order chart.

    Byte counts are transformed with log10(x + 1) to keep highly skewed byte
    values readable. This is record order, not a time series: NSL-KDD does not
    provide timestamps in the 41-feature input schema.
    """
    wanted = ["src_bytes", "dst_bytes", "count", "srv_count"]
    present = [column for column in wanted if column in records.columns]
    if records.empty or not present:
        return pd.DataFrame()

    frame = records[present].copy()
    for column in present:
        frame[column] = pd.to_numeric(frame[column], errors="coerce")

    # Bound chart payload for large uploads while retaining the order of records.
    if len(frame) > max_points:
        step = math.ceil(len(frame) / max_points)
        frame = frame.iloc[::step].copy()

    chart = pd.DataFrame(index=pd.RangeIndex(1, len(frame) + 1, name="Record"))
    for column in present:
        values = frame[column].fillna(0).clip(lower=0)
        if column in {"src_bytes", "dst_bytes"}:
            chart[f"log10({column} + 1)"] = values.map(lambda value: math.log10(float(value) + 1.0)).to_numpy()
        else:
            chart[column] = values.to_numpy()
    return chart


def confidence_frame(predictions: pd.DataFrame, max_points: int = 500) -> pd.DataFrame:
    if "confidence" not in predictions.columns or predictions.empty:
        return pd.DataFrame()
    confidence = pd.to_numeric(predictions["confidence"], errors="coerce").dropna()
    if len(confidence) > max_points:
        confidence = confidence.iloc[:: math.ceil(len(confidence) / max_points)]
    return pd.DataFrame({"Maximum class probability (not calibrated)": confidence.to_numpy()}, index=pd.RangeIndex(1, len(confidence) + 1, name="Record"))


def normal_vs_attack_profile(
    records: pd.DataFrame,
    predictions: pd.DataFrame,
    feature: str = "src_bytes",
    max_points: int = 500,
) -> pd.DataFrame:
    """Split one numeric traffic feature into Normal vs model-predicted attack.

    The groups are predictions, not ground-truth labels. Record order is not a
    time axis. The returned source-byte values use log10(x + 1) for readability.
    """
    if feature not in records.columns or "predicted_class" not in predictions.columns:
        return pd.DataFrame()
    if records.empty or predictions.empty or len(records) != len(predictions):
        return pd.DataFrame()

    values = pd.to_numeric(records[feature], errors="coerce").fillna(0).clip(lower=0)
    labels = predictions["predicted_class"].reset_index(drop=True)
    if feature in {"src_bytes", "dst_bytes"}:
        values = values.map(lambda value: math.log10(float(value) + 1.0))

    frame = pd.DataFrame({
        "Normal (model-predicted)": values.where(labels.eq("Normal")),
        "Attack (model-predicted)": values.where(labels.ne("Normal")),
    })
    if len(frame) > max_points:
        frame = frame.iloc[:: math.ceil(len(frame) / max_points)].copy()
    frame.index = pd.RangeIndex(1, len(frame) + 1, name="Record")
    return frame
