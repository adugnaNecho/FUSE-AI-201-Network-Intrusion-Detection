"""Training and evaluation helpers for the versioned Windows endpoint schema."""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline


def make_group_holdout(
    labels: pd.Series | np.ndarray,
    groups: pd.Series | np.ndarray,
    *,
    random_state: int = 42,
    target_test_fraction: float = 0.20,
) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
    """Choose a stratified group fold; no capture session can leak across splits."""
    raw_labels = np.asarray(labels, dtype=object)
    raw_groups = np.asarray(groups, dtype=object)
    if raw_labels.ndim != 1 or raw_groups.ndim != 1 or len(raw_labels) != len(raw_groups):
        raise ValueError("labels and groups must be one-dimensional arrays of equal length.")
    if len(raw_labels) < 4:
        raise ValueError("At least four labelled windows are required for a group holdout.")
    if pd.isna(raw_labels).any() or pd.isna(raw_groups).any():
        raise ValueError("Labels and group IDs cannot be missing.")
    y = np.asarray([str(value).strip() for value in raw_labels], dtype=str)
    group_values = np.asarray([str(value).strip() for value in raw_groups], dtype=str)
    if np.any(y == "") or np.any(group_values == ""):
        raise ValueError("Labels and group IDs cannot be empty strings.")
    if not 0.0 < target_test_fraction < 1.0:
        raise ValueError("target_test_fraction must be between 0 and 1.")

    classes = sorted(np.unique(y).tolist())
    if len(classes) < 2:
        raise ValueError("At least two labelled classes are required.")

    class_group_counts = {
        label: int(pd.Series(group_values[y == label]).nunique())
        for label in classes
    }
    minimum_groups = min(class_group_counts.values())
    if minimum_groups < 2:
        detail = ", ".join(f"{k}: {v} groups" for k, v in class_group_counts.items())
        raise ValueError(
            "Each class must occur in at least two independent capture sessions "
            f"for a leakage-resistant holdout ({detail})."
        )

    n_splits = min(5, minimum_groups)
    splitter = StratifiedGroupKFold(
        n_splits=n_splits, shuffle=True, random_state=random_state
    )
    candidates: list[tuple[float, np.ndarray, np.ndarray, int]] = []
    full_distribution = pd.Series(y).value_counts(normalize=True).to_dict()

    for fold, (train_idx, test_idx) in enumerate(
        splitter.split(np.zeros(len(y)), y, group_values), start=1
    ):
        if set(y[train_idx]) != set(classes) or set(y[test_idx]) != set(classes):
            continue
        test_distribution = pd.Series(y[test_idx]).value_counts(normalize=True).to_dict()
        distribution_gap = sum(
            abs(float(test_distribution.get(label, 0.0)) - float(full_distribution.get(label, 0.0)))
            for label in classes
        )
        fraction_gap = abs((len(test_idx) / len(y)) - target_test_fraction)
        candidates.append((fraction_gap + 0.25 * distribution_gap, train_idx, test_idx, fold))

    if not candidates:
        raise ValueError(
            "Could not make a holdout containing every class in both partitions. "
            "Collect more independently labelled sessions for each class; do not "
            "fall back to a random row split because rolling windows overlap."
        )

    _, train_idx, test_idx, fold = min(candidates, key=lambda item: item[0])
    train_groups = sorted(np.unique(group_values[train_idx]).tolist())
    test_groups = sorted(np.unique(group_values[test_idx]).tolist())
    if set(train_groups) & set(test_groups):
        raise RuntimeError("Internal error: a capture session leaked across the group split.")

    split_info = {
        "strategy": "StratifiedGroupKFold",
        "n_splits": n_splits,
        "selected_fold": fold,
        "train_rows": int(len(train_idx)),
        "test_rows": int(len(test_idx)),
        "train_groups": train_groups,
        "test_groups": test_groups,
        "class_group_counts": class_group_counts,
    }
    return train_idx, test_idx, split_info


def build_windows_classifier(random_state: int = 42) -> Pipeline:
    """Build a class-weighted, numeric-only random forest pipeline."""
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=400,
                    max_features="sqrt",
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    random_state=random_state,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def classification_metrics(
    y_true: list[str] | np.ndarray,
    y_pred: list[str] | np.ndarray,
    probabilities: np.ndarray,
    classes: list[str],
    positive_label: str | None = None,
) -> dict[str, Any]:
    """Return auditable holdout metrics; ROC/PR AUC are binary-only and explicit."""
    y_true = np.asarray(y_true, dtype=str)
    y_pred = np.asarray(y_pred, dtype=str)
    probabilities = np.asarray(probabilities, dtype=float)
    if probabilities.shape != (len(y_true), len(classes)):
        raise ValueError("Probability matrix shape does not match labels and classes.")

    report = classification_report(
        y_true, y_pred, labels=classes, output_dict=True, zero_division=0
    )
    matrix = confusion_matrix(y_true, y_pred, labels=classes)
    result: dict[str, Any] = {
        "sample_count": int(len(y_true)),
        "classes": classes,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_precision": float(precision_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=classes, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, labels=classes, average="weighted", zero_division=0)),
        "matthews_correlation_coefficient": float(matthews_corrcoef(y_true, y_pred)),
        "confusion_matrix": matrix.astype(int).tolist(),
        "classification_report": report,
        "probability_note": "Estimator class probabilities are not calibrated threat probabilities.",
    }

    if positive_label is not None:
        if len(classes) != 2 or positive_label not in classes:
            raise ValueError("positive_label must name one of the two classes in a binary task.")
        if len(np.unique(y_true)) == 2:
            positive_index = classes.index(positive_label)
            binary_truth = (y_true == positive_label).astype(int)
            positive_scores = probabilities[:, positive_index]
            result["positive_label"] = positive_label
            result["roc_auc"] = float(roc_auc_score(binary_truth, positive_scores))
            result["average_precision"] = float(average_precision_score(binary_truth, positive_scores))

    return result
