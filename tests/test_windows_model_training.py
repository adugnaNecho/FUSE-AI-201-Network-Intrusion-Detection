import numpy as np
import pandas as pd
import pytest

from windows_nids.model_training import (
    build_windows_classifier,
    classification_metrics,
    make_group_holdout,
)


def test_group_holdout_keeps_capture_sessions_disjoint_and_classes_present():
    labels = []
    groups = []
    for index in range(20):
        label = "Benign" if index % 2 == 0 else "Malicious"
        for _ in range(5):
            labels.append(label)
            groups.append(f"capture-{index:02d}")

    train_idx, test_idx, info = make_group_holdout(pd.Series(labels), pd.Series(groups))

    assert set(np.asarray(groups)[train_idx]).isdisjoint(set(np.asarray(groups)[test_idx]))
    assert set(np.asarray(labels)[train_idx]) == {"Benign", "Malicious"}
    assert set(np.asarray(labels)[test_idx]) == {"Benign", "Malicious"}
    assert info["strategy"] == "StratifiedGroupKFold"


def test_group_holdout_rejects_a_class_seen_in_only_one_capture_session():
    labels = ["Benign"] * 4 + ["Malicious"] * 4
    groups = ["normal-a"] * 2 + ["normal-b"] * 2 + ["attack-a"] * 4

    with pytest.raises(ValueError, match="at least two independent capture sessions"):
        make_group_holdout(labels, groups)


def test_classifier_and_metrics_produce_multiclass_outputs():
    X = pd.DataFrame({"a": [0, 0.1, 1, 1.1], "b": [1, 0.9, 0, 0.1]})
    y = np.array(["Benign", "Benign", "Malicious", "Malicious"])
    model = build_windows_classifier(random_state=7)
    model.fit(X, y)
    probabilities = model.predict_proba(X)
    classes = [str(value) for value in model.named_steps["classifier"].classes_]

    metrics = classification_metrics(y, model.predict(X), probabilities, classes, "Malicious")

    assert metrics["sample_count"] == 4
    assert metrics["accuracy"] >= 0.5
    assert "roc_auc" in metrics
    assert "average_precision" in metrics
