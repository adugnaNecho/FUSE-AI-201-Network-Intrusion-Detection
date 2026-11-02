import json

import pandas as pd

from nids_dashboard import (
    REPORTED_RUN_SNAPSHOT,
    class_metrics_frame,
    confidence_frame,
    confusion_matrix_frame,
    fpr_frame,
    load_evaluation,
    metrics_comparison_frame,
    normal_vs_attack_profile,
    prediction_distribution,
    severity_distribution,
    traffic_profile,
)
from nids_core import CLASS_NAMES


def test_reported_metrics_snapshot_has_latest_group_run_values():
    test = REPORTED_RUN_SNAPSHOT["official_test"]
    assert test["accuracy"] == 0.7461852377572746
    assert test["macro_f1"] == 0.5151010737642621
    assert test["per_class_recall"]["U2R"] < 0.10
    assert test["per_class_recall"]["R2L"] < 0.08


def test_load_evaluation_prefers_generated_json(tmp_path):
    payload = {
        "classes": CLASS_NAMES,
        "validation": {"accuracy": 0.9},
        "official_test": {"accuracy": 0.8, "confusion_matrix": [[1] * 5 for _ in range(5)]},
    }
    path = tmp_path / "evaluation.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded, source = load_evaluation(path)
    assert source == "evaluation_artifact"
    assert loaded["official_test"]["accuracy"] == 0.8


def test_load_evaluation_falls_back_to_reported_snapshot(tmp_path):
    loaded, source = load_evaluation(tmp_path / "missing.json")
    assert source == "reported_run_snapshot"
    assert loaded["official_test"]["macro_f1"] == REPORTED_RUN_SNAPSHOT["official_test"]["macro_f1"]


def test_metrics_comparison_returns_long_form_values_for_grouped_bars():
    frame = metrics_comparison_frame(REPORTED_RUN_SNAPSHOT)
    assert list(frame.columns) == ["Metric", "Dataset", "Score"]
    assert len(frame) == 8
    test_f1 = frame.loc[
        frame["Metric"].eq("Macro F1") & frame["Dataset"].eq("KDDTest+"),
        "Score",
    ].iloc[0]
    validation_f1 = frame.loc[
        frame["Metric"].eq("Macro F1") & frame["Dataset"].eq("Validation"),
        "Score",
    ].iloc[0]
    assert test_f1 == REPORTED_RUN_SNAPSHOT["official_test"]["macro_f1"]
    assert validation_f1 == REPORTED_RUN_SNAPSHOT["validation"]["macro_f1"]
    assert frame["Score"].between(0.0, 1.0).all()


def test_metrics_comparison_ignores_invalid_or_out_of_range_scores():
    payload = {
        "validation": {"accuracy": 1.2, "macro_f1": float("nan")},
        "official_test": {"accuracy": 0.75, "macro_f1": 0.5},
    }
    frame = metrics_comparison_frame(payload)
    assert len(frame) == 2
    assert set(frame["Metric"]) == {"Accuracy", "Macro F1"}
    assert set(frame["Dataset"]) == {"KDDTest+"}


def test_class_metrics_only_shows_recall_when_other_metrics_are_unavailable():
    frame = class_metrics_frame(REPORTED_RUN_SNAPSHOT)
    assert list(frame.index) == CLASS_NAMES
    assert "Recall" in frame.columns
    assert "Precision" not in frame.columns
    assert frame.loc["R2L", "Recall"] == REPORTED_RUN_SNAPSHOT["official_test"]["per_class_recall"]["R2L"]


def test_confusion_matrix_is_not_invented_when_missing():
    assert confusion_matrix_frame(REPORTED_RUN_SNAPSHOT) is None


def test_confusion_matrix_reads_actual_five_by_five_matrix():
    payload = {
        "classes": CLASS_NAMES,
        "official_test": {"confusion_matrix": [[i + j for j in range(5)] for i in range(5)]},
    }
    frame = confusion_matrix_frame(payload)
    assert frame.shape == (5, 5)
    assert frame.iloc[0, 0] == 0


def test_prediction_distribution_includes_zero_count_classes():
    predictions = pd.DataFrame({"predicted_class": ["Normal", "DoS", "DoS"]})
    frame = prediction_distribution(predictions)
    assert list(frame.index) == CLASS_NAMES
    assert frame.loc["DoS", "Predicted records"] == 2
    assert frame.loc["U2R", "Predicted records"] == 0


def test_severity_distribution_has_fixed_severity_order():
    predictions = pd.DataFrame({"threat_severity": ["High", "Low", "High"]})
    frame = severity_distribution(predictions)
    assert list(frame.index) == ["Low", "Medium", "High", "Critical"]
    assert frame.loc["High", "Records"] == 2


def test_traffic_profile_transforms_bytes_and_retains_record_order():
    records = pd.DataFrame({"src_bytes": [0, 9, 99], "dst_bytes": [99, 9, 0], "count": [1, 2, 3]})
    frame = traffic_profile(records)
    assert list(frame.index) == [1, 2, 3]
    assert "log10(src_bytes + 1)" in frame.columns
    assert frame.loc[2, "log10(src_bytes + 1)"] == 1.0
    assert list(frame["count"]) == [1, 2, 3]


def test_traffic_profile_caps_large_uploads():
    records = pd.DataFrame({"src_bytes": range(1000)})
    frame = traffic_profile(records, max_points=100)
    assert len(frame) <= 100


def test_confidence_profile_is_empty_without_confidence_column():
    assert confidence_frame(pd.DataFrame({"predicted_class": ["Normal"]})).empty


def test_normal_vs_attack_profile_groups_records_from_model_predictions():
    records = pd.DataFrame({"src_bytes": [9, 99, 999]})
    predictions = pd.DataFrame({"predicted_class": ["Normal", "DoS", "Probe"]})
    frame = normal_vs_attack_profile(records, predictions)
    assert list(frame.columns) == ["Normal (model-predicted)", "Attack (model-predicted)"]
    assert frame.loc[1, "Normal (model-predicted)"] == 1.0
    assert pd.isna(frame.loc[1, "Attack (model-predicted)"])
    assert frame.loc[2, "Attack (model-predicted)"] == 2.0


def test_normal_vs_attack_profile_rejects_row_count_mismatch():
    records = pd.DataFrame({"src_bytes": [1, 2]})
    predictions = pd.DataFrame({"predicted_class": ["Normal"]})
    assert normal_vs_attack_profile(records, predictions).empty


def test_class_metrics_use_canonical_order_and_integer_support():
    source_order = ["R2L", "U2R", "Probe", "DoS", "Normal"]
    payload = {
        "classes": source_order,
        "official_test": {
            "per_class": {
                name: {
                    "precision": 0.5,
                    "recall": 0.4,
                    "f1-score": 0.44,
                    "support": float(index + 10),
                }
                for index, name in enumerate(source_order)
            }
        },
    }
    frame = class_metrics_frame(payload)
    assert list(frame.index) == CLASS_NAMES
    assert frame.loc["Normal", "Support"] == 14
    assert pd.api.types.is_integer_dtype(frame["Support"])


def test_confusion_matrix_is_reordered_to_canonical_class_order():
    source_order = ["R2L", "U2R", "Probe", "DoS", "Normal"]
    matrix = [[i * 10 + j for j in range(5)] for i in range(5)]
    payload = {"classes": source_order, "official_test": {"confusion_matrix": matrix}}
    frame = confusion_matrix_frame(payload)
    assert list(frame.index) == CLASS_NAMES
    assert list(frame.columns) == CLASS_NAMES
    # Normal is the final row/column in source_order, hence source value [4][4].
    assert frame.loc["Normal", "Normal"] == 44
    assert frame.loc["DoS", "DoS"] == 33


def test_fpr_frame_uses_canonical_class_order_and_proportions():
    payload = {
        "official_test": {
            "false_positive_rate_ovr": {
                "R2L": 0.004,
                "U2R": 0.003,
                "Probe": 0.02,
                "DoS": 0.01,
                "Normal": 0.409,
            }
        }
    }
    frame = fpr_frame(payload)
    assert list(frame.columns) == ["Class", "False positive rate"]
    assert list(frame["Class"]) == CLASS_NAMES
    normal_rate = frame.loc[frame["Class"].eq("Normal"), "False positive rate"].iloc[0]
    assert normal_rate == 0.409
    assert frame["False positive rate"].between(0, 1).all()


def test_fpr_frame_is_plotly_express_compatible():
    import plotly.express as px

    payload = {
        "official_test": {
            "false_positive_rate_ovr": {
                "Normal": 0.409,
                "DoS": 0.01,
                "Probe": 0.02,
                "U2R": 0.003,
                "R2L": 0.004,
            }
        }
    }
    frame = fpr_frame(payload)
    figure = px.bar(frame, x="Class", y="False positive rate")
    assert len(figure.data) == 1
    assert list(figure.data[0].x) == CLASS_NAMES
