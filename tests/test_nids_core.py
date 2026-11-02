import pandas as pd
import pytest

from nids_core import FEATURE_COLUMNS, NUMERIC_FEATURES, prepare_features, predict_records


def sample_row():
    values = {name: 0 for name in NUMERIC_FEATURES}
    values.update({"protocol_type": "tcp", "service": "private", "flag": "REJ"})
    return values


def test_schema_has_41_features_and_three_categorical_fields():
    assert len(FEATURE_COLUMNS) == 41


def test_prepare_features_orders_and_converts_numeric_columns():
    row = sample_row()
    row["duration"] = "12"
    result = prepare_features([row])
    assert list(result.columns) == FEATURE_COLUMNS
    assert result.loc[0, "duration"] == 12


def test_known_metadata_columns_are_ignored():
    row = sample_row()
    row["class"] = "neptune"
    row["difficulty_level"] = 21
    result = prepare_features([row])
    assert list(result.columns) == FEATURE_COLUMNS


def test_missing_feature_is_rejected():
    row = sample_row()
    row.pop("src_bytes")
    with pytest.raises(ValueError, match="Missing"):
        prepare_features([row])


def test_non_numeric_feature_is_rejected():
    row = sample_row()
    row["src_bytes"] = "many"
    with pytest.raises(ValueError, match="must be numeric"):
        prepare_features([row])


def test_empty_input_is_rejected():
    with pytest.raises(ValueError, match="at least one"):
        prepare_features([])


class _DummyEstimator:
    classes_ = [0, 1, 2, 3, 4]


class _DummyPipeline:
    named_steps = {"model": _DummyEstimator()}

    def predict(self, frame):
        return [1] * len(frame)

    def predict_proba(self, frame):
        import numpy as np
        return np.tile([0.05, 0.80, 0.05, 0.05, 0.05], (len(frame), 1))


def test_prediction_format_with_deterministic_test_double():
    result = predict_records(_DummyPipeline(), [sample_row()])
    assert result.loc[0, "predicted_class"] == "DoS"
    assert result.loc[0, "threat_severity"] == "High"
    assert result.loc[0, "confidence"] == pytest.approx(0.80)
    assert result.loc[0, "probability_DoS"] == pytest.approx(0.80)
