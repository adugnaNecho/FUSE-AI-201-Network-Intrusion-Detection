import json

import pandas as pd

from windows_nids.schema import SCHEMA_VERSION
from scripts.evaluate_windows_predictions import main


def test_live_evaluation_rejects_training_or_internal_holdout_sessions(tmp_path, monkeypatch, capsys):
    prediction_path = tmp_path / "predictions.jsonl"
    labels_path = tmp_path / "labels.csv"
    metadata_path = tmp_path / "model.json"
    output_path = tmp_path / "evaluation.json"

    prediction_path.write_text(
        json.dumps({
            "snapshot_id": "snapshot-1",
            "predicted_class": "Benign",
            "class_probabilities": {"Benign": 0.9, "Malicious": 0.1},
            "model_version": "test-model",
        }) + "\n",
        encoding="utf-8",
    )
    pd.DataFrame([{
        "snapshot_id": "snapshot-1",
        "session_id": "holdout-session-1",
        "label": "Benign",
        "label_source": "test-only-fixture",
    }]).to_csv(labels_path, index=False)
    metadata_path.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "classes": ["Benign", "Malicious"],
        "model_version": "test-model",
        "training_groups": ["training-session-1"],
        "holdout_groups": ["holdout-session-1"],
    }), encoding="utf-8")

    monkeypatch.setattr("sys.argv", [
        "evaluate_windows_predictions.py",
        "--predictions", str(prediction_path),
        "--labels", str(labels_path),
        "--metadata", str(metadata_path),
        "--output", str(output_path),
    ])

    assert main() == 2
    assert "overlap model-development sessions" in capsys.readouterr().err
    assert not output_path.exists()
