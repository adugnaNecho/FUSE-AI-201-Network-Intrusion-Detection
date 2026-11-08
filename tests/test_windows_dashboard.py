import hashlib
import json

from windows_nids.dashboard import inspect_windows_model, read_prediction_stream
from windows_nids.schema import FEATURE_COLUMNS, SCHEMA_VERSION


def prediction(snapshot_id="snap-1", predicted_class="Benign"):
    return {
        "snapshot_id": snapshot_id,
        "source_id": "win-pc-01",
        "window_end_utc": "2026-11-08T10:00:00Z",
        "process_name": "browser.exe",
        "process_instance_id": "pseudonymous-id",
        "predicted_class": predicted_class,
        "confidence": 0.9,
        "severity": "Low" if predicted_class == "Benign" else "Review",
        "class_probabilities": {"Benign": 0.9, "Suspicious": 0.1},
        "model_version": "windows-rf-test",
        "ground_truth_available": False,
    }


def test_prediction_reader_returns_valid_records_and_counts_bad_lines(tmp_path):
    path = tmp_path / "predictions.jsonl"
    path.write_text(
        json.dumps(prediction()) + "\n" + "not-json\n" +
        json.dumps({"snapshot_id": "incomplete"}) + "\n",
        encoding="utf-8",
    )

    records, diagnostics = read_prediction_stream(path)

    assert len(records) == 1
    assert records[0]["predicted_class"] == "Benign"
    assert diagnostics["valid_records"] == 1
    assert diagnostics["malformed_lines"] == 1
    assert diagnostics["skipped_records"] == 1


def test_prediction_reader_limits_tail_records(tmp_path):
    path = tmp_path / "predictions.jsonl"
    path.write_text(
        "".join(json.dumps(prediction(f"snap-{index}")) + "\n" for index in range(5)),
        encoding="utf-8",
    )

    records, diagnostics = read_prediction_stream(path, limit=2)

    assert [record["snapshot_id"] for record in records] == ["snap-3", "snap-4"]
    assert diagnostics["records_limited"] is True


def test_missing_prediction_file_is_distinguished_from_empty_stream(tmp_path):
    records, diagnostics = read_prediction_stream(tmp_path / "missing.jsonl")

    assert records == []
    assert diagnostics["exists"] is False
    assert diagnostics["valid_records"] == 0


def test_model_status_checks_schema_and_artifact_checksum(tmp_path):
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"trusted-test-artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    metadata = tmp_path / "model.json"
    metadata.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "feature_columns": FEATURE_COLUMNS,
        "classes": ["Benign", "Suspicious"],
        "window_seconds": 60,
        "model_version": "test-model",
        "model_sha256": digest,
    }), encoding="utf-8")

    status = inspect_windows_model(artifact, metadata)

    assert status["available"] is True
    assert status["model_version"] == "test-model"
    assert status["window_seconds"] == 60


def test_model_status_rejects_checksum_mismatch(tmp_path):
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"artifact")
    metadata = tmp_path / "model.json"
    metadata.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "feature_columns": FEATURE_COLUMNS,
        "classes": ["Benign", "Suspicious"],
        "window_seconds": 60,
        "model_version": "test-model",
        "model_sha256": "0" * 64,
    }), encoding="utf-8")

    status = inspect_windows_model(artifact, metadata)

    assert status["available"] is False
    assert "SHA-256" in status["message"]


def test_model_status_rejects_non_object_metadata(tmp_path):
    artifact = tmp_path / "model.joblib"
    artifact.write_bytes(b"artifact")
    metadata = tmp_path / "model.json"
    metadata.write_text("[]", encoding="utf-8")

    status = inspect_windows_model(artifact, metadata)

    assert status["available"] is False
    assert "JSON object" in status["message"]
