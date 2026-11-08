import numpy as np
from fastapi.testclient import TestClient

import api
from windows_nids.inference import WindowsModelBundle
from windows_nids.schema import FEATURE_COLUMNS, SCHEMA_VERSION


class DummyWindowsModel:
    classes_ = np.array(["Benign", "Suspicious"])

    def predict(self, frame):
        return np.array(["Benign"] * len(frame))

    def predict_proba(self, frame):
        return np.tile([0.85, 0.15], (len(frame), 1))


def sample_snapshot(source_id="win-pc-01"):
    features = {name: 0 for name in FEATURE_COLUMNS}
    return {
        "schema_version": SCHEMA_VERSION,
        "snapshot_id": "win-pc-01:abc123:1794120000",
        "source_id": source_id,
        "window_start_utc": "2026-11-08T09:10:00Z",
        "window_end_utc": "2026-11-08T09:11:00Z",
        "window_seconds": 60,
        "process_name": "browser.exe",
        "process_instance_id": "abc12345678901234567",
        "features": features,
    }


def test_windows_prediction_requires_token(monkeypatch):
    monkeypatch.delenv("WINDOWS_INGEST_API_TOKEN", raising=False)
    monkeypatch.delenv("LIVE_INGEST_API_TOKEN", raising=False)
    client = TestClient(api.app)
    response = client.post("/windows/predict", json={"source_id": "win-pc-01", "snapshots": [sample_snapshot()]})
    assert response.status_code == 503


def test_windows_prediction_returns_503_until_model_is_installed(monkeypatch):
    monkeypatch.setenv("WINDOWS_INGEST_API_TOKEN", "windows-test-token")
    monkeypatch.setattr(api, "get_windows_model", lambda: (_ for _ in ()).throw(FileNotFoundError("model absent")))
    client = TestClient(api.app)
    response = client.post(
        "/windows/predict",
        headers={"X-API-Key": "windows-test-token"},
        json={"source_id": "win-pc-01", "snapshots": [sample_snapshot()]},
    )
    assert response.status_code == 503
    assert "Windows model is not ready" in response.json()["detail"]


def test_windows_prediction_uses_separate_schema_and_model(monkeypatch):
    monkeypatch.setenv("WINDOWS_INGEST_API_TOKEN", "windows-test-token")
    bundle = WindowsModelBundle(
        model=DummyWindowsModel(),
        model_version="unit-test-model",
        classes=["Benign", "Suspicious"],
        severity_mapping={"Benign": "Low", "Suspicious": "Review"},
    )
    monkeypatch.setattr(api, "get_windows_model", lambda: bundle)
    client = TestClient(api.app)
    response = client.post(
        "/windows/predict",
        headers={"X-API-Key": "windows-test-token"},
        json={"source_id": "win-pc-01", "snapshots": [sample_snapshot()]},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] == 1
    assert payload["predictions"][0]["predicted_class"] == "Benign"
    assert payload["predictions"][0]["confidence"] == 0.85
    assert payload["ground_truth_available"] is False
    assert payload["raw_features_stored"] is False


def test_windows_prediction_rejects_source_mismatch(monkeypatch):
    monkeypatch.setenv("WINDOWS_INGEST_API_TOKEN", "windows-test-token")
    client = TestClient(api.app)
    response = client.post(
        "/windows/predict",
        headers={"X-API-Key": "windows-test-token"},
        json={"source_id": "win-pc-01", "snapshots": [sample_snapshot("other-pc")]},
    )
    assert response.status_code == 422
