import pytest
from fastapi.testclient import TestClient

import api


class DummyModel:
    def predict(self, frame):
        return [1] * len(frame)

    def predict_proba(self, frame):
        import numpy as np
        return np.tile([0.02, 0.90, 0.03, 0.03, 0.02], (len(frame), 1))


def sample_record():
    from nids_core import NUMERIC_FEATURES
    row = {name: 0 for name in NUMERIC_FEATURES}
    row.update({"protocol_type": "tcp", "service": "private", "flag": "REJ"})
    return row


@pytest.fixture
def client(monkeypatch, tmp_path):
    from telemetry_store import reset_engine_for_tests
    reset_engine_for_tests()
    monkeypatch.setenv("LIVE_INGEST_API_TOKEN", "test-token")
    monkeypatch.setenv("TELEMETRY_DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setattr(api, "get_model", lambda: DummyModel())
    with TestClient(api.app) as test_client:
        yield test_client
    reset_engine_for_tests()


def test_telemetry_ingest_requires_token(client):
    response = client.post("/telemetry/ingest", json={"source_id": "test", "records": [sample_record()]})
    assert response.status_code == 401


def test_telemetry_ingest_and_stats(client):
    response = client.post("/telemetry/ingest", headers={"X-API-Key": "test-token"},
                           json={"source_id": "lab-1", "records": [sample_record()]})
    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    stats = client.get("/telemetry/stats", headers={"X-API-Key": "test-token"})
    assert stats.status_code == 200
    assert stats.json()["total_events_window"] == 1


def test_invalid_feature_record_rejected(client):
    response = client.post("/telemetry/ingest", headers={"X-API-Key": "test-token"},
                           json={"source_id": "lab-1", "records": [{"wrong": 1}]})
    assert response.status_code == 422
