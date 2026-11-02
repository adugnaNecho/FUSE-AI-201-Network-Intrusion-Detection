from fastapi.testclient import TestClient

from api import app

client = TestClient(app)


def test_health_reports_missing_model_without_claiming_ready():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] in {"ready", "model_missing"}


def test_schema_reports_41_required_features():
    response = client.get("/schema")
    assert response.status_code == 200
    assert response.json()["feature_count"] == 41


def test_predict_rejects_empty_records():
    response = client.post("/predict", json={"records": []})
    assert response.status_code == 422
