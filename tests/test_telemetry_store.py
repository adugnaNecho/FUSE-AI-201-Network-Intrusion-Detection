import pytest

from telemetry_store import get_live_stats, reset_engine_for_tests, store_predictions


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch, tmp_path):
    reset_engine_for_tests()
    monkeypatch.setenv("TELEMETRY_DATABASE_URL", f"sqlite:///{tmp_path / 'telemetry.db'}")
    yield
    reset_engine_for_tests()


def test_empty_store_reports_no_live_data():
    result = get_live_stats()
    assert result["status"] == "no_live_data"
    assert result["total_events_window"] == 0
    assert result["live_accuracy_available"] is False


def test_store_and_aggregate_predictions():
    count = store_predictions([
        {"predicted_class": "DoS", "confidence": 0.91},
        {"predicted_class": "Normal", "confidence": 0.82},
    ], "lab-gateway-01")
    result = get_live_stats()
    assert count == 2
    assert result["status"] == "live"
    assert result["class_counts"]["DoS"] == 1
    assert result["class_counts"]["Normal"] == 1
    assert result["active_sources_window"] == 1
    assert result["ground_truth_available"] is False


def test_invalid_source_id_is_rejected():
    with pytest.raises(ValueError):
        store_predictions([{"predicted_class": "DoS", "confidence": 0.9}], "bad source id")
