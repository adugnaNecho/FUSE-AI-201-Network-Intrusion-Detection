from scripts.update_live_readme import render


def test_live_readme_labels_predictions_not_confirmed_incidents():
    text = render({"status": "live", "total_events_window": 4, "total_events_all_time": 8,
                   "active_sources_window": 1, "last_received_at": "2026-11-08T07:00:00Z",
                   "class_counts": {"DoS": 3, "Normal": 1}})
    assert "not independently verified incidents" in text
    assert "| DoS | 3 |" in text
    assert "ground-truth labels" in text
