from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from windows_nids.inference import WindowsModelBundle, predict_snapshots
from windows_nids.schema import FEATURE_COLUMNS, SCHEMA_VERSION


class FixedModel:
    classes_ = np.array(["Benign", "Malicious"])

    def predict(self, frame):
        return np.array(["Benign"] * len(frame))

    def predict_proba(self, frame):
        return np.tile([0.8, 0.2], (len(frame), 1))


def sample_snapshot(window_seconds=60):
    end = datetime(2026, 11, 8, 10, 1, tzinfo=timezone.utc)
    start = end - timedelta(seconds=window_seconds)
    return {
        "schema_version": SCHEMA_VERSION,
        "snapshot_id": "s1",
        "source_id": "pc-01",
        "window_start_utc": start.isoformat().replace("+00:00", "Z"),
        "window_end_utc": end.isoformat().replace("+00:00", "Z"),
        "window_seconds": window_seconds,
        "process_name": "browser.exe",
        "process_instance_id": "abc12345678901234567",
        "features": {name: 0 for name in FEATURE_COLUMNS},
    }


def test_inference_rejects_window_size_different_from_training():
    bundle = WindowsModelBundle(
        model=FixedModel(),
        model_version="unit-test",
        classes=["Benign", "Malicious"],
        severity_mapping={"Benign": "Low", "Malicious": "High"},
        window_seconds=60,
    )
    with pytest.raises(ValueError, match="does not match the model's 60-second"):
        predict_snapshots(bundle, [sample_snapshot(window_seconds=30)])
