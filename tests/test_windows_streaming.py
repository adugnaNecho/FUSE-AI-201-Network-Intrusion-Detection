from datetime import datetime, timezone

import numpy as np
import pytest

from windows_nids.inference import WindowsModelBundle, predict_snapshots
from windows_nids.schema import FEATURE_COLUMNS, SCHEMA_VERSION, validate_feature_vector, validate_snapshot
from windows_nids.streaming import RollingWindowAggregator


def stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def event(event_id, record_id, ts, process_guid="{proc-a}", image=r"C:\Program Files\Browser\browser.exe", **fields):
    base = {"ProcessGuid": process_guid, "ProcessId": "2000", "Image": image}
    base.update(fields)
    return {"event_id": event_id, "record_id": record_id, "event_time_utc": ts, "fields": base}


def test_rolling_snapshot_aggregates_connection_dns_and_process_metadata():
    aggregator = RollingWindowAggregator("test-pc", window_seconds=60)
    aggregator.ingest_record(event(3, 1, "2026-11-08 09:10:05.000", Protocol="tcp", Initiated="true",
                                   DestinationIp="8.8.8.8", DestinationPort="443"))
    aggregator.ingest_record(event(3, 2, "2026-11-08 09:10:15.000", Protocol="udp", Initiated="false",
                                   DestinationIp="192.168.1.1", DestinationPort="53"))
    aggregator.ingest_record(event(22, 3, "2026-11-08 09:10:20.000", QueryName="example.test"))
    aggregator.ingest_record(event(22, 4, "2026-11-08 09:10:21.000", process_guid="{sysmon}",
                                   image=r"C:\Sysmon\Sysmon64.exe", QueryName="sysmon.internal"))
    snapshots = aggregator.snapshot(stamp("2026-11-08T09:10:30Z"))
    assert len(snapshots) == 1
    snapshot = validate_snapshot(snapshots[0])
    assert snapshot["schema_version"] == SCHEMA_VERSION
    assert snapshot["process_name"] == "browser.exe"
    assert snapshot["features"]["network_connect_event_count"] == 2
    assert snapshot["features"]["tcp_event_count"] == 1
    assert snapshot["features"]["udp_event_count"] == 1
    assert snapshot["features"]["tcp_initiated_true_count"] == 1
    assert snapshot["features"]["tcp_initiated_false_count"] == 0
    assert snapshot["features"]["global_destination_event_count"] == 1
    assert snapshot["features"]["private_destination_event_count"] == 1
    assert snapshot["features"]["destination_port_443_count"] == 1
    assert snapshot["features"]["destination_port_53_count"] == 1
    assert snapshot["features"]["dns_query_event_count"] == 1
    assert snapshot["features"]["unique_dns_query_count"] == 1
    assert len(snapshot["process_instance_id"]) == 20


def test_rolling_window_expires_old_events():
    aggregator = RollingWindowAggregator("test-pc", window_seconds=60)
    aggregator.ingest_record(event(3, 1, "2026-11-08 09:10:00.000", Protocol="tcp", Initiated="true",
                                   DestinationIp="8.8.8.8", DestinationPort="443"))
    aggregator.ingest_record(event(3, 2, "2026-11-08 09:10:30.000", Protocol="udp", Initiated="false",
                                   DestinationIp="8.8.4.4", DestinationPort="443"))
    snapshots = aggregator.snapshot(stamp("2026-11-08T09:11:10Z"))
    assert len(snapshots) == 1
    features = snapshots[0]["features"]
    assert features["network_connect_event_count"] == 1
    assert features["udp_event_count"] == 1
    assert features["tcp_event_count"] == 0


def test_unknown_and_malformed_records_are_counted():
    aggregator = RollingWindowAggregator("test-pc")
    assert not aggregator.ingest_line("not-json")
    assert not aggregator.ingest_record({"event_id": 1, "fields": {}})
    assert aggregator.malformed_lines == 1
    assert aggregator.filtered_events == 1


def test_feature_schema_rejects_inconsistent_transport_counts():
    features = {name: 0 for name in FEATURE_COLUMNS}
    features["network_connect_event_count"] = 2
    features["tcp_event_count"] = 1
    with pytest.raises(ValueError, match=r"TCP \+ UDP"):
        validate_feature_vector(features)


class DummyWindowsModel:
    classes_ = np.array(["Benign", "Suspicious"])

    def predict(self, frame):
        assert list(frame.columns) == FEATURE_COLUMNS
        return np.array(["Benign"] * len(frame))

    def predict_proba(self, frame):
        return np.tile([0.9, 0.1], (len(frame), 1))


def test_local_inference_contract_returns_predictions_without_ground_truth():
    aggregator = RollingWindowAggregator("test-pc")
    aggregator.ingest_record(event(3, 1, "2026-11-08 09:10:05.000", Protocol="tcp", Initiated="true",
                                   DestinationIp="8.8.8.8", DestinationPort="443"))
    snapshot = aggregator.snapshot(stamp("2026-11-08T09:10:20Z"))[0]
    bundle = WindowsModelBundle(
        model=DummyWindowsModel(),
        model_version="test-only",
        classes=["Benign", "Suspicious"],
        severity_mapping={"Benign": "Low", "Suspicious": "Review"},
    )
    prediction = predict_snapshots(bundle, [snapshot])[0]
    assert prediction["predicted_class"] == "Benign"
    assert prediction["confidence"] == pytest.approx(0.9)
    assert prediction["severity"] == "Low"
    assert prediction["ground_truth_available"] is False
