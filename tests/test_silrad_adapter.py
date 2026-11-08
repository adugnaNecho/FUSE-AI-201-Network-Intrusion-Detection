from datetime import datetime, timedelta, timezone

import pytest

from windows_nids.schema import FEATURE_COLUMNS
from windows_nids.silrad_adapter import build_labelled_windows, map_source_label


HEADERS = [
    "EventID", "UtcTime", "ProcessGuid", "ProcessId", "Image", "Protocol",
    "DestinationIp", "DestinationPort", "Initiated", "QueryName", "Label", "SessionId",
]


def event_row(event_id, when, label, session="capture-A", protocol="tcp"):
    return {
        "EventID": str(event_id),
        "UtcTime": when.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "ProcessGuid": "{same-process-guid}",
        "ProcessId": "100",
        "Image": r"C:\Program Files\Browser\browser.exe",
        "Protocol": protocol if event_id == 3 else "",
        "DestinationIp": "8.8.8.8" if event_id == 3 else "",
        "DestinationPort": "443" if event_id == 3 else "",
        "Initiated": "true" if event_id == 3 and protocol == "tcp" else "",
        "QueryName": "example.test" if event_id == 22 else "",
        "Label": str(label),
        "SessionId": session,
    }


def base_time():
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_maps_only_documented_goodware_ransomware_labels():
    assert map_source_label("0") == "Benign"
    assert map_source_label("Goodware") == "Benign"
    assert map_source_label("1") == "Malicious"
    assert map_source_label("Ransomware") == "Malicious"
    with pytest.raises(ValueError, match="Unknown source label"):
        map_source_label("unknown")


def test_builds_19_feature_windows_from_labelled_raw_events():
    start = base_time()
    rows = [
        event_row(3, start, 0),
        event_row(22, start + timedelta(seconds=20), 0),
        event_row(3, start + timedelta(seconds=70), 0),
    ]

    windows, stats = build_labelled_windows(
        rows, HEADERS, source_name="SILRAD synthetic unit fixture"
    )

    assert len(windows) == 2
    assert all(window["label"] == "Benign" for window in windows)
    assert all(window["window_seconds"] == 60 for window in windows)
    assert all(set(FEATURE_COLUMNS).issubset(window) for window in windows)
    assert windows[0]["features"] if "features" in windows[0] else True
    assert windows[0]["network_connect_event_count"] == 1
    assert windows[0]["tcp_event_count"] == 1
    assert windows[0]["dns_query_event_count"] == 1
    assert windows[0]["unique_dns_query_count"] == 1
    assert stats["eligible_event_rows"] == 3
    assert stats["windows_written"] == 2


def test_conflicting_event_labels_exclude_the_ambiguous_window():
    start = base_time()
    rows = [
        event_row(3, start, 0),
        event_row(22, start + timedelta(seconds=20), 1),
        event_row(3, start + timedelta(seconds=70), 1),
    ]

    windows, stats = build_labelled_windows(
        rows, HEADERS, source_name="SILRAD synthetic unit fixture"
    )

    assert stats["ambiguous_windows_excluded"] == 1
    assert len(windows) == 1
    assert windows[0]["label"] == "Malicious"


def test_sessions_produce_distinct_process_instance_ids():
    start = base_time()
    rows = [
        event_row(3, start, 0, session="capture-A"),
        event_row(22, start + timedelta(seconds=20), 0, session="capture-A"),
        event_row(3, start + timedelta(seconds=70), 0, session="capture-A"),
        event_row(3, start, 1, session="capture-B"),
        event_row(22, start + timedelta(seconds=20), 1, session="capture-B"),
        event_row(3, start + timedelta(seconds=70), 1, session="capture-B"),
    ]

    windows, stats = build_labelled_windows(
        rows, HEADERS, source_name="SILRAD synthetic unit fixture"
    )

    assert {window["session_id"] for window in windows} == {"capture-A", "capture-B"}
    assert len({window["process_instance_id"] for window in windows}) == 2
    assert {window["label"] for window in windows} == {"Benign", "Malicious"}


def test_missing_session_or_process_fields_block_conversion():
    start = base_time()
    rows = [event_row(3, start, 0)]

    with pytest.raises(ValueError, match="Missing source fields"):
        build_labelled_windows(
            rows,
            [header for header in HEADERS if header != "SessionId"],
            source_name="fixture",
        )


def test_invalid_network_protocol_is_rejected():
    start = base_time()
    row = event_row(3, start, 0, protocol="icmp")
    row["UtcTime"] = (start + timedelta(seconds=70)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    with pytest.raises(ValueError, match="supported TCP/UDP Protocol"):
        build_labelled_windows([row], HEADERS, source_name="fixture")
