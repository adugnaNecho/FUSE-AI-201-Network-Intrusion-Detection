import json
from pathlib import Path

from scripts.build_windows_features_offline import main


def test_offline_replay_uses_event_time_and_emits_the_current_schema(tmp_path, monkeypatch):
    source = tmp_path / "events.jsonl"
    output = tmp_path / "features.jsonl"
    records = [
        {
            "event_id": 3,
            "record_id": 1,
            "fields": {
                "UtcTime": "2026-11-08 10:00:10.000",
                "Image": "C:\\Windows\\System32\\browser.exe",
                "ProcessGuid": "{process-guid-1}",
                "ProcessId": "1000",
                "Protocol": "tcp",
                "Initiated": "true",
                "DestinationIp": "8.8.8.8",
                "DestinationPort": "443",
            },
        },
        {
            "event_id": 3,
            "record_id": 2,
            "fields": {
                "UtcTime": "2026-11-08 10:01:05.000",
                "Image": "C:\\Windows\\System32\\browser.exe",
                "ProcessGuid": "{process-guid-1}",
                "ProcessId": "1000",
                "Protocol": "udp",
                "Initiated": "false",
                "DestinationIp": "8.8.4.4",
                "DestinationPort": "53",
            },
        },
    ]
    source.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
    argv = [
        "build_windows_features_offline.py", "--input", str(source), "--output", str(output),
        "--source-id", "test-pc", "--window-seconds", "60", "--step-seconds", "10",
    ]
    monkeypatch.setattr("sys.argv", argv)

    assert main() == 0
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert rows[0]["window_seconds"] == 60
    assert rows[0]["window_end_utc"] == "2026-11-08T10:01:10Z"
    assert rows[0]["features"]["network_connect_event_count"] == 2
    assert rows[0]["features"]["tcp_event_count"] == 1
    assert rows[0]["features"]["udp_event_count"] == 1
    assert rows[0]["features"]["tcp_initiated_true_count"] == 1
    assert rows[0]["features"]["tcp_initiated_false_count"] == 0
