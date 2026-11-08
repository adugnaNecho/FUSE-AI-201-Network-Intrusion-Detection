import csv
import io
import zipfile

import pytest

from scripts.inspect_sysmon_dataset import inspect_stream, open_csv_member


RAW_HEADER = (
    "EventID,UtcTime,ProcessGuid,ProcessId,Image,Protocol,DestinationIp,"
    "DestinationPort,Initiated,QueryName,Label,SessionId\n"
)
RAW_ROWS = (
    "3,2026-01-01 00:00:00.000,{guid-1},100,browser.exe,tcp,203.0.113.10,443,true,,0,good-run-01\n"
    "22,2026-01-01 00:00:05.000,{guid-1},100,browser.exe,,,,,example.test,0,good-run-01\n"
)


def test_raw_sysmon_rows_are_flagged_as_candidate_only_when_required_fields_exist():
    report = inspect_stream(io.StringIO(RAW_HEADER + RAW_ROWS), "raw.csv")

    assert report["row_count"] == 2
    assert report["event_id_counts"] == {"3": 1, "22": 1}
    assert report["label_counts"] == {"0": 2}
    assert report["has_explicit_session_group"] is True
    assert report["distinct_session_ids"] == 1
    assert report["compatible_for_19_feature_window_reconstruction"] is True
    assert "Candidate" in report["interpretation"]


def test_fasttext_numeric_matrix_is_not_mistaken_for_raw_sysmon_events():
    header = ",".join([f"feature_{i}" for i in range(100)] + ["label"])
    row = ",".join(["0.1"] * 100 + ["1"])
    report = inspect_stream(io.StringIO(header + "\n" + row + "\n"), "vectors.csv")

    assert report["compatible_for_19_feature_window_reconstruction"] is False
    assert any("embeddings" in reason for reason in report["reasons_not_compatible"])


def test_event_csv_without_capture_id_is_not_group_split_compatible():
    header = RAW_HEADER.replace(",SessionId", "")
    rows = RAW_ROWS.replace(",good-run-01", "")
    report = inspect_stream(io.StringIO(header + rows), "no_session.csv")

    assert report["has_explicit_session_group"] is False
    assert report["compatible_for_19_feature_window_reconstruction"] is False
    assert any("session identifier" in reason for reason in report["reasons_not_compatible"])


def test_zip_with_multiple_csvs_requires_explicit_member_name(tmp_path):
    archive_path = tmp_path / "dataset.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("train.csv", RAW_HEADER + RAW_ROWS)
        archive.writestr("test.csv", RAW_HEADER + RAW_ROWS)

    with pytest.raises(ValueError, match="multiple CSV files"):
        open_csv_member(archive_path, None)

    stream, name, archive = open_csv_member(archive_path, "train.csv")
    try:
        report = inspect_stream(stream, name)
    finally:
        stream.close()
        archive.close()

    assert name == "train.csv"
    assert report["row_count"] == 2


def test_session_column_must_be_populated():
    text = RAW_HEADER + RAW_ROWS.replace("good-run-01", "")
    report = inspect_stream(io.StringIO(text), "blank_session.csv")

    assert report["has_explicit_session_group"] is False
