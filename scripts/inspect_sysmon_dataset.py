#!/usr/bin/env python3
"""Audit a Sysmon research CSV/ZIP before attempting Windows feature conversion.

This utility is intentionally an inspector, not a label generator. It never
assumes an event label can be assigned to an aggregated process window.
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
import json
from pathlib import Path
import re
import sys
import zipfile
from typing import Any, TextIO


ALIASES = {
    "event_id": ("eventid", "event_id", "event id", "id"),
    "timestamp": ("utctime", "timestamp", "eventtime", "event_time", "timecreated", "time_created"),
    "process_guid": ("processguid", "process_guid", "process guid"),
    "process_id": ("processid", "process_id", "process id", "pid"),
    "image": ("image", "processimage", "process_image", "process name", "processname"),
    "protocol": ("protocol", "networkprotocol"),
    "destination_ip": ("destinationip", "destination_ip", "destination ip", "dest_ip"),
    "destination_port": ("destinationport", "destination_port", "destination port", "dest_port"),
    "initiated": ("initiated", "connectioninitiated"),
    "query_name": ("queryname", "query_name", "dnsquery", "dns_query"),
    "label": ("label", "class", "target", "is_malicious", "malicious", "groundtruth"),
    "session_id": ("session_id", "sessionid", "capture_id", "captureid", "run_id", "runid",
                   "execution_id", "executionid", "sample_id", "sampleid", "vm_id", "vmid"),
}

NETWORK_FIELDS = ("event_id", "timestamp", "image", "protocol", "destination_ip", "destination_port")
DNS_FIELDS = ("event_id", "timestamp", "image", "query_name")
PROCESS_IDENTITY_FIELDS = ("process_guid",)  # or the pair process_id + image


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def map_columns(headers: list[str]) -> dict[str, str | None]:
    normalized: dict[str, str] = {}
    for header in headers:
        normalized.setdefault(normalize_name(header), header)

    result: dict[str, str | None] = {}
    for field, aliases in ALIASES.items():
        candidates = {normalize_name(alias) for alias in aliases}
        result[field] = next((normalized[key] for key in candidates if key in normalized), None)
    return result


def open_csv_member(path: Path, member_name: str | None) -> tuple[TextIO, str, zipfile.ZipFile | None]:
    """Open a plain CSV or a selected CSV member in a ZIP, preserving UTF-8 BOM handling."""
    if path.suffix.lower() != ".zip":
        if member_name:
            raise ValueError("--csv-name is only valid when --input is a ZIP archive.")
        return path.open("r", encoding="utf-8-sig", newline=""), path.name, None

    archive = zipfile.ZipFile(path)
    csv_names = [name for name in archive.namelist() if name.lower().endswith(".csv") and not name.endswith("/")]
    if not csv_names:
        archive.close()
        raise ValueError("ZIP archive contains no CSV files.")
    if member_name:
        matches = [name for name in csv_names if name == member_name or Path(name).name == member_name]
        if len(matches) != 1:
            archive.close()
            raise ValueError(f"--csv-name must match exactly one CSV member; found {len(matches)} matches.")
        selected = matches[0]
    elif len(csv_names) == 1:
        selected = csv_names[0]
    else:
        archive.close()
        listing = ", ".join(csv_names)
        raise ValueError(
            "ZIP contains multiple CSV files. Run once per file with --csv-name. "
            f"Available files: {listing}"
        )
    raw = archive.open(selected, "r")
    import io
    text_stream = io.TextIOWrapper(raw, encoding="utf-8-sig", newline="")
    return text_stream, selected, archive


def inspect_stream(stream: TextIO, name: str) -> dict[str, Any]:
    reader = csv.DictReader(stream)
    headers = list(reader.fieldnames or [])
    if not headers:
        raise ValueError(f"{name}: CSV has no header row.")

    mapping = map_columns(headers)
    label_counts: Counter[str] = Counter()
    event_counts: Counter[str] = Counter()
    rows = 0
    rows_with_label = 0
    rows_with_timestamp = 0
    rows_with_process_guid = 0
    rows_with_process_id_and_image = 0
    rows_with_network_fields = 0
    rows_with_dns_fields = 0
    rows_with_session_id = 0
    session_values: set[str] = set()
    numeric_header_count = sum(
        1 for h in headers if re.fullmatch(r"(?:feature[_ -]?)?\d+", h.strip(), flags=re.I)
    )

    for row in reader:
        rows += 1
        label_column = mapping["label"]
        if label_column and row.get(label_column, "").strip():
            label_counts[row[label_column].strip()] += 1
            rows_with_label += 1

        event_column = mapping["event_id"]
        event_id = row.get(event_column, "").strip() if event_column else ""
        if event_id:
            event_counts[event_id] += 1

        if mapping["timestamp"] and row.get(mapping["timestamp"], "").strip():
            rows_with_timestamp += 1
        if mapping["process_guid"] and row.get(mapping["process_guid"], "").strip():
            rows_with_process_guid += 1
        if (
            mapping["process_id"] and mapping["image"]
            and row.get(mapping["process_id"], "").strip()
            and row.get(mapping["image"], "").strip()
        ):
            rows_with_process_id_and_image += 1

        if event_id in {"3", "3.0"} and mapping.get("protocol") and row.get(mapping["protocol"], "").strip():
            rows_with_network_fields += 1
        if event_id in {"22", "22.0"} and mapping.get("query_name"):
            rows_with_dns_fields += 1
        session_column = mapping["session_id"]
        if session_column and row.get(session_column, "").strip():
            rows_with_session_id += 1
            session_values.add(row[session_column].strip())

    event_ids = {str(value).strip() for value in event_counts}
    has_event_3 = bool(event_ids.intersection({"3", "3.0"}))
    has_event_22 = bool(event_ids.intersection({"22", "22.0"}))
    has_time = rows_with_timestamp > 0
    has_identity = rows_with_process_guid > 0 or rows_with_process_id_and_image > 0
    has_labels = rows_with_label > 0
    has_event_specific_fields = (
        all(mapping.get(field) for field in ("protocol", "destination_ip", "destination_port", "query_name"))
        and rows_with_network_fields > 0
        and rows_with_dns_fields > 0
    )
    has_group = rows_with_session_id > 0

    reasons: list[str] = []
    if not has_labels:
        reasons.append("No populated event-level label column was identified.")
    if not has_time:
        reasons.append("No populated event timestamp column was identified.")
    if not has_identity:
        reasons.append("No populated ProcessGuid or ProcessId+Image identity was identified.")
    if not has_event_3:
        reasons.append("No Event ID 3 rows were identified in the event-id column.")
    if not has_event_22:
        reasons.append("No Event ID 22 rows were identified in the event-id column.")
    if not has_event_specific_fields:
        reasons.append("Raw Event 3 network fields and Event 22 DNS fields are not both available.")
    if not has_group:
        reasons.append("No explicit capture/session/run identifier was identified for leakage-resistant grouping.")
    if numeric_header_count >= 20 and not any(mapping[field] for field in ("event_id", "timestamp", "process_guid", "image")):
        reasons.append(
            "The CSV looks like a numeric feature/embedding matrix, not raw Sysmon events; "
            "the 19 live features cannot be reconstructed from embeddings."
        )

    compatible = (
        has_labels and has_time and has_identity and has_event_3 and has_event_22
        and has_event_specific_fields and has_group
    )

    return {
        "file": name,
        "row_count": rows,
        "column_count": len(headers),
        "columns": headers,
        "mapped_columns": mapping,
        "event_id_counts": dict(event_counts.most_common()),
        "label_counts": dict(label_counts.most_common()),
        "rows_with_timestamp": rows_with_timestamp,
        "rows_with_process_guid": rows_with_process_guid,
        "rows_with_process_id_and_image": rows_with_process_id_and_image,
        "rows_with_event3_network_fields": rows_with_network_fields,
        "rows_with_event22_dns_fields": rows_with_dns_fields,
        "rows_with_session_id": rows_with_session_id,
        "distinct_session_ids": len(session_values),
        "numeric_feature_like_headers": numeric_header_count,
        "has_explicit_session_group": has_group,
        "compatible_for_19_feature_window_reconstruction": compatible,
        "reasons_not_compatible": reasons,
        "interpretation": (
            "Candidate for a carefully labelled window adapter; inspect label semantics and timestamp/session meaning first."
            if compatible else
            "Not directly convertible to the 19-feature 60-second process-window schema from the identified columns."
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="SILRAD ZIP archive or an extracted CSV file.")
    parser.add_argument("--csv-name", default=None, help="Exact CSV member name when ZIP contains multiple CSVs.")
    parser.add_argument("--report", type=Path, default=None, help="Optional JSON audit report path.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 2

    archive = None
    try:
        stream, member_name, archive = open_csv_member(args.input, args.csv_name)
        try:
            report = inspect_stream(stream, member_name)
        finally:
            stream.close()
            if archive is not None:
                archive.close()
    except (OSError, ValueError, zipfile.BadZipFile, csv.Error) as exc:
        print(f"Dataset inspection failed: {exc}", file=sys.stderr)
        return 2

    print(f"File: {report['file']}")
    print(f"Rows: {report['row_count']:,}; columns: {report['column_count']}")
    print("\nColumns:")
    for column in report["columns"]:
        print(f"  - {column}")

    print("\nMapped fields:")
    for key, value in report["mapped_columns"].items():
        print(f"  {key}: {value or 'NOT FOUND'}")

    print("\nEvent ID counts:")
    for key, value in report["event_id_counts"].items():
        print(f"  {key}: {value:,}")

    print("\nLabel counts:")
    for key, value in report["label_counts"].items():
        print(f"  {key}: {value:,}")

    print("\n19-feature window compatibility:",
          "YES" if report["compatible_for_19_feature_window_reconstruction"] else "NO")
    for reason in report["reasons_not_compatible"]:
        print(f"  - {reason}")
    print(report["interpretation"])

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nJSON report written: {args.report}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
