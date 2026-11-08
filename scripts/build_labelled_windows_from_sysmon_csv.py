#!/usr/bin/env python3
"""Convert raw, event-labelled Sysmon CSV rows to 60-second process windows.

The converter supports CSV files directly or a selected CSV member in a ZIP.
It does not consume fastText embedding matrices or infer labels from features.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.inspect_sysmon_dataset import open_csv_member
from windows_nids.schema import FEATURE_COLUMNS
from windows_nids.silrad_adapter import build_labelled_windows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Raw Sysmon CSV file or ZIP archive.")
    parser.add_argument("--csv-name", default=None, help="CSV member name when the ZIP contains multiple CSVs.")
    parser.add_argument("--output", type=Path, required=True, help="New labelled Windows feature CSV.")
    parser.add_argument("--report", type=Path, default=None, help="Optional JSON conversion report.")
    parser.add_argument("--source-id", default="silrad-public")
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--step-seconds", type=int, default=10)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 2
    if args.output.exists() and not args.overwrite:
        print(f"Output exists (use --overwrite to replace): {args.output}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", args.source_id):
        print("--source-id must use 1–64 letters, numbers, dot, underscore, colon or hyphen.", file=sys.stderr)
        return 2

    archive = None
    try:
        stream, member_name, archive = open_csv_member(args.input, args.csv_name)
        try:
            reader = csv.DictReader(stream)
            headers = list(reader.fieldnames or [])
            if not headers:
                raise ValueError("Selected CSV has no header row.")
            rows, stats = build_labelled_windows(
                reader,
                headers,
                source_name=f"SILRAD source file {member_name}",
                source_id=args.source_id,
                window_seconds=args.window_seconds,
                step_seconds=args.step_seconds,
            )
        finally:
            stream.close()
            if archive is not None:
                archive.close()
    except (OSError, ValueError, zipfile.BadZipFile, csv.Error) as exc:
        print(f"Window conversion stopped: {exc}", file=sys.stderr)
        return 2

    if not rows:
        print(
            "No unambiguous labelled process windows were produced. "
            f"Ambiguous windows excluded: {stats['ambiguous_windows_excluded']}. "
            "Do not force majority labels; inspect the source schema and label alignment.",
            file=sys.stderr,
        )
        return 2

    columns = [
        "snapshot_id", "session_id", "label", "label_source", "source_id",
        "window_start_utc", "window_end_utc", "window_seconds",
        "process_name", "process_instance_id", *FEATURE_COLUMNS,
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8-sig", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    label_counts: dict[str, int] = {}
    for row in rows:
        label_counts[row["label"]] = label_counts.get(row["label"], 0) + 1

    report = {
        "source_file": member_name,
        "source_dataset": "SILRAD Sysmon ransomware research dataset",
        "label_mapping": {"0": "Benign (Goodware)", "1": "Malicious (Ransomware)"},
        "window_seconds": args.window_seconds,
        "step_seconds": args.step_seconds,
        "labelled_windows": len(rows),
        "class_counts": label_counts,
        **stats,
        "output": str(args.output),
        "note": (
            "Only Event ID 3/22 process windows with unanimous event labels were retained. "
            "Mixed-label windows were excluded; labels were not inferred from feature values."
        ),
    }

    print(f"Source CSV: {member_name}")
    print(f"Labelled windows written: {len(rows):,} -> {args.output}")
    print(f"Class counts: {label_counts}")
    for key, value in stats.items():
        print(f"{key}: {value:,}")
    print(report["note"])

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"JSON report written: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
