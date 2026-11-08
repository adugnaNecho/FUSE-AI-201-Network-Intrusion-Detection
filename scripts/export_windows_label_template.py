#!/usr/bin/env python3
"""Flatten Windows feature snapshots into an auditable, initially-unlabelled CSV."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from windows_nids.schema import FEATURE_COLUMNS, validate_snapshot


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="windows_feature_stream.jsonl")
    parser.add_argument("--output", type=Path, required=True, help="New CSV template path")
    parser.add_argument("--session-id", required=True, help="Unique ID for this independent capture session")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing output CSV")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.session_id.strip() or len(args.session_id) > 128:
        print("--session-id must contain 1–128 non-whitespace characters.", file=sys.stderr)
        return 2
    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 2
    if args.output.exists() and not args.overwrite:
        print(f"Output already exists (use --overwrite to replace): {args.output}", file=sys.stderr)
        return 2

    columns = [
        "snapshot_id", "session_id", "label", "label_source", "source_id",
        "window_start_utc", "window_end_utc", "window_seconds",
        "process_name", "process_instance_id", *FEATURE_COLUMNS,
    ]
    rows: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    malformed = 0
    with args.input.open("r", encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                snapshot = validate_snapshot(json.loads(line))
                snapshot_id = snapshot["snapshot_id"]
                if snapshot_id in seen_ids:
                    continue
                seen_ids.add(snapshot_id)
                row = {
                    "snapshot_id": snapshot_id,
                    "session_id": args.session_id.strip(),
                    "label": "",
                    "label_source": "",
                    "source_id": snapshot["source_id"],
                    "window_start_utc": snapshot["window_start_utc"],
                    "window_end_utc": snapshot["window_end_utc"],
                    "window_seconds": snapshot["window_seconds"],
                    "process_name": snapshot["process_name"],
                    "process_instance_id": snapshot["process_instance_id"],
                    **snapshot["features"],
                }
                rows.append(row)
            except (json.JSONDecodeError, ValueError, KeyError, TypeError):
                malformed += 1

    if not rows:
        print("No valid, unique Windows feature snapshots were found.", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Exported {len(rows)} unique snapshots to {args.output}")
    print(f"Session ID: {args.session_id}; malformed/skipped rows: {malformed}")
    print("Labels are intentionally blank. Add independently verified 'label' and 'label_source' values before training.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
