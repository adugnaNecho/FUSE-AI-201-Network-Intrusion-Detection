#!/usr/bin/env python3
"""Replay a pre-collected Sysmon JSONL session into the Windows 19-feature schema."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from windows_nids.streaming import RollingWindowAggregator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Pre-collected Sysmon JSONL event file")
    parser.add_argument("--output", type=Path, required=True, help="New JSONL feature-snapshot file")
    parser.add_argument("--source-id", default="windows-pc-01")
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--step-seconds", type=int, default=10)
    parser.add_argument("--include-sysmon", action="store_true", help="Include Sysmon's own events (not recommended)")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing feature file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.window_seconds <= 0 or args.step_seconds <= 0 or args.step_seconds > args.window_seconds:
        print("Window and step must be positive, and step must not exceed window.", file=sys.stderr)
        return 2
    if not args.input.is_file():
        print(f"Sysmon input file not found: {args.input}", file=sys.stderr)
        return 2
    if args.output.exists() and not args.overwrite:
        print(f"Output exists (use --overwrite to replace): {args.output}", file=sys.stderr)
        return 2

    aggregator = RollingWindowAggregator(
        args.source_id,
        window_seconds=args.window_seconds,
        exclude_self=not args.include_sysmon,
    )
    try:
        with args.input.open("r", encoding="utf-8-sig") as source:
            for line in source:
                aggregator.ingest_line(line)
    except OSError as exc:
        print(f"Could not read Sysmon input: {exc}", file=sys.stderr)
        return 1

    if not aggregator._events:
        print("No valid, eligible Sysmon Event ID 3/22 records found.", file=sys.stderr)
        return 2

    first_event = min(event.event_time for event in aggregator._events)
    last_event = max(event.event_time for event in aggregator._events)
    first_end = math.ceil((first_event.timestamp() + args.window_seconds) / args.step_seconds) * args.step_seconds
    last_end = math.ceil(last_event.timestamp() / args.step_seconds) * args.step_seconds
    if first_end > last_end:
        print("The capture is shorter than one complete rolling window; no snapshots were emitted.", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    snapshots_written = 0
    try:
        with args.output.open("w", encoding="utf-8", newline="\n") as target:
            for epoch in range(first_end, last_end + 1, args.step_seconds):
                end = datetime.fromtimestamp(epoch, tz=timezone.utc)
                snapshots = aggregator.snapshot(as_of=end)
                for snapshot in snapshots:
                    target.write(json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False) + "\n")
                    snapshots_written += 1
    except OSError as exc:
        print(f"Could not write feature snapshots: {exc}", file=sys.stderr)
        return 1

    print(f"Input events: {aggregator.total_lines}; accepted: {aggregator.accepted_events}; "
          f"filtered: {aggregator.filtered_events}; malformed: {aggregator.malformed_lines}")
    print(f"Feature snapshots written: {snapshots_written} -> {args.output}")
    print("This conversion does not create labels; label each capture session only from independent ground truth.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
