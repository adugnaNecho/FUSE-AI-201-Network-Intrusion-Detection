#!/usr/bin/env python3
"""Tail Sysmon JSONL, emit rolling feature snapshots, and optionally run inference."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from windows_nids.api_client import send_snapshots
from windows_nids.inference import load_windows_model, predict_snapshots
from windows_nids.streaming import RollingWindowAggregator


def append_jsonl(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n")
        stream.flush()


def next_boundary(now_epoch: float, step_seconds: int) -> int:
    return (int(now_epoch // step_seconds) + 1) * step_seconds


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path(r"D:\FUSE AI 201\Sysmon\data\sysmon_events.jsonl"))
    parser.add_argument("--features-output", type=Path, default=Path(r"D:\FUSE AI 201\Sysmon\data\windows_feature_stream.jsonl"))
    parser.add_argument("--predictions-output", type=Path, default=Path(r"D:\FUSE AI 201\Sysmon\data\windows_predictions.jsonl"))
    parser.add_argument("--source-id", default="windows-pc-01")
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--step-seconds", type=int, default=10)
    parser.add_argument("--poll-seconds", type=float, default=0.5)
    parser.add_argument("--replay-existing", action="store_true", help="Read existing JSONL before following new lines.")
    parser.add_argument("--include-sysmon", action="store_true", help="Include Sysmon's own process events (not recommended).")
    parser.add_argument("--model", type=Path, default=None, help="Trusted Windows-specific joblib model artifact.")
    parser.add_argument("--metadata", type=Path, default=None, help="JSON metadata matching the Windows feature schema.")
    parser.add_argument("--api-url", default=os.getenv("WINDOWS_PREDICTION_API_URL", ""), help="Optional HTTPS base URL for FastAPI /windows/predict.")
    parser.add_argument("--api-token", default=os.getenv("WINDOWS_INGEST_API_TOKEN", os.getenv("LIVE_INGEST_API_TOKEN", "")), help="Optional API token; prefer setting it in the environment.")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", args.source_id):
        parser.error("--source-id must use 1–64 letters, numbers, dot, underscore, colon, or hyphen.")
    if args.window_seconds <= 0 or args.step_seconds <= 0 or args.step_seconds > args.window_seconds:
        parser.error("Window and step durations must be positive, and step must not exceed window.")
    if args.poll_seconds <= 0:
        parser.error("--poll-seconds must be positive.")
    if bool(args.model) != bool(args.metadata):
        parser.error("Supply both --model and --metadata, or neither.")
    if args.api_url and not args.api_token:
        parser.error("Set WINDOWS_INGEST_API_TOKEN or pass --api-token when --api-url is used.")
    if args.api_url and args.model:
        parser.error("Choose either local model inference or API inference, not both.")
    return args


def main() -> int:
    args = parse_args()
    if not args.input.is_file():
        print(f"Input JSONL file not found: {args.input}", file=sys.stderr)
        print("Start collect_sysmon.ps1 first and verify its output path.", file=sys.stderr)
        return 2

    bundle = None
    if args.api_url:
        print(f"Remote Windows inference enabled: {args.api_url.rstrip('/')}/windows/predict")
    elif args.model and args.metadata:
        try:
            bundle = load_windows_model(args.model, args.metadata)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Windows model could not be loaded: {exc}", file=sys.stderr)
            return 2
        print(f"Loaded Windows model: {bundle.model_version}; classes={bundle.classes}")
    else:
        env_model = os.getenv("WINDOWS_MODEL_PATH")
        env_metadata = os.getenv("WINDOWS_MODEL_METADATA_PATH")
        if env_model and env_metadata:
            try:
                bundle = load_windows_model(env_model, env_metadata)
            except (FileNotFoundError, ValueError) as exc:
                print(f"Windows model environment is configured but invalid: {exc}", file=sys.stderr)
                return 2
            print(f"Loaded Windows model: {bundle.model_version}; classes={bundle.classes}")
        else:
            print("No trained Windows model or remote inference API configured: feature snapshots only; ML predictions are disabled.")

    aggregator = RollingWindowAggregator(args.source_id, args.window_seconds, exclude_self=not args.include_sysmon)
    args.features_output.parent.mkdir(parents=True, exist_ok=True)
    if not args.replay_existing:
        print("Starting at end of existing input file; historical rows will not be replayed.")
    print(f"Following: {args.input}")
    print(f"Feature stream: {args.features_output}")
    if bundle or args.api_url:
        print(f"Prediction stream: {args.predictions_output}")
    print(f"Rolling window: {args.window_seconds}s; snapshot cadence: {args.step_seconds}s; Ctrl+C to stop.")

    try:
        with args.input.open("r", encoding="utf-8-sig", newline="") as source:
            if not args.replay_existing:
                source.seek(0, os.SEEK_END)
            next_emit = next_boundary(time.time(), args.step_seconds)
            while True:
                line = source.readline()
                if line:
                    aggregator.ingest_line(line)
                now_epoch = time.time()
                if now_epoch >= next_emit:
                    emit_at = datetime.fromtimestamp(next_emit, tz=timezone.utc)
                    snapshots = aggregator.snapshot(as_of=emit_at)
                    append_jsonl(args.features_output, snapshots)
                    predictions = []
                    if snapshots and bundle:
                        try:
                            predictions = predict_snapshots(bundle, snapshots)
                            append_jsonl(args.predictions_output, predictions)
                        except (ValueError, TypeError) as exc:
                            print(f"Local inference rejected a snapshot batch: {exc}", file=sys.stderr)
                    elif snapshots and args.api_url:
                        try:
                            predictions = send_snapshots(args.api_url, args.api_token, args.source_id, snapshots)
                            append_jsonl(args.predictions_output, predictions)
                        except (RuntimeError, ValueError) as exc:
                            print(f"Remote inference unavailable; feature snapshots retained locally: {exc}", file=sys.stderr)
                    if snapshots:
                        print(
                            f"{emit_at.isoformat()} | snapshots={len(snapshots)} "
                            f"| buffered_events={aggregator.buffered_event_count} "
                            f"| predictions={len(predictions)}"
                        )
                    next_emit = next_boundary(now_epoch, args.step_seconds)
                elif not line:
                    time.sleep(args.poll_seconds)
                try:
                    current_size = args.input.stat().st_size
                    if current_size < source.tell():
                        print("Input file was truncated; restarting tail position.", file=sys.stderr)
                        source.seek(0)
                except OSError:
                    pass
    except KeyboardInterrupt:
        print("\nWindows stream processor stopped.")
    except OSError as exc:
        print(f"Could not read Sysmon JSONL input: {exc}", file=sys.stderr)
        return 1

    print(
        "Summary: "
        f"lines={aggregator.total_lines}, accepted={aggregator.accepted_events}, "
        f"filtered={aggregator.filtered_events}, malformed={aggregator.malformed_lines}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
