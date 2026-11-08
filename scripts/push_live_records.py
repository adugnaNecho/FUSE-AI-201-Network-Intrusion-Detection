#!/usr/bin/env python3
"""Forward JSONL rows already transformed to the exact 41-feature model schema."""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class PermanentAPIError(RuntimeError):
    pass


def submit(url, token, source_id, records):
    body = json.dumps({"source_id": source_id, "records": records}).encode()
    request = Request(url.rstrip("/") + "/telemetry/ingest", data=body,
                      headers={"Content-Type": "application/json", "X-API-Key": token},
                      method="POST")
    try:
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode())
    except HTTPError as exc:
        detail = exc.read(800).decode(errors="replace")
        message = f"Telemetry API returned HTTP {exc.code}: {detail}"
        if 400 <= exc.code < 500 and exc.code not in (408, 429):
            raise PermanentAPIError(message) from exc
        raise RuntimeError(message) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not submit telemetry batch: {exc}") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--follow", action="store_true", help="Watch an append-only JSONL file for new records")
    parser.add_argument("--batch-size", type=int, default=25)
    parser.add_argument("--flush-interval", type=float, default=5.0,
                        help="Send a partial batch after this many seconds in follow mode")
    args = parser.parse_args()
    url = os.getenv("LIVE_STATS_API_URL", "").strip()
    token = os.getenv("LIVE_STATS_API_TOKEN", "").strip()
    if not url or not token:
        parser.error("Set LIVE_STATS_API_URL and LIVE_STATS_API_TOKEN.")
    if not 1 <= args.batch_size <= 100:
        parser.error("--batch-size must be from 1 to 100.")
    if args.flush_interval <= 0:
        parser.error("--flush-interval must be greater than zero.")
    if not args.input.is_file():
        parser.error("Input JSONL file does not exist.")

    print("This client forwards already-extracted 41-feature records; it does not capture packets.")
    print("Only prediction summaries are stored by the API; raw feature rows are not persisted.")
    batch = []
    batch_started = None
    retry_delay = 2.0
    with args.input.open("r", encoding="utf-8") as stream:
        if args.follow:
            stream.seek(0, 2)  # Do not replay historic rows as live traffic.
        while True:
            line = stream.readline()
            if line:
                if line.strip():
                    try:
                        row = json.loads(line)
                        if not isinstance(row, dict):
                            raise ValueError("Each JSONL line must contain an object.")
                    except (json.JSONDecodeError, ValueError) as exc:
                        print(f"Skipping invalid JSONL record: {exc}", file=sys.stderr)
                        continue
                    batch.append(row)
                    if batch_started is None:
                        batch_started = time.monotonic()
            elif args.follow:
                time.sleep(0.25)
            elif not batch:
                break

            elapsed = time.monotonic() - batch_started if batch_started is not None else 0.0
            flush = bool(batch) and (
                len(batch) >= args.batch_size or not args.follow or elapsed >= args.flush_interval
            )
            if not flush:
                continue

            while batch:
                try:
                    result = submit(url, token, args.source_id, batch)
                    print(f"Accepted {result.get('accepted', 0)} record(s); class counts: {result.get('predicted_class_counts', {})}")
                    batch.clear()
                    batch_started = None
                    retry_delay = 2.0
                except PermanentAPIError as exc:
                    print(f"Stopping on a permanent API error; current batch was not discarded: {exc}", file=sys.stderr)
                    return 1
                except RuntimeError as exc:
                    print(f"{exc}; retrying in {retry_delay:.0f}s without dropping the batch.", file=sys.stderr)
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 60.0)
            if not args.follow:
                break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
