#!/usr/bin/env python3
"""Forward JSONL rows already transformed to the exact 41-feature model schema."""
import argparse
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def submit(url, token, source_id, records):
    body = json.dumps({"source_id": source_id, "records": records}).encode()
    request = Request(url.rstrip("/") + "/telemetry/ingest", data=body,
                      headers={"Content-Type": "application/json", "X-API-Key": token},
                      method="POST")
    try:
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode())
    except HTTPError as exc:
        text = exc.read(800).decode(errors="replace")
        if 400 <= exc.code < 500 and exc.code not in (408, 429):
            raise SystemExit(f"Permanent API error {exc.code}: {text}") from exc
        raise RuntimeError(f"Temporary API error {exc.code}: {text}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach telemetry API: {exc}") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--follow", action="store_true", help="Watch an append-only JSONL file for new records")
    parser.add_argument("--batch-size", type=int, default=25)
    args = parser.parse_args()
    url = os.getenv("LIVE_STATS_API_URL", "").strip()
    token = os.getenv("LIVE_STATS_API_TOKEN", "").strip()
    if not url or not token:
        parser.error("Set LIVE_STATS_API_URL and LIVE_STATS_API_TOKEN.")
    if not 1 <= args.batch_size <= 100:
        parser.error("--batch-size must be from 1 to 100.")
    if not args.input.is_file():
        parser.error("Input JSONL file does not exist.")
    print("This client forwards already-extracted 41-feature records; it does not capture packets.")
    batch = []
    with args.input.open("r", encoding="utf-8") as stream:
        if args.follow:
            stream.seek(0, 2)
        while True:
            line = stream.readline()
            if not line:
                if not args.follow:
                    break
                time.sleep(0.25)
                continue
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("Each JSONL line must be an object.")
            except (json.JSONDecodeError, ValueError) as exc:
                print(f"Skipping invalid line: {exc}")
                continue
            batch.append(row)
            if len(batch) >= args.batch_size or not args.follow:
                while batch:
                    try:
                        result = submit(url, token, args.source_id, batch)
                        print(f"Accepted {result.get('accepted', 0)} predictions.")
                        batch.clear()
                    except RuntimeError as exc:
                        print(f"{exc}; retrying in 5 seconds.")
                        time.sleep(5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
