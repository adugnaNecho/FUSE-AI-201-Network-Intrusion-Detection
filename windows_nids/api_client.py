"""Authenticated client for the separate Windows prediction endpoint."""
from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def send_snapshots(api_url: str, token: str, source_id: str, snapshots: list[dict], timeout: float = 15.0) -> list[dict]:
    if not api_url.strip() or not token.strip():
        raise ValueError("Both API URL and API token are required.")
    parsed = urlparse(api_url)
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if not parsed.netloc or (
        parsed.scheme != "https"
        and not (parsed.scheme == "http" and parsed.hostname in local_hosts)
    ):
        raise ValueError("Use HTTPS for remote inference. HTTP is permitted only for localhost testing.")

    predictions: list[dict] = []
    for offset in range(0, len(snapshots), 100):
        chunk = snapshots[offset:offset + 100]
        body = json.dumps({"source_id": source_id, "snapshots": chunk}).encode("utf-8")
        request = Request(
            api_url.rstrip("/") + "/windows/predict",
            data=body,
            headers={"Content-Type": "application/json", "X-API-Key": token},
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read(1000).decode("utf-8", errors="replace")
            raise RuntimeError(f"Windows prediction API returned HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Could not reach Windows prediction API: {exc}") from exc
        rows = payload.get("predictions") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise RuntimeError("Windows prediction API response did not contain a predictions list.")
        predictions.extend(rows)
    return predictions
