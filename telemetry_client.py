"""Streamlit-side client for the protected live telemetry API."""
import os
from typing import Any
import requests


class TelemetryClientError(RuntimeError):
    pass


def resolve_setting(name: str, secrets: Any = None):
    if secrets is not None:
        try:
            value = secrets.get(name)
            if value:
                return str(value).strip()
        except Exception:
            pass
    value = os.getenv(name)
    return str(value).strip() if value else None


def fetch_live_stats(api_url: str, token: str, window_hours: int = 24, timeout: float = 5.0):
    if not api_url or not token:
        raise TelemetryClientError("LIVE_STATS_API_URL and LIVE_STATS_API_TOKEN are required.")
    try:
        response = requests.get(api_url.rstrip("/") + "/telemetry/stats",
                                params={"window_hours": window_hours},
                                headers={"X-API-Key": token}, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise TelemetryClientError(f"Telemetry API unavailable ({type(exc).__name__}).") from exc
    except ValueError as exc:
        raise TelemetryClientError("Telemetry API returned invalid JSON.") from exc
    if not isinstance(data, dict) or "total_events_window" not in data:
        raise TelemetryClientError("Telemetry API response does not contain live statistics.")
    return data
