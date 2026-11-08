"""Versioned feature contract for Windows Sysmon endpoint telemetry."""
from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any

SCHEMA_VERSION = "windows-endpoint-v1"

# Metadata such as process names, IDs, IP addresses and DNS names is deliberately
# excluded from model inputs. UDP Initiated flags are also excluded.
FEATURE_COLUMNS = [
    "network_connect_event_count",
    "tcp_event_count",
    "udp_event_count",
    "tcp_initiated_true_count",
    "tcp_initiated_false_count",
    "unique_destination_ip_count",
    "unique_destination_port_count",
    "unique_destination_subnet_count",
    "global_destination_event_count",
    "private_destination_event_count",
    "loopback_destination_event_count",
    "link_local_destination_event_count",
    "other_non_global_destination_event_count",
    "destination_port_53_count",
    "destination_port_80_count",
    "destination_port_137_count",
    "destination_port_443_count",
    "dns_query_event_count",
    "unique_dns_query_count",
]


def parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Timestamp must be a non-empty ISO-8601 string.")
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a UTC offset or Z suffix.")
    return parsed.astimezone(timezone.utc)


def validate_feature_vector(features: Any) -> dict[str, float]:
    """Validate the fixed numeric feature schema and return ordered values."""
    if not isinstance(features, dict):
        raise ValueError("features must be a JSON object.")
    missing = [name for name in FEATURE_COLUMNS if name not in features]
    extra = [name for name in features if name not in FEATURE_COLUMNS]
    if missing:
        raise ValueError(f"Missing Windows feature(s): {', '.join(missing)}")
    if extra:
        raise ValueError(f"Unexpected Windows feature(s): {', '.join(map(str, extra))}")

    normalized: dict[str, float] = {}
    for name in FEATURE_COLUMNS:
        value = features[name]
        if isinstance(value, bool):
            raise ValueError(f"Feature '{name}' must be numeric, not boolean.")
        try:
            numeric = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Feature '{name}' must be numeric.") from exc
        if not math.isfinite(numeric) or numeric < 0:
            raise ValueError(f"Feature '{name}' must be finite and non-negative.")
        normalized[name] = numeric

    if normalized["network_connect_event_count"] != (
        normalized["tcp_event_count"] + normalized["udp_event_count"]
    ):
        raise ValueError("network_connect_event_count must equal TCP + UDP event counts.")
    if normalized["tcp_initiated_true_count"] + normalized["tcp_initiated_false_count"] > normalized["tcp_event_count"]:
        raise ValueError("TCP Initiated counts cannot exceed TCP event count.")
    if normalized["unique_destination_ip_count"] > normalized["network_connect_event_count"]:
        raise ValueError("Unique destination IP count cannot exceed network event count.")
    if normalized["unique_destination_port_count"] > normalized["network_connect_event_count"]:
        raise ValueError("Unique destination port count cannot exceed network event count.")
    if normalized["unique_destination_subnet_count"] > normalized["network_connect_event_count"]:
        raise ValueError("Unique destination subnet count cannot exceed network event count.")
    if normalized["dns_query_event_count"] < normalized["unique_dns_query_count"]:
        raise ValueError("Unique DNS query count cannot exceed DNS query event count.")
    return normalized


def validate_snapshot(snapshot: Any) -> dict[str, Any]:
    """Validate a complete snapshot before local or remote model inference."""
    if not isinstance(snapshot, dict):
        raise ValueError("Snapshot must be a JSON object.")
    if snapshot.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be '{SCHEMA_VERSION}'.")
    for field in ("snapshot_id", "source_id", "process_name", "process_instance_id"):
        value = snapshot.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string.")

    start = parse_utc(snapshot.get("window_start_utc"))
    end = parse_utc(snapshot.get("window_end_utc"))
    try:
        window_seconds = int(snapshot.get("window_seconds"))
    except (TypeError, ValueError) as exc:
        raise ValueError("window_seconds must be a positive integer.") from exc
    if window_seconds <= 0 or end <= start:
        raise ValueError("Snapshot window must have a positive duration.")
    if (end - start).total_seconds() != window_seconds:
        raise ValueError("Snapshot timestamps must match window_seconds exactly.")

    return {
        **snapshot,
        "window_start_utc": start.isoformat().replace("+00:00", "Z"),
        "window_end_utc": end.isoformat().replace("+00:00", "Z"),
        "window_seconds": window_seconds,
        "features": validate_feature_vector(snapshot.get("features")),
    }
