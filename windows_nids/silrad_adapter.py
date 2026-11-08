"""Convert labelled raw Sysmon CSV events into the project's 19-feature windows.

This adapter refuses vector-only tables and requires event timestamps, process
identity, the relevant Event 3/22 fields, event labels and an explicit
capture/session identifier. Conflicting labels inside a process window are
excluded rather than resolved by majority vote.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import math
from typing import Any, Iterable

from windows_nids.schema import FEATURE_COLUMNS
from windows_nids.streaming import parse_event_time
from scripts.inspect_sysmon_dataset import map_columns


RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
IPV6_ULA = ipaddress.ip_network("fc00::/7")


@dataclass(frozen=True)
class LabelledSysmonEvent:
    session_id: str
    event_time: datetime
    process_key: str
    process_instance_id: str
    process_name: str
    event_id: int
    label: str
    fields: dict[str, str]
    row_number: int


def _text(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    return "" if text.casefold() in {"", "-", "none", "null", "nan"} else text


def map_source_label(value: Any) -> str:
    """Map only documented Goodware/Ransomware labels to Benign/Malicious."""
    normalized = str(value).strip().casefold()
    if normalized in {"0", "0.0", "goodware", "benign", "normal"}:
        return "Benign"
    if normalized in {"1", "1.0", "ransomware", "malicious"}:
        return "Malicious"
    raise ValueError(f"Unknown source label {value!r}; expected 0/Goodware or 1/Ransomware.")


def _destination_category(value: str) -> tuple[str | None, str | None, str | None]:
    value = _text(value)
    if not value:
        return None, None, None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None, None, None
    prefix = 24 if address.version == 4 else 64
    subnet = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    if address.is_global:
        category = "global"
    elif address.version == 4 and any(address in net for net in RFC1918_NETWORKS):
        category = "private"
    elif address.version == 6 and address in IPV6_ULA:
        category = "private"
    elif address.is_loopback:
        category = "loopback"
    elif address.is_link_local:
        category = "link_local"
    else:
        category = "other_non_global"
    return category, subnet, address.compressed


def _bool(value: str) -> bool | None:
    normalized = _text(value).casefold()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def _ceil_boundary(epoch: float, step_seconds: int) -> int:
    return math.ceil(epoch / step_seconds) * step_seconds


def _features(events: list[LabelledSysmonEvent]) -> dict[str, int]:
    result = {name: 0 for name in FEATURE_COLUMNS}
    destination_ips: set[str] = set()
    destination_ports: set[int] = set()
    destination_subnets: set[str] = set()
    dns_queries: set[str] = set()

    port_counters = {
        53: "destination_port_53_count",
        80: "destination_port_80_count",
        137: "destination_port_137_count",
        443: "destination_port_443_count",
    }

    for event in events:
        fields = event.fields
        if event.event_id == 3:
            result["network_connect_event_count"] += 1
            protocol = fields.get("protocol", "").strip().casefold()
            if protocol in {"tcp", "6"}:
                result["tcp_event_count"] += 1
                initiated = _bool(fields.get("initiated", ""))
                if initiated is True:
                    result["tcp_initiated_true_count"] += 1
                elif initiated is False:
                    result["tcp_initiated_false_count"] += 1
            elif protocol in {"udp", "17"}:
                result["udp_event_count"] += 1
            else:
                raise ValueError(
                    f"Row {event.row_number}: Event ID 3 protocol must be TCP/6 or UDP/17, "
                    "otherwise network_connect_event_count cannot satisfy the project's TCP+UDP invariant."
                )

            category, subnet, ip_text = _destination_category(fields.get("destination_ip", ""))
            if category:
                destination_ips.add(ip_text)
                destination_subnets.add(subnet)
                result[f"{category}_destination_event_count"] += 1

            port_text = fields.get("destination_port", "").strip()
            if port_text and port_text != "-":
                try:
                    port = int(port_text)
                except ValueError as exc:
                    raise ValueError(f"Row {event.row_number}: DestinationPort must be an integer.") from exc
                if not 0 <= port <= 65535:
                    raise ValueError(f"Row {event.row_number}: DestinationPort is outside 0–65535.")
                destination_ports.add(port)
                if port in port_counters:
                    result[port_counters[port]] += 1

        elif event.event_id == 22:
            result["dns_query_event_count"] += 1
            query = fields.get("query_name", "").strip().casefold().rstrip(".")
            if query and query != "-":
                dns_queries.add(query)

    result["unique_destination_ip_count"] = len(destination_ips)
    result["unique_destination_port_count"] = len(destination_ports)
    result["unique_destination_subnet_count"] = len(destination_subnets)
    result["unique_dns_query_count"] = len(dns_queries)
    return result


def build_labelled_windows(
    rows: Iterable[dict[str, Any]],
    headers: list[str],
    *,
    source_name: str,
    source_id: str = "silrad-public",
    window_seconds: int = 60,
    step_seconds: int = 10,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build process windows from raw event rows; no labels are inferred."""
    if window_seconds != 60:
        raise ValueError("This Windows schema/trainer currently requires 60-second windows.")
    if step_seconds < 1 or step_seconds > window_seconds:
        raise ValueError("step_seconds must be between 1 and window_seconds.")

    mapping = map_columns(headers)
    required = [
        "event_id", "timestamp", "image", "protocol", "destination_ip",
        "destination_port", "query_name", "label", "session_id",
    ]
    missing = [key for key in required if not mapping.get(key)]
    has_guid = bool(mapping.get("process_guid"))
    has_pid = bool(mapping.get("process_id"))
    if not has_guid and not has_pid:
        missing.append("process_guid or process_id")
    if missing:
        raise ValueError(
            "Cannot reconstruct the project's 19-feature windows. Missing source fields: "
            + ", ".join(missing)
            + ". Use the dataset inspector; do not convert a fastText vector-only table."
        )

    by_process: dict[tuple[str, str], list[LabelledSysmonEvent]] = defaultdict(list)
    stats = {
        "rows_read": 0,
        "eligible_event_rows": 0,
        "feature_event_rows": 0,
        "context_event_rows": 0,
        "invalid_rows": 0,
        "ambiguous_windows_excluded": 0,
        "windows_written": 0,
    }

    for row_number, row in enumerate(rows, start=2):
        stats["rows_read"] += 1
        try:
            raw_event_id = _text(row.get(mapping["event_id"], ""))
            try:
                event_id = int(float(raw_event_id))
            except ValueError as exc:
                raise ValueError(f"Row {row_number}: Event ID is not numeric.") from exc
            session_id = _text(row.get(mapping["session_id"], ""))
            if not session_id:
                raise ValueError(f"Row {row_number}: capture/session ID is blank.")
            process_name = _text(row.get(mapping["image"], "")).replace("\\", "/").rsplit("/", 1)[-1].strip().lower()
            if not process_name:
                raise ValueError(f"Row {row_number}: Image/process name is blank.")
            process_guid = _text(row.get(mapping["process_guid"], "")) if mapping.get("process_guid") else ""
            process_id = _text(row.get(mapping["process_id"], "")) if mapping.get("process_id") else ""
            process_token = process_guid if process_guid and process_guid != "-" else (
                f"pid:{process_id}|image:{process_name}" if process_id else ""
            )
            if not process_token:
                raise ValueError(f"Row {row_number}: no ProcessGuid or usable ProcessId.")
            event_time = parse_event_time(_text(row.get(mapping["timestamp"], "")))
            label = map_source_label(row.get(mapping["label"], ""))

            fields = {
                "protocol": _text(row.get(mapping["protocol"], "")) if event_id == 3 else "",
                "destination_ip": _text(row.get(mapping["destination_ip"], "")) if event_id == 3 else "",
                "destination_port": _text(row.get(mapping["destination_port"], "")) if event_id == 3 else "",
                "initiated": _text(row.get(mapping.get("initiated"), "")) if event_id == 3 and mapping.get("initiated") else "",
                "query_name": _text(row.get(mapping["query_name"], "")) if event_id == 22 else "",
            }
            if event_id == 3 and fields["protocol"].strip().casefold() not in {"tcp", "6", "udp", "17"}:
                raise ValueError(f"Row {row_number}: Event ID 3 has no supported TCP/UDP Protocol value.")

            process_key = f"{session_id}|{process_token}"
            instance_id = hashlib.sha256(process_key.encode("utf-8")).hexdigest()[:20]
            event = LabelledSysmonEvent(
                session_id=session_id,
                event_time=event_time,
                process_key=process_key,
                process_instance_id=instance_id,
                process_name=process_name,
                event_id=event_id,
                label=label,
                fields=fields,
                row_number=row_number,
            )
            by_process[(session_id, process_key)].append(event)
            stats["eligible_event_rows"] += 1
            if event_id in (3, 22):
                stats["feature_event_rows"] += 1
            else:
                stats["context_event_rows"] += 1

        except (ValueError, TypeError, OverflowError) as exc:
            stats["invalid_rows"] += 1
            raise ValueError(str(exc)) from exc

    output: list[dict[str, Any]] = []
    label_source = (
        f"{source_name}; event-level source labels mapped as 0=Goodware/Benign, "
        "1=Ransomware/Malicious; labels are inherited only when all source events "
        "for the same process in the window agree. Only Event ID 3/22 contribute features."
    )

    for (session_id, _process_key), process_events in by_process.items():
        process_events.sort(key=lambda item: item.event_time)
        first_epoch = process_events[0].event_time.timestamp()
        last_epoch = process_events[-1].event_time.timestamp()
        first_end = _ceil_boundary(first_epoch + window_seconds, step_seconds)
        last_end = _ceil_boundary(last_epoch, step_seconds)
        if first_end > last_end:
            continue

        left = 0
        right = 0
        for end_epoch in range(first_end, last_end + 1, step_seconds):
            start_epoch = end_epoch - window_seconds
            while left < len(process_events) and process_events[left].event_time.timestamp() < start_epoch:
                left += 1
            while right < len(process_events) and process_events[right].event_time.timestamp() <= end_epoch:
                right += 1
            active = process_events[left:right]
            if not active:
                continue
            feature_events = [event for event in active if event.event_id in (3, 22)]
            if not feature_events:
                continue

            labels = {event.label for event in active}
            if len(labels) != 1:
                stats["ambiguous_windows_excluded"] += 1
                continue

            label = next(iter(labels))
            features = _features(feature_events)
            start = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
            end = datetime.fromtimestamp(end_epoch, tz=timezone.utc)
            end_epoch_int = int(end_epoch)
            instance_id = process_events[0].process_instance_id
            output.append({
                "snapshot_id": f"{source_id}:{instance_id}:{end_epoch_int}",
                "session_id": session_id,
                "label": label,
                "label_source": label_source,
                "source_id": source_id,
                "window_start_utc": start.isoformat().replace("+00:00", "Z"),
                "window_end_utc": end.isoformat().replace("+00:00", "Z"),
                "window_seconds": window_seconds,
                "process_name": active[-1].process_name,
                "process_instance_id": instance_id,
                **features,
            })

    output.sort(key=lambda row: (row["session_id"], row["window_end_utc"], row["process_name"]))
    stats["windows_written"] = len(output)
    return output, stats
