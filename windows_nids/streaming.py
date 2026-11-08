"""Rolling-window aggregation for locally collected Windows Sysmon JSONL events."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from typing import Any

from windows_nids.schema import SCHEMA_VERSION

SELF_PROCESSES = {"sysmon.exe", "sysmon64.exe", "sysmon64a.exe"}
RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
IPV6_ULA = ipaddress.ip_network("fc00::/7")


def parse_event_time(value: Any) -> datetime:
    """Sysmon UtcTime is usually YYYY-MM-DD HH:MM:SS.mmm and implicitly UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Sysmon event has no valid UtcTime.")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _bool_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1"}:
        return True
    if text in {"false", "0"}:
        return False
    return None


def _process_name(image: Any) -> str:
    return str(image or "unknown").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _ip_category(value: Any) -> tuple[str | None, str | None, str | None]:
    if not value:
        return None, None, None
    try:
        address = ipaddress.ip_address(str(value).strip())
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


@dataclass(frozen=True)
class SysmonRecord:
    event_id: int
    record_id: int | None
    event_time: datetime
    process_key: str
    process_instance_id: str
    process_name: str
    fields: dict[str, Any]


class RollingWindowAggregator:
    """Emit one per-process snapshot for each trailing window when snapshot() is called."""

    def __init__(self, source_id: str, window_seconds: int = 60, exclude_self: bool = True) -> None:
        if not source_id or len(source_id) > 64:
            raise ValueError("source_id must contain 1–64 characters.")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive.")
        self.source_id = source_id
        self.window_seconds = int(window_seconds)
        self.exclude_self = exclude_self
        self._events: deque[SysmonRecord] = deque()
        self._seen_record_ids: set[int] = set()
        self.total_lines = 0
        self.accepted_events = 0
        self.filtered_events = 0
        self.malformed_lines = 0

    def ingest_line(self, line: str) -> bool:
        self.total_lines += 1
        if not line.strip():
            return False
        try:
            return self.ingest_record(json.loads(line))
        except (json.JSONDecodeError, TypeError, ValueError, KeyError):
            self.malformed_lines += 1
            return False

    def ingest_record(self, record: dict[str, Any]) -> bool:
        if not isinstance(record, dict):
            self.malformed_lines += 1
            return False
        try:
            event_id = int(record["event_id"])
            fields = record["fields"]
            if event_id not in (3, 22) or not isinstance(fields, dict):
                self.filtered_events += 1
                return False
            timestamp = parse_event_time(fields.get("UtcTime") or record.get("event_time_utc"))
            record_id_value = record.get("record_id")
            record_id = int(record_id_value) if record_id_value is not None else None
            if record_id is not None and record_id in self._seen_record_ids:
                self.filtered_events += 1
                return False
            process_name = _process_name(fields.get("Image", ""))
            if self.exclude_self and process_name in SELF_PROCESSES:
                self.filtered_events += 1
                return False
            process_guid = str(fields.get("ProcessGuid", "")).strip()
            process_id = str(fields.get("ProcessId", "unknown")).strip()
            process_key = process_guid if process_guid and process_guid != "-" else f"pid:{process_id}|image:{process_name}"
            process_instance_id = hashlib.sha256(process_key.encode("utf-8")).hexdigest()[:20]
        except (KeyError, TypeError, ValueError):
            self.malformed_lines += 1
            return False

        self._events.append(SysmonRecord(
            event_id, record_id, timestamp, process_key, process_instance_id, process_name, dict(fields)
        ))
        if record_id is not None:
            self._seen_record_ids.add(record_id)
        self.accepted_events += 1
        return True

    def _expire(self, cutoff: datetime) -> None:
        while self._events and self._events[0].event_time < cutoff:
            expired = self._events.popleft()
            if expired.record_id is not None:
                self._seen_record_ids.discard(expired.record_id)

    def snapshot(self, as_of: datetime | None = None) -> list[dict[str, Any]]:
        end = (as_of or datetime.now(timezone.utc)).astimezone(timezone.utc)
        start = end - timedelta(seconds=self.window_seconds)
        self._expire(start)
        groups: dict[str, dict[str, Any]] = {}

        for event in self._events:
            if event.event_time > end:
                continue
            group = groups.setdefault(event.process_key, {
                "process_name": event.process_name,
                "process_instance_id": event.process_instance_id,
                "network_connect_event_count": 0,
                "tcp_event_count": 0,
                "udp_event_count": 0,
                "tcp_initiated_true_count": 0,
                "tcp_initiated_false_count": 0,
                "destination_ips": set(),
                "destination_ports": set(),
                "destination_subnets": set(),
                "global_destination_event_count": 0,
                "private_destination_event_count": 0,
                "loopback_destination_event_count": 0,
                "link_local_destination_event_count": 0,
                "other_non_global_destination_event_count": 0,
                "destination_port_53_count": 0,
                "destination_port_80_count": 0,
                "destination_port_137_count": 0,
                "destination_port_443_count": 0,
                "dns_query_event_count": 0,
                "dns_query_names": set(),
            })

            if event.event_id == 3:
                group["network_connect_event_count"] += 1
                protocol = str(event.fields.get("Protocol", "")).strip().lower()
                if protocol in {"tcp", "6"}:
                    group["tcp_event_count"] += 1
                    initiated = _bool_value(event.fields.get("Initiated"))
                    if initiated is True:
                        group["tcp_initiated_true_count"] += 1
                    elif initiated is False:
                        group["tcp_initiated_false_count"] += 1
                elif protocol in {"udp", "17"}:
                    group["udp_event_count"] += 1

                category, subnet, ip_text = _ip_category(event.fields.get("DestinationIp"))
                if category:
                    group["destination_ips"].add(ip_text)
                    group["destination_subnets"].add(subnet)
                    group[f"{category}_destination_event_count"] += 1

                try:
                    port = int(event.fields.get("DestinationPort"))
                except (TypeError, ValueError):
                    port = None
                if port is not None:
                    group["destination_ports"].add(port)
                    port_columns = {
                        53: "destination_port_53_count",
                        80: "destination_port_80_count",
                        137: "destination_port_137_count",
                        443: "destination_port_443_count",
                    }
                    if port in port_columns:
                        group[port_columns[port]] += 1

            elif event.event_id == 22:
                group["dns_query_event_count"] += 1
                query = str(event.fields.get("QueryName", "")).strip().lower().rstrip(".")
                if query and query != "-":
                    group["dns_query_names"].add(query)

        window_start = start.isoformat().replace("+00:00", "Z")
        window_end = end.isoformat().replace("+00:00", "Z")
        end_epoch = int(end.timestamp())
        snapshots = []
        for group in groups.values():
            features = {
                "network_connect_event_count": group["network_connect_event_count"],
                "tcp_event_count": group["tcp_event_count"],
                "udp_event_count": group["udp_event_count"],
                "tcp_initiated_true_count": group["tcp_initiated_true_count"],
                "tcp_initiated_false_count": group["tcp_initiated_false_count"],
                "unique_destination_ip_count": len(group["destination_ips"]),
                "unique_destination_port_count": len(group["destination_ports"]),
                "unique_destination_subnet_count": len(group["destination_subnets"]),
                "global_destination_event_count": group["global_destination_event_count"],
                "private_destination_event_count": group["private_destination_event_count"],
                "loopback_destination_event_count": group["loopback_destination_event_count"],
                "link_local_destination_event_count": group["link_local_destination_event_count"],
                "other_non_global_destination_event_count": group["other_non_global_destination_event_count"],
                "destination_port_53_count": group["destination_port_53_count"],
                "destination_port_80_count": group["destination_port_80_count"],
                "destination_port_137_count": group["destination_port_137_count"],
                "destination_port_443_count": group["destination_port_443_count"],
                "dns_query_event_count": group["dns_query_event_count"],
                "unique_dns_query_count": len(group["dns_query_names"]),
            }
            snapshots.append({
                "schema_version": SCHEMA_VERSION,
                "snapshot_id": f"{self.source_id}:{group['process_instance_id']}:{end_epoch}",
                "source_id": self.source_id,
                "window_start_utc": window_start,
                "window_end_utc": window_end,
                "window_seconds": self.window_seconds,
                "process_name": group["process_name"],
                "process_instance_id": group["process_instance_id"],
                "features": features,
            })
        snapshots.sort(key=lambda item: (item["process_name"], item["process_instance_id"]))
        return snapshots

    @property
    def buffered_event_count(self) -> int:
        return len(self._events)
