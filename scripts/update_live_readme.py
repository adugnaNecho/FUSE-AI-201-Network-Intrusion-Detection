"""Update only the marked live telemetry block in README.md."""
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
START = "<!-- LIVE_NIDS_STATS_START -->"
END = "<!-- LIVE_NIDS_STATS_END -->"
CLASSES = ["Normal", "DoS", "Probe", "U2R", "R2L"]


def fetch(url, token):
    req = Request(url.rstrip("/") + "/telemetry/stats?window_hours=24",
                  headers={"X-API-Key": token, "Accept": "application/json"})
    with urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode())


def render(stats):
    counts = stats.get("class_counts") or {}
    last = stats.get("last_received_at") or "No events received yet"
    lines = [
        "### Live telemetry statistics",
        "",
        "> These are predictions submitted by an authenticated external producer. They are not the benchmark metrics below, are not independently verified incidents, and do not prove capture provenance.",
        "",
        f"**Status:** {stats.get('status', 'unknown')}  ",
        f"**Predictions in last 24 hours:** {int(stats.get('total_events_window', 0)):,}  ",
        f"**Predictions all time:** {int(stats.get('total_events_all_time', 0)):,}  ",
        f"**Active producer IDs in last 24 hours:** {int(stats.get('active_sources_window', 0)):,}  ",
        f"**Last received (UTC):** {last}",
        "",
        "| Predicted class | Last 24 hours |",
        "|---|---:|",
    ]
    for label in CLASSES:
        lines.append(f"| {label} | {int(counts.get(label, 0)):,} |")
    lines += [
        "",
        "Live accuracy, precision, recall, F1-score and confusion matrix are unavailable because this API does not receive independent ground-truth labels.",
        "",
        "<sub>README refresh runs approximately every 15 minutes. GitHub may delay scheduled workflows. Streamlit polling is more frequent while the Live Monitoring tab is open.</sub>",
    ]
    return "\n".join(lines)


def main():
    url = os.getenv("LIVE_STATS_API_URL", "").strip()
    token = os.getenv("LIVE_STATS_API_TOKEN", "").strip()
    if not url or not token:
        print("Live API secrets are not configured; README unchanged.")
        return
    content = README.read_text(encoding="utf-8")
    stats = fetch(url, token)
    replacement = START + "\n\n" + render(stats) + "\n\n" + END
    if START not in content or END not in content:
        raise RuntimeError("README live-statistics markers are missing; refusing to alter an unknown section.")
    a = content.index(START)
    b = content.index(END, a) + len(END)
    updated = content[:a] + replacement + content[b:]
    if updated != content:
        README.write_text(updated, encoding="utf-8")
        print("README live-statistics block updated.")
    else:
        print("README live-statistics block is already current.")


if __name__ == "__main__":
    main()
