import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG_FILE = ROOT / "logs" / "sample-events.jsonl"
OUTPUT_FILE = ROOT / "reports" / "credential-stuffing-alerts.json"

WINDOW = timedelta(minutes=5)
MIN_FAILURES = 5
MIN_DISTINCT_USERS = 5

events = []

with LOG_FILE.open("r", encoding="utf-8-sig") as f:
    for line in f:
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event_type") != "login_failure":
            continue
        if not all(event.get(k) for k in ("timestamp", "source_ip", "username")):
            continue

        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )
        events.append({
            "timestamp": timestamp,
            "source_ip": event["source_ip"],
            "username": event["username"],
        })

events.sort(key=lambda e: e["timestamp"])
by_ip = defaultdict(list)

for event in events:
    by_ip[event["source_ip"]].append(event)

alerts = []

for source_ip, ip_events in by_ip.items():
    for end_index, end_event in enumerate(ip_events):
        start_time = end_event["timestamp"] - WINDOW
        window_events = [
            e for e in ip_events[:end_index + 1]
            if start_time <= e["timestamp"] <= end_event["timestamp"]
        ]

        usernames = sorted({e["username"] for e in window_events})

        if (
            len(window_events) >= MIN_FAILURES
            and len(usernames) >= MIN_DISTINCT_USERS
        ):
            alert = {
                "rule_name": "Credential Stuffing",
                "severity": "high",
                "source_ip": source_ip,
                "failed_login_count": len(window_events),
                "distinct_username_count": len(usernames),
                "usernames": usernames,
                "window_start": window_events[0]["timestamp"].isoformat(),
                "window_end": end_event["timestamp"].isoformat(),
                "window_minutes": 5,
                "data_type": "synthetic test data",
                "recommendation": (
                    "Investigate the source IP, review authentication logs, "
                    "and apply approved account-protection controls if warranted."
                ),
            }
            alerts.append(alert)
            break

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE.write_text(json.dumps(alerts, indent=2), encoding="utf-8-sig")

print(f"Login-failure events analyzed: {len(events)}")
print(f"Credential-stuffing alerts generated: {len(alerts)}")
print(f"Output: {OUTPUT_FILE}")

for alert in alerts:
    print(
        f"\nALERT: {alert['rule_name']} | "
        f"Source: {alert['source_ip']} | "
        f"Failures: {alert['failed_login_count']} | "
        f"Distinct users: {alert['distinct_username_count']}"
    )
