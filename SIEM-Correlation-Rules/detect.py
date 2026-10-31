import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
LOG_FILE = BASE / "logs" / "sample-events.jsonl"
ALERT_FILE = BASE / "reports" / "alerts.json"

events = []
with LOG_FILE.open("r", encoding="utf-8-sig") as file:
    for line_number, line in enumerate(file, 1):
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"Skipping invalid JSON on line {line_number}: {exc}")

alerts = []

# Rule 1: Credential stuffing
failures = defaultdict(list)

for event in events:
    if event.get("event_type") == "login_failure":
        failures[event.get("source_ip", "unknown")].append(event)

for source_ip, records in failures.items():
    usernames = {record.get("username") for record in records}
    times = sorted(
        datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
        for record in records
    )

    for start in range(len(times)):
        window = [
            timestamp for timestamp in times[start:]
            if (timestamp - times[start]).total_seconds() <= 300
        ]
        if len(window) >= 5 and len(usernames) >= 5:
            alerts.append({
                "rule": "Credential Stuffing",
                "severity": "HIGH",
                "source_ip": source_ip,
                "failed_attempts": len(window),
                "distinct_usernames": len(usernames),
                "description": "Repeated failed logins across multiple usernames."
            })
            break

# Rule 2: Suspicious DNS query
for event in events:
    if event.get("event_type") == "dns_query":
        query = event.get("query", "")
        label = query.split(".")[0]
        if event.get("query_length", len(query)) >= 35 and len(label) >= 20:
            alerts.append({
                "rule": "Suspicious DNS Activity",
                "severity": "MEDIUM",
                "source_ip": event.get("source_ip"),
                "query": query,
                "description": "Long DNS query with a long first label; investigate for possible tunnelling."
            })

# Rule 3: Suspicious PowerShell execution
for event in events:
    if event.get("event_type") == "process_creation":
        process = event.get("process", "").lower()
        command_line = event.get("command_line", "").lower()

        if process == "powershell.exe" and (
            "-encodedcommand" in command_line or " -enc " in command_line
        ):
            alerts.append({
                "rule": "Suspicious PowerShell",
                "severity": "HIGH",
                "host": event.get("host"),
                "username": event.get("username"),
                "command_line": event.get("command_line"),
                "description": "PowerShell encoded-command flag detected; review process context."
            })

ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
ALERT_FILE.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

print(f"Events processed: {len(events)}")
print(f"Alerts generated: {len(alerts)}")
for number, alert in enumerate(alerts, 1):
    print(f"\nAlert {number}: [{alert['severity']}] {alert['rule']}")
    print(alert["description"])

print(f"\nAlerts saved to: {ALERT_FILE}")
