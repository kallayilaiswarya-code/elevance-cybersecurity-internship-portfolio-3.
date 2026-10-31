import json
from pathlib import Path
from collections import Counter

root = Path(__file__).resolve().parent.parent
log_file = root / "logs" / "apt-events.jsonl"
report_file = root / "reports" / "apt-alerts.json"

with log_file.open("r", encoding="utf-8-sig") as f:
    events = [json.loads(line) for line in f if line.strip()]

suspicious_types = {
    "suspicious_email_attachment",
    "suspicious_powershell",
    "scheduled_task_created",
    "privilege_change",
    "remote_logon",
    "unusual_outbound_dns",
}

alerts = []
for event in events:
    if event.get("event_type") in suspicious_types:
        alerts.append({
            "timestamp": event["timestamp"],
            "event_id": event["event_id"],
            "severity": "HIGH" if event["stage"] in {
                "execution", "privilege_escalation", "exfiltration"
            } else "MEDIUM",
            "stage": event["stage"],
            "host": event["host"],
            "event_type": event["event_type"],
            "source_ip": event.get("source_ip"),
            "details": event["details"],
            "source": "synthetic_training_data",
        })

report_file.parent.mkdir(parents=True, exist_ok=True)
report_file.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

print(f"Events analyzed: {len(events)}")
print(f"Alerts generated: {len(alerts)}")
for alert in alerts:
    print(f"[{alert['severity']}] {alert['stage']} | "
          f"{alert['host']} | {alert['event_type']}")
print(f"Report saved: {report_file}")
