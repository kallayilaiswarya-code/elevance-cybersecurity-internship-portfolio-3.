#!/usr/bin/env python3
"""
SIEM Dashboard Dataset Builder
Aggregates, normalizes, and enriches security telemetry from Tasks 2, 3, and Brutus into a standardized Elastic Common Schema (ECS)-aligned JSONL file for Task 6.
Strictly preserves and documents data provenance (Synthetic vs Lab Evidence).
"""

import json
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_FILE = ROOT / "SIEM-Dashboard" / "data" / "siem_dashboard_events.jsonl"

dashboard_events = []

# -------------------------------------------------------------------------
# 1. TASK 2: Credential Stuffing & DNS Tunneling (Synthetic)
# -------------------------------------------------------------------------
t2_path = ROOT / "SIEM-Correlation-Rules" / "logs" / "sample-events.jsonl"
if t2_path.exists():
    with open(t2_path, "r", encoding="utf-8-sig") as f:
        for idx, line in enumerate(f, 1):
            if not line.strip():
                continue
            ev = json.loads(line)
            ev_type = ev.get("event_type")

            if ev_type == "login_failure":
                dashboard_events.append({
                    "@timestamp": ev.get("timestamp"),
                    "event_id": f"T2-AUTH-{idx:03d}",
                    "attack_category": "brute_force",
                    "severity": "HIGH",
                    "event_code": 4625,
                    "event_type": "authentication_failure",
                    "host_name": "CORP-IDP01",
                    "user_name": ev.get("username"),
                    "source_ip": ev.get("source_ip"),
                    "destination_ip": "10.0.1.10",
                    "mitre_attack_id": "T1110.004",
                    "mitre_attack_technique": "Brute Force: Credential Stuffing",
                    "data_provenance": "Synthetic Training Simulation",
                    "synthetic_flag": True,
                    "details": f"Synthetic login failure for user '{ev.get('username')}' from source {ev.get('source_ip')}"
                })
            elif ev_type == "dns_query" and ev.get("query_length", 0) > 30:
                dashboard_events.append({
                    "@timestamp": ev.get("timestamp"),
                    "event_id": f"T2-DNS-{idx:03d}",
                    "attack_category": "data_exfiltration",
                    "severity": "MEDIUM",
                    "event_code": 22,
                    "event_type": "dns_query",
                    "host_name": "CORP-WKSTN05",
                    "user_name": "network_client",
                    "source_ip": ev.get("source_ip"),
                    "destination_ip": "8.8.8.8",
                    "dns_query_name": ev.get("query"),
                    "dns_query_length": ev.get("query_length"),
                    "mitre_attack_id": "T1071.004",
                    "mitre_attack_technique": "Application Layer Protocol: DNS",
                    "data_provenance": "Synthetic Training Simulation",
                    "synthetic_flag": True,
                    "details": f"Suspicious high-length DNS query ({ev.get('query_length')} chars): {ev.get('query')}"
                })
            elif ev_type == "dns_query" and ev.get("query_length", 0) <= 30:
                dashboard_events.append({
                    "@timestamp": ev.get("timestamp"),
                    "event_id": f"T2-BENIGN-{idx:03d}",
                    "attack_category": "benign_baseline",
                    "severity": "INFORMATIONAL",
                    "event_code": 22,
                    "event_type": "dns_query",
                    "host_name": "CORP-WKSTN05",
                    "user_name": "network_client",
                    "source_ip": ev.get("source_ip"),
                    "destination_ip": "8.8.8.8",
                    "dns_query_name": ev.get("query"),
                    "dns_query_length": ev.get("query_length"),
                    "mitre_attack_id": "N/A",
                    "mitre_attack_technique": "Normal Business Traffic",
                    "data_provenance": "Synthetic Training Simulation",
                    "synthetic_flag": True,
                    "details": f"Standard benign DNS query: {ev.get('query')}"
                })

# Add Task 2 Credential Stuffing Aggregated Alert
dashboard_events.append({
    "@timestamp": "2026-10-13T10:00:15Z",
    "event_id": "T2-ALERT-001",
    "attack_category": "brute_force",
    "severity": "HIGH",
    "event_code": "CORR-STUFFING",
    "event_type": "correlation_alert",
    "host_name": "CORP-IDP01",
    "user_name": "multiple (5 users)",
    "source_ip": "192.0.2.25",
    "destination_ip": "10.0.1.10",
    "mitre_attack_id": "T1110.004",
    "mitre_attack_technique": "Brute Force: Credential Stuffing",
    "data_provenance": "Synthetic Training Simulation",
    "synthetic_flag": True,
    "details": "CORRELATION ALERT: 5 failed logins from 192.0.2.25 across 5 distinct usernames within 12 seconds"
})

# -------------------------------------------------------------------------
# 2. TASK 3: Privilege Escalation, Exfiltration & Benign Baselines (Synthetic ECS)
# -------------------------------------------------------------------------
t3_path = ROOT / "APT-Simulation" / "simulation" / "events" / "synthetic_ecs_events.jsonl"
if t3_path.exists():
    with open(t3_path, "r", encoding="utf-8-sig") as f:
        for line in f:
            if not line.strip():
                continue
            ev = json.loads(line)
            stage = ev.get("scenario_stage")

            category = "benign_baseline"
            sev = "INFORMATIONAL"
            mitre_id = "N/A"
            mitre_tech = "Normal Business Traffic"

            if stage == "privilege_escalation":
                category = "privilege_escalation"
                sev = "HIGH"
                mitre_id = "T1078 / T1134"
                mitre_tech = "Valid Accounts / Access Token Manipulation"
            elif stage == "exfiltration":
                category = "data_exfiltration"
                sev = "HIGH"
                mitre_id = "T1071.004"
                mitre_tech = "Exfiltration Over DNS Tunnel"
            elif stage == "initial_access":
                category = "initial_access"
                sev = "HIGH"
                mitre_id = "T1566.001"
                mitre_tech = "Phishing: Spearphishing Attachment"
            elif stage == "execution":
                category = "execution"
                sev = "HIGH"
                mitre_id = "T1059.001"
                mitre_tech = "PowerShell Execution"
            elif stage == "persistence":
                category = "persistence"
                sev = "MEDIUM"
                mitre_id = "T1053.005"
                mitre_tech = "Scheduled Task"
            elif stage == "lateral_movement":
                category = "lateral_movement"
                sev = "HIGH"
                mitre_id = "T1047"
                mitre_tech = "Windows Management Instrumentation"

            dashboard_events.append({
                "@timestamp": ev.get("@timestamp"),
                "event_id": ev.get("event.id"),
                "attack_category": category,
                "severity": sev,
                "event_code": ev.get("event.code"),
                "event_type": ev.get("event.dataset"),
                "host_name": ev.get("host.name"),
                "user_name": ev.get("user.name"),
                "source_ip": ev.get("source.ip", "internal"),
                "destination_ip": ev.get("destination.ip", "internal"),
                "process_name": ev.get("process.name"),
                "process_command_line": ev.get("process.command_line"),
                "privilege_list": ev.get("winlog.privilege_list"),
                "dns_query_name": ev.get("dns.question.name"),
                "dns_query_length": ev.get("dns.question.length"),
                "mitre_attack_id": mitre_id,
                "mitre_attack_technique": mitre_tech,
                "data_provenance": "Synthetic Training Simulation",
                "synthetic_flag": True,
                "details": ev.get("details")
            })

# -------------------------------------------------------------------------
# 3. TASK 5 (Brutus): Linux SSH Brute-Force & Privilege Escalation (Lab Challenge Telemetry)
# -------------------------------------------------------------------------
brutus_auth = ROOT / "Brutus" / "auth.log"
if brutus_auth.exists():
    import re
    lines = brutus_auth.read_text(encoding="utf-8", errors="ignore").splitlines()

    # Extract SSH brute force failures
    ssh_fail_count = 0
    for idx, l in enumerate(lines):
        m = re.search(r'^(Mar\s+\d+\s+[\d:]+)\s+([\w-]+)\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\w+) from ([0-9.]+)', l)
        if m:
            ssh_fail_count += 1
            # Sample every 3rd or all to give realistic high volume
            dashboard_events.append({
                "@timestamp": f"2026-03-06T{m.group(1).split()[2]}Z",
                "event_id": f"BRUTUS-SSH-FAIL-{ssh_fail_count:03d}",
                "attack_category": "brute_force",
                "severity": "HIGH",
                "event_code": "SSHD-FAIL",
                "event_type": "ssh_login_failure",
                "host_name": m.group(2),
                "user_name": m.group(3),
                "source_ip": m.group(4),
                "destination_ip": "172.31.35.28",
                "mitre_attack_id": "T1110.001",
                "mitre_attack_technique": "Brute Force: Password Guessing",
                "data_provenance": "Lab Challenge Telemetry (HTB Brutus)",
                "synthetic_flag": False,
                "details": f"SSH brute-force login failure for account '{m.group(3)}' from adversary IP {m.group(4)}"
            })

        m_acc = re.search(r'^(Mar\s+\d+\s+[\d:]+)\s+([\w-]+)\s+sshd\[\d+\]:\s+Accepted password for (\w+) from ([0-9.]+)', l)
        if m_acc and m_acc.group(4) == "65.2.161.68":
            dashboard_events.append({
                "@timestamp": f"2026-03-06T{m_acc.group(1).split()[2]}Z",
                "event_id": "BRUTUS-SSH-SUCCESS-001",
                "attack_category": "brute_force",
                "severity": "CRITICAL",
                "event_code": "SSHD-ACCEPTED",
                "event_type": "ssh_login_success",
                "host_name": m_acc.group(2),
                "user_name": m_acc.group(3),
                "source_ip": m_acc.group(4),
                "destination_ip": "172.31.35.28",
                "mitre_attack_id": "T1078.003",
                "mitre_attack_technique": "Valid Accounts: Local Accounts",
                "data_provenance": "Lab Challenge Telemetry (HTB Brutus)",
                "synthetic_flag": False,
                "details": f"ADVERSARY LOGON SUCCESS: Attacker {m_acc.group(4)} obtained valid credentials for user '{m_acc.group(3)}'"
            })

        m_user = re.search(r'^(Mar\s+\d+\s+[\d:]+)\s+([\w-]+)\s+useradd\[\d+\]:\s+new user: name=(\w+)', l)
        if m_user:
            dashboard_events.append({
                "@timestamp": f"2026-03-06T{m_user.group(1).split()[2]}Z",
                "event_id": "BRUTUS-BACKDOOR-001",
                "attack_category": "privilege_escalation",
                "severity": "CRITICAL",
                "event_code": "USERADD",
                "event_type": "account_creation",
                "host_name": m_user.group(2),
                "user_name": m_user.group(3),
                "source_ip": "65.2.161.68",
                "destination_ip": "172.31.35.28",
                "mitre_attack_id": "T1136.001",
                "mitre_attack_technique": "Create Account: Local Account",
                "data_provenance": "Lab Challenge Telemetry (HTB Brutus)",
                "synthetic_flag": False,
                "details": f"BACKDOOR ACCOUNT CREATED: Unauthorized local user '{m_user.group(3)}' added by adversary"
            })

        m_sudo = re.search(r'^(Mar\s+\d+\s+[\d:]+)\s+([\w-]+)\s+sudo:.*\s+(\w+)\s+:\s+TTY=.*\s+;\s+USER=(\w+)\s+;\s+COMMAND=(.*)', l)
        if m_sudo:
            dashboard_events.append({
                "@timestamp": f"2026-03-06T{m_sudo.group(1).split()[2]}Z",
                "event_id": "BRUTUS-SUDO-001",
                "attack_category": "privilege_escalation",
                "severity": "CRITICAL",
                "event_code": "SUDO-ELEVATION",
                "event_type": "privilege_elevation",
                "host_name": m_sudo.group(2),
                "user_name": m_sudo.group(3),
                "target_user": m_sudo.group(4),
                "source_ip": "65.2.161.68",
                "destination_ip": "172.31.35.28",
                "process_command_line": m_sudo.group(5),
                "mitre_attack_id": "T1548.003",
                "mitre_attack_technique": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                "data_provenance": "Lab Challenge Telemetry (HTB Brutus)",
                "synthetic_flag": False,
                "details": f"SUDO ROOT EXECUTION: User '{m_sudo.group(3)}' elevated to '{m_sudo.group(4)}' executing: {m_sudo.group(5)}"
            })

# -------------------------------------------------------------------------
# 4. TASK 1 & 4 (HawkEye): SMTP Periodic Exfiltration (Lab Challenge Telemetry)
# -------------------------------------------------------------------------
hawkeye_times = [
    "2019-04-10T20:38:08Z",
    "2019-04-10T20:48:12Z",
    "2019-04-10T20:58:17Z",
    "2019-04-10T21:08:23Z",
]

for idx, t in enumerate(hawkeye_times, 1):
    dashboard_events.append({
        "@timestamp": t,
        "event_id": f"HAWKEYE-SMTP-{idx:03d}",
        "attack_category": "data_exfiltration",
        "severity": "CRITICAL",
        "event_code": "SMTP-EXFIL",
        "event_type": "email_data_exfiltration",
        "host_name": "Beijing-5cd1-PC",
        "user_name": "sales.del@macwinlogistics.in",
        "source_ip": "10.4.10.132",
        "destination_ip": "23.229.162.69",
        "destination_port": 587,
        "mitre_attack_id": "T1048.003",
        "mitre_attack_technique": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
        "data_provenance": "Lab Challenge Telemetry (HawkEye stealer.pcap)",
        "synthetic_flag": False,
        "details": f"PERIODIC SMTP EXFILTRATION: Keylogger credential log exfiltrated to mail.winlogistics.in (Burst #{idx}, ~10-min interval)"
    })

# Write out standardized dataset
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for ev in dashboard_events:
        f.write(json.dumps(ev) + "\n")

print(f"[+] Successfully built unified SIEM Dashboard dataset: {OUTPUT_FILE}")
print(f"[+] Total Events Ingested: {len(dashboard_events)}")
categories = {}
for e in dashboard_events:
    cat = e.get("attack_category")
    categories[cat] = categories.get(cat, 0) + 1
for cat, count in sorted(categories.items()):
    print(f"    - {cat:<22}: {count} events")
