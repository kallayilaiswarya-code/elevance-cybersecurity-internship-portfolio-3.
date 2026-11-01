#!/usr/bin/env python3
"""
Custom SIEM Dashboard Backend Server
Lightweight, zero-dependency Python HTTP server providing REST API endpoints and static asset serving for Task 6.
Runs on Windows 11 using Python standard library (< 30 MB RAM).
"""

import sys
import os
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from collections import Counter
import webbrowser

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "siem_dashboard_events.jsonl"
FRONTEND_DIR = ROOT / "frontend"


def load_events():
    """Loads all normalized events from data/siem_dashboard_events.jsonl."""
    events = []
    if DATA_FILE.exists():
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    return events


def filter_events(events, category=None, severity=None, provenance=None, search=None):
    """Filters events dynamically based on user query parameters."""
    filtered = events

    if category and category != "all":
        filtered = [e for e in filtered if e.get("attack_category") == category]

    if severity and severity != "all":
        filtered = [e for e in filtered if e.get("severity") == severity.upper()]

    if provenance and provenance != "all":
        if provenance.lower() == "synthetic":
            filtered = [e for e in filtered if e.get("synthetic_flag") is True]
        elif provenance.lower() in ["lab", "challenge", "forensics"]:
            filtered = [e for e in filtered if e.get("synthetic_flag") is False]

    if search:
        s = search.lower().strip()
        matched = []
        for e in filtered:
            text_corpus = " ".join([
                str(e.get("event_id", "")),
                str(e.get("host_name", "")),
                str(e.get("user_name", "")),
                str(e.get("source_ip", "")),
                str(e.get("destination_ip", "")),
                str(e.get("mitre_attack_id", "")),
                str(e.get("mitre_attack_technique", "")),
                str(e.get("details", "")),
                str(e.get("attack_category", ""))
            ]).lower()
            if s in text_corpus:
                matched.append(e)
        filtered = matched

    return filtered


def compute_metrics(events):
    """Computes real-time SOC metrics directly from event objects (zero hardcoded values)."""
    total = len(events)
    critical = sum(1 for e in events if e.get("severity") == "CRITICAL")
    high = sum(1 for e in events if e.get("severity") == "HIGH")
    medium = sum(1 for e in events if e.get("severity") == "MEDIUM")
    low_info = sum(1 for e in events if e.get("severity") in ["LOW", "INFORMATIONAL"])

    brute_force = sum(1 for e in events if e.get("attack_category") == "brute_force")
    privesc = sum(1 for e in events if e.get("attack_category") == "privilege_escalation")
    exfil = sum(1 for e in events if e.get("attack_category") == "data_exfiltration")
    benign = sum(1 for e in events if e.get("attack_category") == "benign_baseline")

    synthetic = sum(1 for e in events if e.get("synthetic_flag") is True)
    lab_evidence = sum(1 for e in events if e.get("synthetic_flag") is False)

    unique_sources = len({e.get("source_ip") for e in events if e.get("source_ip") and e.get("source_ip") != "internal"})
    targeted_users = len({e.get("user_name") for e in events if e.get("user_name")})

    return {
        "total_events": total,
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "low_info_alerts": low_info,
        "active_incidents": critical + high,
        "brute_force_count": brute_force,
        "privilege_escalation_count": privesc,
        "data_exfiltration_count": exfil,
        "benign_count": benign,
        "synthetic_event_count": synthetic,
        "lab_evidence_count": lab_evidence,
        "unique_source_ips": unique_sources,
        "targeted_accounts_count": targeted_users
    }


def compute_aggregations(events):
    """Computes aggregation distributions for interactive charts."""
    # 1. Category Breakdown
    cat_counts = Counter(e.get("attack_category", "unknown") for e in events)

    # 2. Severity Breakdown
    sev_counts = Counter(e.get("severity", "unknown") for e in events)

    # 3. Top Brute Force Targeted Users
    bf_events = [e for e in events if e.get("attack_category") == "brute_force"]
    top_users = Counter(e.get("user_name") for e in bf_events if e.get("user_name")).most_common(8)

    # 4. Top Attacker Source IPs
    top_sources = Counter(e.get("source_ip") for e in events if e.get("source_ip") and e.get("source_ip") != "internal").most_common(6)

    # 5. Privilege Escalation Types
    priv_events = [e for e in events if e.get("attack_category") == "privilege_escalation"]
    priv_types = Counter(e.get("mitre_attack_technique", "Other Elevation") for e in priv_events).most_common(5)

    # 6. Exfiltration Destination Channels
    exfil_events = [e for e in events if e.get("attack_category") == "data_exfiltration"]
    exfil_dest = Counter(f"{e.get('destination_ip', 'unknown')} ({e.get('mitre_attack_id', '')})" for e in exfil_events).most_common(5)

    return {
        "categories": dict(cat_counts),
        "severities": dict(sev_counts),
        "top_users": [{"user": u, "count": c} for u, c in top_users],
        "top_sources": [{"ip": ip, "count": c} for ip, c in top_sources],
        "privesc_breakdown": [{"technique": t, "count": c} for t, c in priv_types],
        "exfil_destinations": [{"channel": ch, "count": c} for ch, c in exfil_dest]
    }


class SIEMDashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # CORS and Security Headers
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "X-Content-Type-Options": "nosniff"
        }

        # Route 1: Serve UI
        if path in ["/", "/index.html"]:
            html_file = FRONTEND_DIR / "index.html"
            if html_file.exists():
                content = html_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "UI template not found")
            return

        # Route 2: API Metrics
        if path == "/api/metrics":
            events = load_events()
            metrics = compute_metrics(events)
            self.send_json_response(metrics, headers)
            return

        # Route 3: API Aggregations for Charts
        if path == "/api/aggregations":
            events = load_events()
            aggs = compute_aggregations(events)
            self.send_json_response(aggs, headers)
            return

        # Route 4: API Filtered Events
        if path == "/api/events":
            events = load_events()
            cat = query.get("category", [None])[0]
            sev = query.get("severity", [None])[0]
            prov = query.get("provenance", [None])[0]
            search = query.get("search", [None])[0]

            filtered = filter_events(events, category=cat, severity=sev, provenance=prov, search=search)

            # Sort chronologically reverse by default
            filtered.sort(key=lambda x: str(x.get("@timestamp", "")), reverse=True)

            response = {
                "total_matched": len(filtered),
                "events": filtered
            }
            self.send_json_response(response, headers)
            return

        # Fallback 404
        self.send_error(404, "Endpoint not found")

    def send_json_response(self, data, extra_headers):
        content = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        for k, v in extra_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        # Concise logging to stdout
        sys.stdout.write(f"[{self.log_date_time_string()}] {format % args}\n")
        sys.stdout.flush()


def run_server(port=8080, open_browser=False):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, SIEMDashboardHandler)
    url = f"http://127.0.0.1:{port}"
    print("=" * 70)
    print("ELEVANCE HEALTH SOC — CUSTOM SIEM DASHBOARD SERVER (TASK 6)")
    print("=" * 70)
    print(f"[*] Server initialized on {url}")
    print(f"[*] Data Source: {DATA_FILE.name}")
    print(f"[*] Memory Profile: < 30 MB (Standard Library Python)")
    print(f"[*] Press CTRL+C to terminate.")
    print("=" * 70)

    if open_browser:
        webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Dashboard server shut down gracefully.")
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run Task 6 SIEM Dashboard Server")
    parser.add_argument("--port", type=int, default=8080, help="Local port (default 8080)")
    parser.add_argument("--open", action="store_true", help="Automatically launch web browser")
    args = parser.parse_args()

    run_server(port=args.port, open_browser=args.open)
