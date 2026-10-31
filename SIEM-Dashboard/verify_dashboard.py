#!/usr/bin/env python3
"""
Automated Verification Suite for Task 6 SIEM Dashboard
Author: AI-assisted preparation; no independent human reviewer
Validates:
1. File structure & data integrity.
2. Event categorization & dynamic metrics computation.
3. Kibana Saved Objects NDJSON specification compliance.
4. Live HTTP REST API endpoints and UI serving on local host.
"""

import sys
import os
import json
import time
import urllib.request
import threading
from pathlib import Path
from http.server import HTTPServer

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))

from dashboard_server import (
    load_events,
    compute_metrics,
    compute_aggregations,
    filter_events,
    SIEMDashboardHandler
)

DATA_FILE = ROOT / "data" / "siem_dashboard_events.jsonl"
NDJSON_FILE = ROOT / "kibana" / "kibana_dashboard.ndjson"
SERVER_FILE = ROOT / "backend" / "dashboard_server.py"
UI_FILE = ROOT / "frontend" / "index.html"


def test_file_structure():
    print("[*] TEST 1: Verifying Component Files...")
    assert DATA_FILE.exists(), f"Missing dataset: {DATA_FILE}"
    assert NDJSON_FILE.exists(), f"Missing Kibana NDJSON: {NDJSON_FILE}"
    assert SERVER_FILE.exists(), f"Missing server script: {SERVER_FILE}"
    assert UI_FILE.exists(), f"Missing frontend UI: {UI_FILE}"
    print(f"    [PASS] All 4 primary files exist.")


def test_data_and_categorization():
    print("\n[*] TEST 2: Ingestion & Multi-Pillar Categorization...")
    events = load_events()
    assert len(events) >= 20, f"Expected at least 20 events, got {len(events)}"
    print(f"    - Ingested Total Events: {len(events)}")

    # Check 3 required attack pillars
    categories = {e.get("attack_category") for e in events}
    assert "brute_force" in categories, "Missing 'brute_force' attack category"
    assert "privilege_escalation" in categories, "Missing 'privilege_escalation' attack category"
    assert "data_exfiltration" in categories, "Missing 'data_exfiltration' attack category"

    bf_count = sum(1 for e in events if e.get("attack_category") == "brute_force")
    pe_count = sum(1 for e in events if e.get("attack_category") == "privilege_escalation")
    ex_count = sum(1 for e in events if e.get("attack_category") == "data_exfiltration")

    print(f"    - Pillar 1 (Brute-Force Attacks):       {bf_count} events [PASS]")
    print(f"    - Pillar 2 (Privilege Escalation):      {pe_count} events [PASS]")
    print(f"    - Pillar 3 (Data Exfiltration Attempts): {ex_count} events [PASS]")

    # Check provenance segregation
    synthetic_count = sum(1 for e in events if e.get("synthetic_flag") is True)
    lab_count = sum(1 for e in events if e.get("synthetic_flag") is False)
    assert synthetic_count > 0, "Missing synthetic simulation events"
    assert lab_count > 0, "Missing real lab challenge events"
    print(f"    - Synthetic Simulation Events:           {synthetic_count} events [PASS]")
    print(f"    - Lab Challenge Telemetry Events:       {lab_count} events [PASS]")


def test_metrics_and_filtering():
    print("\n[*] TEST 3: Dynamic Metrics & Filter Logic...")
    events = load_events()
    metrics = compute_metrics(events)

    required_metric_keys = [
        "total_events", "active_incidents", "brute_force_count",
        "privilege_escalation_count", "data_exfiltration_count",
        "unique_source_ips", "targeted_accounts_count"
    ]
    for k in required_metric_keys:
        assert k in metrics, f"Missing metric key: {k}"
        assert isinstance(metrics[k], int) and metrics[k] > 0, f"Metric {k} must be > 0"
    print(f"    [PASS] Metrics computed dynamically: {metrics['active_incidents']} active incidents, {metrics['unique_source_ips']} unique IPs.")

    # Test filtering
    filtered_bf = filter_events(events, category="brute_force")
    assert len(filtered_bf) == metrics["brute_force_count"]
    print(f"    [PASS] Category filter ('brute_force'): {len(filtered_bf)} hits.")

    filtered_search_ip = filter_events(events, search="192.0.2.25")
    assert len(filtered_search_ip) >= 5
    print(f"    [PASS] Search filter ('192.0.2.25'): {len(filtered_search_ip)} hits.")

    filtered_search_root = filter_events(events, search="root")
    assert len(filtered_search_root) >= 1
    print(f"    [PASS] Search filter ('root'): {len(filtered_search_root)} hits.")


def test_kibana_ndjson_compliance():
    print("\n[*] TEST 4: Kibana NDJSON Specification Compliance...")
    lines = NDJSON_FILE.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 5, f"Expected at least 5 saved objects, got {len(lines)}"

    object_types = set()
    object_ids = set()
    for idx, l in enumerate(lines, 1):
        obj = json.loads(l)
        assert "id" in obj and "type" in obj and "attributes" in obj, f"Malformed saved object on line {idx}"
        object_types.add(obj["type"])
        object_ids.add(obj["id"])

    assert "index-pattern" in object_types, "Missing index-pattern / data-view object"
    assert "lens" in object_types, "Missing lens visualization objects"
    assert "dashboard" in object_types, "Missing dashboard container object"
    print(f"    [PASS] Kibana Saved Objects verified ({len(lines)} objects: {sorted(object_types)})")


def test_live_server_endpoints():
    print("\n[*] TEST 5: Local HTTP Server Endpoints & UI Serving...")
    test_port = 8899
    server = HTTPServer(("127.0.0.1", test_port), SIEMDashboardHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    try:
        base_url = f"http://127.0.0.1:{test_port}"

        # 1. Test UI index.html
        with urllib.request.urlopen(f"{base_url}/") as res:
            assert res.status == 200
            html = res.read().decode("utf-8")
            assert "Elevance Health SOC" in html
            assert "chart-brute-force" in html
            print(f"    [PASS] GET / -> HTTP 200 (HTML UI served successfully)")

        # 2. Test /api/metrics
        with urllib.request.urlopen(f"{base_url}/api/metrics") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert "total_events" in data
            print(f"    [PASS] GET /api/metrics -> HTTP 200 (Total Events: {data['total_events']})")

        # 3. Test /api/aggregations
        with urllib.request.urlopen(f"{base_url}/api/aggregations") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert "top_users" in data and "categories" in data
            print(f"    [PASS] GET /api/aggregations -> HTTP 200 (Charts data returned)")

        # 4. Test /api/events?category=privilege_escalation
        with urllib.request.urlopen(f"{base_url}/api/events?category=privilege_escalation") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["total_matched"] > 0
            print(f"    [PASS] GET /api/events?category=privilege_escalation -> HTTP 200 ({data['total_matched']} matched)")

        # 5. Test /api/events?category=data_exfiltration
        with urllib.request.urlopen(f"{base_url}/api/events?category=data_exfiltration") as res:
            assert res.status == 200
            data = json.loads(res.read().decode("utf-8"))
            assert data["total_matched"] > 0
            print(f"    [PASS] GET /api/events?category=data_exfiltration -> HTTP 200 ({data['total_matched']} matched)")

    finally:
        server.shutdown()
        server.server_close()
        print(f"    [+] Local test server terminated cleanly.")


def main():
    print("=" * 70)
    print("TASK 6: CUSTOM SIEM DASHBOARD — AUTOMATED VERIFICATION SUITE")
    print("=" * 70)
    try:
        test_file_structure()
        test_data_and_categorization()
        test_metrics_and_filtering()
        test_kibana_ndjson_compliance()
        test_live_server_endpoints()
        print("\n" + "=" * 70)
        print("[SUCCESS] ALL VERIFICATION TESTS PASSED (5/5). TASK 6 IS OPERATIONAL.")
        print("=" * 70)
    except AssertionError as e:
        print(f"\n[FAILURE] Assertion failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected test error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
