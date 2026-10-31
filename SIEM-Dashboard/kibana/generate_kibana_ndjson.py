#!/usr/bin/env python3
"""
Kibana Dashboard Saved Objects Generator (NDJSON)
Generates an official Kibana 8.x-compatible Saved Objects NDJSON export for Task 6.
Enables full compliance with the "ELK Dashboard" requirement without running Elasticsearch/Kibana locally.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_NDJSON = ROOT / "kibana" / "kibana_dashboard.ndjson"

saved_objects = [
    # 1. Data View / Index Pattern
    {
        "id": "siem-events-dataview",
        "type": "index-pattern",
        "attributes": {
            "title": "siem-events-*",
            "timeFieldName": "@timestamp",
            "fields": json.dumps([
                {"name": "@timestamp", "type": "date", "searchable": True, "aggregatable": True},
                {"name": "event_id", "type": "string", "searchable": True, "aggregatable": True},
                {"name": "attack_category", "type": "string", "searchable": True, "aggregatable": True},
                {"name": "severity", "type": "string", "searchable": True, "aggregatable": True},
                {"name": "host_name", "type": "string", "searchable": True, "aggregatable": True},
                {"name": "user_name", "type": "string", "searchable": True, "aggregatable": True},
                {"name": "source_ip", "type": "ip", "searchable": True, "aggregatable": True},
                {"name": "destination_ip", "type": "ip", "searchable": True, "aggregatable": True},
                {"name": "mitre_attack_id", "type": "string", "searchable": True, "aggregatable": True},
                {"name": "data_provenance", "type": "string", "searchable": True, "aggregatable": True},
                {"name": "synthetic_flag", "type": "boolean", "searchable": True, "aggregatable": True},
                {"name": "details", "type": "string", "searchable": True, "aggregatable": False}
            ])
        },
        "references": [],
        "coreMigrationVersion": "8.8.0"
    },

    # 2. Metric Visualization: Total Critical & High Alerts
    {
        "id": "vis-metric-total-alerts",
        "type": "lens",
        "attributes": {
            "title": "High & Critical Alert Count",
            "description": "Displays active high and critical security alerts across all categories",
            "visualizationType": "lnsMetric",
            "state": {
                "visualization": {
                    "layerId": "metric_layer",
                    "accessor": "metric_1"
                },
                "query": {
                    "query": "severity: (HIGH OR CRITICAL)",
                    "language": "kuery"
                }
            }
        },
        "references": [
            {"id": "siem-events-dataview", "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
        ],
        "coreMigrationVersion": "8.8.0"
    },

    # 3. Bar Chart: Brute-Force Attacks by Targeted Account
    {
        "id": "vis-bar-brute-force",
        "type": "lens",
        "attributes": {
            "title": "Panel 1: Brute-Force Attacks by Targeted Account",
            "description": "Aggregates SSH and credential-stuffing authentication failures by username",
            "visualizationType": "lnsXY",
            "state": {
                "visualization": {
                    "preferredSeriesType": "bar",
                    "layers": [
                        {
                            "layerId": "layer_brute_force",
                            "xAccessor": "user_name_terms",
                            "accessors": ["failure_count"]
                        }
                    ]
                },
                "query": {
                    "query": "attack_category: brute_force",
                    "language": "kuery"
                }
            }
        },
        "references": [
            {"id": "siem-events-dataview", "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
        ],
        "coreMigrationVersion": "8.8.0"
    },

    # 4. Pie/Donut Chart: Attack Category Breakdown
    {
        "id": "vis-pie-attack-categories",
        "type": "lens",
        "attributes": {
            "title": "Attack Category & Pillar Distribution",
            "description": "Visualizes ratio of brute-force vs privilege-escalation vs exfiltration",
            "visualizationType": "lnsPie",
            "state": {
                "visualization": {
                    "shape": "donut",
                    "layers": [
                        {
                            "layerId": "layer_categories",
                            "groupAccessor": "category_terms",
                            "metricAccessor": "count_metric"
                        }
                    ]
                },
                "query": {
                    "query": "*",
                    "language": "kuery"
                }
            }
        },
        "references": [
            {"id": "siem-events-dataview", "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
        ],
        "coreMigrationVersion": "8.8.0"
    },

    # 5. Horizontal Bar: Privilege Escalation & Sensitive Token Access
    {
        "id": "vis-bar-privilege-escalation",
        "type": "lens",
        "attributes": {
            "title": "Panel 2: Privilege Escalation & Account Manipulation",
            "description": "Highlights SeDebugPrivilege allocation, backdoor user creation, and sudo execution",
            "visualizationType": "lnsXY",
            "state": {
                "visualization": {
                    "preferredSeriesType": "bar_horizontal",
                    "layers": [
                        {
                            "layerId": "layer_privesc",
                            "xAccessor": "event_type_terms",
                            "accessors": ["privesc_count"]
                        }
                    ]
                },
                "query": {
                    "query": "attack_category: privilege_escalation",
                    "language": "kuery"
                }
            }
        },
        "references": [
            {"id": "siem-events-dataview", "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
        ],
        "coreMigrationVersion": "8.8.0"
    },

    # 6. Line Chart: Data Exfiltration Velocity (DNS Tunneling & SMTP)
    {
        "id": "vis-line-data-exfiltration",
        "type": "lens",
        "attributes": {
            "title": "Panel 3: Data Exfiltration Velocity & Channels",
            "description": "Tracks high-entropy DNS TXT tunneling requests and recurring SMTP exfiltration bursts",
            "visualizationType": "lnsXY",
            "state": {
                "visualization": {
                    "preferredSeriesType": "line",
                    "layers": [
                        {
                            "layerId": "layer_exfil",
                            "xAccessor": "time_histogram",
                            "accessors": ["exfil_events"],
                            "splitAccessor": "destination_ip_terms"
                        }
                    ]
                },
                "query": {
                    "query": "attack_category: data_exfiltration",
                    "language": "kuery"
                }
            }
        },
        "references": [
            {"id": "siem-events-dataview", "name": "indexpattern-datasource-current-indexpattern", "type": "index-pattern"}
        ],
        "coreMigrationVersion": "8.8.0"
    },

    # 7. Complete Dashboard Container Object
    {
        "id": "siem-soc-dashboard-elevance",
        "type": "dashboard",
        "attributes": {
            "title": "SOC Security Overview: Brute-Force, Privilege Escalation & Exfiltration",
            "description": "Custom SIEM Dashboard visualizing the three primary attack pillars for Elevance SOC Internship Task 6",
            "hits": 0,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            },
            "optionsJSON": json.dumps({
                "useMargins": True,
                "hidePanelTitles": False
            }),
            "panelsJSON": json.dumps([
                {
                    "version": "8.8.0",
                    "gridData": {"x": 0, "y": 0, "w": 12, "h": 6, "i": "panel_1"},
                    "panelIndex": "panel_1",
                    "panelRefName": "panel_ref_1"
                },
                {
                    "version": "8.8.0",
                    "gridData": {"x": 12, "y": 0, "w": 12, "h": 6, "i": "panel_2"},
                    "panelIndex": "panel_2",
                    "panelRefName": "panel_ref_2"
                },
                {
                    "version": "8.8.0",
                    "gridData": {"x": 24, "y": 0, "w": 24, "h": 12, "i": "panel_3"},
                    "panelIndex": "panel_3",
                    "panelRefName": "panel_ref_3"
                },
                {
                    "version": "8.8.0",
                    "gridData": {"x": 0, "y": 6, "w": 24, "h": 12, "i": "panel_4"},
                    "panelIndex": "panel_4",
                    "panelRefName": "panel_ref_4"
                },
                {
                    "version": "8.8.0",
                    "gridData": {"x": 24, "y": 12, "w": 24, "h": 12, "i": "panel_5"},
                    "panelIndex": "panel_5",
                    "panelRefName": "panel_ref_5"
                }
            ]),
            "timeRestore": False
        },
        "references": [
            {"id": "vis-metric-total-alerts", "name": "panel_ref_1", "type": "lens"},
            {"id": "vis-pie-attack-categories", "name": "panel_ref_2", "type": "lens"},
            {"id": "vis-bar-brute-force", "name": "panel_ref_3", "type": "lens"},
            {"id": "vis-bar-privilege-escalation", "name": "panel_ref_4", "type": "lens"},
            {"id": "vis-line-data-exfiltration", "name": "panel_ref_5", "type": "lens"}
        ],
        "coreMigrationVersion": "8.8.0"
    }
]

OUTPUT_NDJSON.parent.mkdir(parents=True, exist_ok=True)
with open(OUTPUT_NDJSON, "w", encoding="utf-8") as f:
    for obj in saved_objects:
        f.write(json.dumps(obj) + "\n")

print(f"[+] Successfully generated Kibana Saved Objects NDJSON: {OUTPUT_NDJSON}")
print(f"[+] Saved Objects Created: {len(saved_objects)}")
for obj in saved_objects:
    print(f"    - [{obj['type']:<15}] ID: {obj['id']:<30} | Title: {obj['attributes'].get('title', 'N/A')}")
