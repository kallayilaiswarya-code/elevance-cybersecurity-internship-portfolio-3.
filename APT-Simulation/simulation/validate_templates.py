#!/usr/bin/env python3
"""
Structural Validator for Threat Intelligence & Case Management Templates
Author: AI-assisted preparation; no independent human reviewer
Validates offline JSON syntax and schema compliance for MISP and TheHive templates.
"""

import json
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MISP_FILE = ROOT / "threat-intelligence" / "misp-training-event.json"
THEHIVE_FILE = ROOT / "threat-intelligence" / "thehive-case-template.json"


def validate_misp(file_path: Path):
    print(f"[*] Validating MISP Template: {file_path.name}")
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if "Event" not in data:
        raise ValueError("Missing root 'Event' object")

    event = data["Event"]
    req_fields = ["uuid", "info", "date", "threat_level_id", "analysis", "distribution", "Attribute", "Tag"]
    missing = [rf for rf in req_fields if rf not in event]
    if missing:
        raise ValueError(f"Missing required Event fields: {missing}")

    # Validate Event UUID
    uuid.UUID(event["uuid"])

    # Validate Attributes
    attr_req = ["uuid", "type", "category", "to_ids", "value"]
    print(f"    - Attributes parsed: {len(event['Attribute'])}")
    for idx, attr in enumerate(event["Attribute"]):
        attr_missing = [af for af in attr_req if af not in attr]
        if attr_missing:
            raise ValueError(f"Attribute {idx} missing fields: {attr_missing}")
        uuid.UUID(attr["uuid"])

    print(f"    - Tags parsed: {len(event['Tag'])}")
    print("[+] MISP Template Structure: VALID")


def validate_thehive(file_path: Path):
    print(f"\n[*] Validating TheHive 5 Template: {file_path.name}")
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    req_fields = ["title", "description", "severity", "tlp", "tags", "tasks", "observables"]
    missing = [rf for rf in req_fields if rf not in data]
    if missing:
        raise ValueError(f"Missing required Case fields: {missing}")

    if not isinstance(data["tasks"], list) or not data["tasks"]:
        raise ValueError("TheHive template must contain a non-empty 'tasks' list")
    print(f"    - Investigation tasks parsed: {len(data['tasks'])}")

    if not isinstance(data["observables"], list) or not data["observables"]:
        raise ValueError("TheHive template must contain a non-empty 'observables' list")
    print(f"    - Case observables parsed: {len(data['observables'])}")

    print("[+] TheHive 5 Template Structure: VALID")


if __name__ == "__main__":
    try:
        validate_misp(MISP_FILE)
        validate_thehive(THEHIVE_FILE)
        print("\n[SUCCESS] Both offline candidate templates passed schema and syntax validation.")
    except Exception as e:
        print(f"\n[FAILURE] Validation error: {e}")
        exit(1)
