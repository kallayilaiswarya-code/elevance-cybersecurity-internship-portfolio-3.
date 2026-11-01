#!/usr/bin/env python3
"""
Task 2: Elastic Query DSL Configuration Validator (Zero-Dependency)
Author: Aiswarya (ElevanceSkills Cybersecurity Intern)
Purpose: Validates syntax, JSON structure, and mandatory query/aggregation
         clauses for production Elastic Query DSL specifications.
"""

from pathlib import Path
import json
import sys

folder = Path(__file__).resolve().parent / "rules" / "elastic-dsl"


def main():
    print("=" * 70)
    print("TASK 2: ELASTIC QUERY DSL SPECIFICATION VALIDATOR")
    print("=" * 70)

    files = sorted(folder.glob("*.json"))
    print(f"[*] Scanning Elastic Query DSL directory: {folder}")
    print(f"[*] Elastic DSL files found: {len(files)}")
    all_ok = True

    for path in files:
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            if "query" not in data:
                raise ValueError("Missing mandatory root 'query' clause")

            has_aggs = "aggs" in data or "aggregations" in data
            technique = data.get("_technique", "N/A")
            comment = data.get("_comment", "N/A")

            print(f"    [PASS] {path.name:<28} | Technique: {technique:<16} | Has Aggs: {str(has_aggs):<5}")
        except Exception as exc:
            all_ok = False
            print(f"    [FAIL] {path.name:<28} | Error: {exc}")

    print("-" * 70)
    if all_ok and files:
        print(f"[SUCCESS] All {len(files)} Elastic Query DSL files passed JSON & structure validation.")
        return 0
    else:
        print("[ERROR] Elastic Query DSL validation failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
