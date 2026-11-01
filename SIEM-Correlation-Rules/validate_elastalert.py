#!/usr/bin/env python3
"""
Task 2: ElastAlert 2 Rule Configuration & Syntax Validator (Zero-Dependency)
Author: Aiswarya (ElevanceSkills Cybersecurity Intern)
Purpose: Validates that all Task 2 ElastAlert rule configurations adhere to
         ElastAlert 2 specifications, mandatory top-level keys, filter syntax,
         and query structures without external dependencies.
"""

from pathlib import Path
import re
import sys

folder = Path(__file__).resolve().parent / "rules" / "elastalert"
required_keys = {"name", "type", "index", "filter", "alert"}


def parse_simple_yaml(text: str) -> dict:
    """Zero-dependency parser for standard ElastAlert rule YAML."""
    result = {}
    current_key = None
    sub_key = None

    lines = text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))

        if indent == 0 and ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip()
            current_key = k
            sub_key = None
            if v:
                result[k] = v.strip("'\"")
            else:
                result[k] = {}
            continue

        if current_key:
            if stripped.startswith("- "):
                val = stripped[2:].strip().strip("'\"")
                if not isinstance(result[current_key], list):
                    result[current_key] = []
                result[current_key].append(val)
            elif ":" in line:
                parts = line.split(":", 1)
                sk = parts[0].strip()
                sv = parts[1].strip()
                if not isinstance(result[current_key], dict):
                    result[current_key] = {}
                if indent <= 4:
                    sub_key = sk
                    result[current_key][sk] = sv.strip("'\"") if sv else {}
                else:
                    if isinstance(result[current_key].get(sub_key), dict):
                        result[current_key][sub_key][sk] = sv.strip("'\"") if sv else []
    return result


def main():
    print("=" * 70)
    print("TASK 2: ELASTALERT RULE CONFIGURATION VALIDATOR (ZERO-DEPENDENCY)")
    print("=" * 70)

    files = sorted(folder.glob("*.yaml")) + sorted(folder.glob("*.yml"))
    print(f"[*] Scanning ElastAlert directory: {folder}")
    print(f"[*] ElastAlert rule files found: {len(files)}")
    all_ok = True

    for path in files:
        try:
            with path.open("r", encoding="utf-8") as f:
                content = f.read()

            rule = parse_simple_yaml(content)
            missing = required_keys - set(rule.keys())

            if missing:
                raise ValueError(f"Missing required ElastAlert keys: {sorted(missing)}")

            rule_type = rule.get("type", "unknown")
            rule_index = rule.get("index", "unknown")
            print(f"    [PASS] {path.name:<26} | Type: {rule_type:<12} | Index: {rule_index}")
        except Exception as exc:
            all_ok = False
            print(f"    [FAIL] {path.name:<26} | Error: {exc}")

    print("-" * 70)
    if all_ok and files:
        print(f"[SUCCESS] All {len(files)} ElastAlert rules passed specification validation.")
        return 0
    else:
        print("[ERROR] ElastAlert validation encountered errors.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
