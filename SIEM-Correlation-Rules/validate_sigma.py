#!/usr/bin/env python3
"""
Task 2: Sigma Rule Schema & Integrity Validator (Zero-Dependency)
Author: Aiswarya (ElevanceSkills Cybersecurity Intern)
Purpose: Validates that all Task 2 Sigma YAML detection rules contain mandatory
         Sigma specification fields, structured logsource definitions, and
         valid detection logic conditions without requiring external dependencies.
"""

from pathlib import Path
import re
import sys

folder = Path(__file__).resolve().parent / "sigma-rules"
required = {
    "title", "id", "status", "description",
    "logsource", "detection", "falsepositives", "level"
}


def parse_simple_yaml(text: str) -> dict:
    """Zero-dependency parser for standard single-document Sigma rule YAML."""
    # Split document on --- separator if present, taking the primary document
    docs = re.split(r"^---(?:\s*#.*)?$", text, flags=re.MULTILINE)
    primary_text = docs[0] if docs else text

    result = {}
    current_key = None
    sub_key = None

    lines = primary_text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))

        # Top-level key (indent 0)
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

        # Nested keys
        if current_key:
            if stripped.startswith("- "):
                val = stripped[2:].strip().strip("'\"")
                if sub_key and isinstance(result[current_key], dict) and isinstance(result[current_key].get(sub_key), list):
                    result[current_key][sub_key].append(val)
                else:
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
                    if sv:
                        result[current_key][sk] = sv.strip("'\"")
                    else:
                        result[current_key][sk] = {}
                else:
                    if isinstance(result[current_key].get(sub_key), dict):
                        if sv:
                            result[current_key][sub_key][sk] = sv.strip("'\"")
                        else:
                            result[current_key][sub_key][sk] = []
    return result


def load_yaml(path: Path) -> dict:
    """Attempts yaml.safe_load if PyYAML is installed, else uses zero-dependency parser."""
    with path.open("r", encoding="utf-8-sig") as f:
        content = f.read()

    try:
        import yaml
        documents = [doc for doc in yaml.safe_load_all(content) if doc is not None]
        if documents:
            return documents[0]
    except ImportError:
        pass

    return parse_simple_yaml(content)


def main():
    print("=" * 70)
    print("TASK 2: SIGMA RULE INTEGRITY VALIDATOR (ZERO-DEPENDENCY)")
    print("=" * 70)

    files = sorted(folder.glob("*.yml"))
    print(f"[*] Scanning rule directory: {folder}")
    print(f"[*] Sigma rule files identified: {len(files)}")
    all_ok = True

    for path in files:
        try:
            rule = load_yaml(path)
            missing = required - set(rule.keys())

            if missing:
                raise ValueError(f"Missing required fields: {sorted(missing)}")
            if not isinstance(rule["detection"], dict):
                raise ValueError("The detection section must be a mapping")
            if "condition" not in rule["detection"]:
                raise ValueError("Missing detection condition")

            level = rule.get("level", "unknown").upper()
            title = rule.get("title", path.name)
            print(f"    [PASS] {path.name:<32} | Level: {level:<6} | Title: {title}")
        except Exception as exc:
            all_ok = False
            print(f"    [FAIL] {path.name:<32} | Error: {exc}")

    print("-" * 70)
    if all_ok and files:
        print(f"[SUCCESS] All {len(files)} Sigma rules passed structural and syntax validation.")
        return 0
    else:
        print("[ERROR] Rule validation encountered issues.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
