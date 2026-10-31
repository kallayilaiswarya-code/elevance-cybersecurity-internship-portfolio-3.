from pathlib import Path
import yaml

folder = Path(__file__).resolve().parent / "sigma-rules"
required = {
    "title", "id", "status", "description",
    "logsource", "detection", "falsepositives", "level"
}

files = sorted(folder.glob("*.yml"))
print(f"Sigma files found: {len(files)}")
all_ok = True

for path in files:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            documents = [doc for doc in yaml.safe_load_all(f) if doc is not None]

        if len(documents) != 1:
            raise ValueError(
                f"Expected one rule document, found {len(documents)}"
            )

        rule = documents[0]
        missing = required - set(rule)

        if missing:
            raise ValueError(f"Missing required fields: {sorted(missing)}")
        if not isinstance(rule["detection"], dict):
            raise ValueError("The detection section must be a mapping")
        if "condition" not in rule["detection"]:
            raise ValueError("Missing detection condition")

        print(f"PASS: {path.name} — {rule['title']}")
    except Exception as exc:
        all_ok = False
        print(f"CHECK NEEDED: {path.name} — {exc}")

print("\nResult:", "All files passed basic checks" if all_ok else
      "Some files need corrections")
