#!/usr/bin/env python3
import json
import sys


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"findings": [], "diagnostics": ["empty input"]}))
        return 0

    payload = json.loads(raw)
    findings = []
    diagnostics = [
        f"plugin_id={payload.get('plugin_id', 'unknown')}",
        f"changed_files={len(payload.get('changed_files', []))}",
    ]

    for file in payload.get("changed_files", []):
        path = file.get("path", "")
        if path.endswith(".sql") and file.get("added", 0) > 20:
            findings.append(
                {
                    "id": "PLG-SQL-001",
                    "rule_id": "PLG-SQL-001",
                    "category": "plugin",
                    "docs_url": "",
                    "title": "Large SQL change detected",
                    "message": f"{path} added lines={file.get('added', 0)}",
                    "severity": "medium",
                    "penalty": 5,
                    "location": {"file": path, "line": None},
                    "tags": ["sql", "plugin"],
                }
            )

    print(json.dumps({"findings": findings, "diagnostics": diagnostics}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
