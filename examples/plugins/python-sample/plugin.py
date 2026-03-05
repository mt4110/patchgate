#!/usr/bin/env python3
import json
import sys

raw = sys.stdin.read()
if not raw.strip():
    payload = {}
else:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(json.dumps({"findings": [], "diagnostics": [f"invalid json input: {exc.msg}"]}))
        raise SystemExit(0)

findings = []
for f in payload.get("changed_files", []):
    if f.get("path", "").startswith("infra/") and f.get("added", 0) > 0:
        findings.append(
            {
                "id": "EX-INFRA-001",
                "rule_id": "EX-INFRA-001",
                "category": "plugin",
                "docs_url": "",
                "title": "Infrastructure change detected",
                "message": f"{f.get('path')} changed",
                "severity": "high",
                "penalty": 8,
                "location": {"file": f.get("path"), "line": None},
                "tags": ["infra", "plugin"],
            }
        )

print(json.dumps({"findings": findings, "diagnostics": ["example plugin"]}))
