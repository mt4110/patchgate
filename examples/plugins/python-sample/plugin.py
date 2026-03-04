#!/usr/bin/env python3
import json
import sys

payload = json.loads(sys.stdin.read() or "{}")
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
