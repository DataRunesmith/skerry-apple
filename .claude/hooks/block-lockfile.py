#!/usr/bin/env python3
"""PreToolUse hook: block direct edits of Package.resolved."""
import json, sys
data = json.load(sys.stdin)
path = (data.get("tool_input") or {}).get("file_path", "")
if path.endswith("Package.resolved"):
    print("Package.resolved is managed by `swift package resolve`/Renovate; do not edit by hand.", file=sys.stderr)
    sys.exit(2)
