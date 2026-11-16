#!/usr/bin/env bash
# PostToolUse hook: format edited Swift files if swiftformat is installed.
f=$(python3 -c 'import json,sys; print((json.load(sys.stdin).get("tool_input") or {}).get("file_path",""))')
case "$f" in *.swift) ;; *) exit 0 ;; esac
command -v swiftformat >/dev/null 2>&1 || exit 0
swiftformat --quiet "$f" >/dev/null 2>&1 || true
