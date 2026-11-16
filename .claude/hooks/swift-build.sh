#!/usr/bin/env bash
# PostToolUse hook: compile after editing package Swift sources (App/ needs Xcode, so skipped).
f=$(python3 -c 'import json,sys; print((json.load(sys.stdin).get("tool_input") or {}).get("file_path",""))')
case "$f" in
  */Sources/*.swift|*/Tests/*.swift) ;;
  *) exit 0 ;;
esac
command -v swift >/dev/null 2>&1 || exit 0
cd "$(dirname "$0")/../.." && out=$(swift build 2>&1) || { echo "$out" | tail -30 >&2; exit 2; }
