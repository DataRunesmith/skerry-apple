---
name: pre-push-check
description: Run the project's quality gate (build, tests, diff review against AGENTS.md) before pushing.
disable-model-invocation: true
---

Follow the quality gate in AGENTS.md section 2. Do not push as part of this skill.

1. Run `swift build`, `swift test` and `python3 Tests/cli_password_prompt_test.py`.
   If `swift` is not installed (e.g. Linux without a toolchain), say so explicitly: the check was not run.
2. Review the full diff (`git diff origin/HEAD...` plus untracked files) for correctness,
   security (secrets, host-key verification, key handling), error handling and edge cases.
3. Confirm tests exercise the changed behavior.
4. Report: what passed, what could not be run, and any open findings. Never describe the
   result as fully verified if a check was skipped.
