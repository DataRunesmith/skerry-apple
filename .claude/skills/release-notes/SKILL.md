---
name: release-notes
description: Draft release notes from merged PRs and commits since the last tag.
disable-model-invocation: true
---

1. Find the last release tag (`git describe --tags --abbrev=0`; if none, use the full history).
2. List commits since then (`git log <tag>..HEAD --oneline`) and group them: Features, Fixes, Security, Chore.
3. Write short user-facing notes in Swedish, skipping pure CI/dependency noise unless security-relevant.
4. Output the draft only; do not tag, push or publish.
