---
name: new-host-feature
description: Scaffold a new SwiftUI feature view in App/ following the project's conventions.
disable-model-invocation: true
argument-hint: <FeatureName>
---

Create `App/$ARGUMENTS`View.swift modelled on `App/PortForwardView.swift`:
- Wrap the file in `#if canImport(SwiftUI)`; import SwiftUI and SSHCore.
- Put state in a `@MainActor final class <Name>Model: ObservableObject` with `@Published` state and `errorMessage`.
- Keep UI text and doc comments in Swedish, like the surrounding code.
- Put logic that does not need UI in `Sources/SSHCore` (it builds on Linux) and add tests in `Tests/SSHCoreTests`.
- Register new files via `App/project.yml` only if sources are not globbed. Do not run xcodegen here.
Then run the `pre-push-check` skill.
