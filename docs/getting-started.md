# Get started

## Requirements

Swift 6.1 or newer. The app in `App/` builds only in Xcode; the Xcode project is generated from `App/project.yml` with `App/generate-project.sh` (XcodeGen).

## Layout

- `Sources/SSHCore` is the core library: SSH shell, SFTP, port forwarding, host store, known hosts, S3-compatible storage, encrypted sync.
- `Sources/skerry-cli` is a small command-line client built on the library.
- `App/` is the SwiftUI app.

## Build and test

```sh
swift build
swift test
```

<!-- coderabbit-ai-generated:v1 -->

<!-- coderabbit-ai-generated-section:v1:781965506a6c17ee4f671bf279864a87ea9409e31c5154f49e909bdd102808e2 -->

`SSHCore` and `skerry-cli` also build on Linux. Before running the iOS app on a device, set your own bundle identifier and signing team in `App/project.yml`. Those changes alone are insufficient: for manual signing, also install a development provisioning profile matching your bundle identifier, team, and device, and set the iOS target’s Debug `PROVISIONING_PROFILE_SPECIFIER` to its name. Alternatively, configure automatic signing (`CODE_SIGN_STYLE: Automatic`), remove the manual provisioning profile specifiers for that target, and let Xcode manage signing with your team. Regenerate the Xcode project after updating `App/project.yml`.

<!-- /coderabbit-ai-generated:v1 -->
