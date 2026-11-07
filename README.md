# Skerry for Apple platforms

An SSH and host-management app for macOS, iOS and tvOS, written in Swift.

- `Sources/SSHCore` is the core library: SSH shell, SFTP, port forwarding, host store, known hosts, S3-compatible storage, encrypted sync.
- `Sources/skerry-cli` is a small command-line client built on the library.
- `App/` is the SwiftUI app. The Xcode project is generated from `App/project.yml` with `App/generate-project.sh` (XcodeGen).

## Build and test

Requires Swift 6.1 or newer.

```sh
swift build
swift test
```

`SSHCore` and `skerry-cli` also build on Linux. The app in `App/` builds only in Xcode. Set your own bundle identifier and signing team in `App/project.yml` before running it on a device.
