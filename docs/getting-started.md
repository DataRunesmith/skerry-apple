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

`SSHCore` and `skerry-cli` also build on Linux. Set your own bundle identifier and signing team in `App/project.yml` before running the app on a device.
