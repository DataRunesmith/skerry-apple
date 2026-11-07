// swift-tools-version:5.9
import PackageDescription

// Skerry: core library plus a CLI that proves the SSH transport.
// SSHCore and skerry-cli build on Linux AND Apple platforms (pure SwiftNIO code).
// The terminal UI (SwiftTerm) lives in App/ and is only built in Xcode; see docs/architecture.md.
// The Linux, Windows and Android apps live in their own repos (skerry-linux,
// skerry-windows and skerry-android) and share no code with this package.
let package = Package(
    name: "skerry",
    platforms: [
        .macOS(.v13), .iOS(.v16),
    ],
    products: [
        .library(name: "SSHCore", targets: ["SSHCore"]),
        .executable(name: "skerry-cli", targets: ["skerry-cli"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.15.1"),
        // Pinned exactly: newer releases fail to compile on Windows under Swift 6 strict concurrency.
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.105.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.1.1"),
    ],
    targets: [
        .target(
            name: "SSHCore",
            dependencies: [
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .executableTarget(
            name: "skerry-cli",
            dependencies: ["SSHCore"]
        ),
        .testTarget(
            name: "SSHCoreTests",
            dependencies: [
                "SSHCore",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ]
        ),
    ]
)
