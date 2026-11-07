import XCTest
@testable import SSHCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

final class WireGuardProfileStoreTests: XCTestCase {
    private func makeTemporaryDirectory() throws -> String {
        var template = (NSTemporaryDirectory() + "skerry-wireguard-XXXXXX").utf8CString
        guard template.withUnsafeMutableBufferPointer({ mkdtemp($0.baseAddress!) != nil }) else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let dir = template.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: dir)
            guard let mode = attributes[.posixPermissions] as? NSNumber, mode.intValue & 0o777 == 0o700 else {
                throw POSIXError(.EACCES)
            }
        } catch {
            try? FileManager.default.removeItem(atPath: dir)
            throw error
        }
        return dir
    }

    private func makeConfig(privateKey: String) -> WireGuardConfig {
        var config = WireGuardConfig()
        config.interface.privateKey = privateKey
        config.interface.address = ["10.0.0.2/24"]
        config.peers = [WireGuardConfig.Peer(publicKey: "pk=", allowedIPs: ["0.0.0.0/0"])]
        return config
    }

    func testUpsertGetDeleteSorted() {
        let store = WireGuardProfileStore(path: nil)
        let home = WireGuardProfile(name: "Hemma", config: makeConfig(privateKey: "a="))
        let work = WireGuardProfile(name: "jobbet", config: makeConfig(privateKey: "b="))
        store.upsert(home)
        store.upsert(work)

        XCTAssertEqual(store.all().map(\.name), ["Hemma", "jobbet"])  // skiftlägesokänslig sort
        XCTAssertEqual(store.get(home.id)?.config.interface.privateKey, "a=")

        store.delete(work.id)
        XCTAssertEqual(store.all().map(\.name), ["Hemma"])
    }

    func testPersistAcrossInstances() throws {
        let dir = try makeTemporaryDirectory()
        let path = dir + "/wireguard.json"
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let profile = WireGuardProfile(name: "Hemma", config: makeConfig(privateKey: "a="))
        var stored: WireGuardProfile?
        do {
            let s1 = WireGuardProfileStore(path: path)
            s1.upsert(profile)
            stored = s1.get(profile.id)
        }
        let s2 = WireGuardProfileStore(path: path)
        XCTAssertEqual(s2.get(profile.id), stored)
    }

    /// Bevisar hela vägen: text -> WireGuardConfig -> WireGuardProfile ->
    /// lagrad JSON -> ny store-instans -> tillbaka till .conf-text, allt
    /// identiskt med originalet.
    func testFullRoundTripThroughStoreAndBackToConfText() throws {
        let privateKey = ProcessInfo.processInfo.environment["SKERRY_TEST_WIREGUARD_PRIVATE_KEY"]
            ?? "safe-test-private-key"
        let text = """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 10.0.0.2/24

        [Peer]
        PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
        AllowedIPs = 0.0.0.0/0
        Endpoint = vpn.example.com:51820
        """
        let config = WireGuardConfig(text: text)
        let profile = WireGuardProfile(name: "Hemma", config: config)

        let dir = try makeTemporaryDirectory()
        let path = dir + "/wireguard.json"
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let s1 = WireGuardProfileStore(path: path)
        s1.upsert(profile)

        let s2 = WireGuardProfileStore(path: path)
        let reloaded = s2.get(profile.id)
        XCTAssertTrue(reloaded?.config == config)
        XCTAssertTrue(reloaded?.config.rendered() == config.rendered())
    }

    func testPersistCreatesPrivateFileAndReplacesInsecureFile() throws {
        let dir = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let sharedDir = dir + "/shared"
        try FileManager.default.createDirectory(atPath: sharedDir, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: sharedDir)
        let path = sharedDir + "/wireguard.json"

        let store = WireGuardProfileStore(path: path)
        let profile = WireGuardProfile(name: "Home", config: makeConfig(privateKey: "test-key"))
        store.upsert(profile)
        func permissions() throws -> Int {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            return try XCTUnwrap(attributes[.posixPermissions] as? NSNumber).intValue & 0o777
        }
        XCTAssertEqual(try permissions(), 0o600)

        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
        store.upsert(profile)
        XCTAssertEqual(try permissions(), 0o600)
        XCTAssertNotNil(WireGuardProfileStore(path: path).get(profile.id))
    }
}
