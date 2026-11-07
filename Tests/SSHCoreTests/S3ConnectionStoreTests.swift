import XCTest
@testable import SSHCore

final class S3ConnectionStoreTests: XCTestCase {
    private func makeConnection(name: String, accessKeyID: String = "AKID") -> S3Connection {
        S3Connection(
            name: name, endpoint: "https://s3.example.com", region: "us-east-1",
            accessKeyID: accessKeyID, secretAccessKey: "secret")
    }

    func testUpsertGetDeleteSorted() {
        let store = S3ConnectionStore(path: nil)
        let a = makeConnection(name: "Example")
        let b = makeConnection(name: "annat-konto")
        store.upsert(a)
        store.upsert(b)

        XCTAssertEqual(store.all().map(\.name), ["annat-konto", "Example"])  // skiftlägesokänslig sort
        XCTAssertEqual(store.get(a.id)?.accessKeyID, "AKID")

        store.delete(b.id)
        XCTAssertEqual(store.all().map(\.name), ["Example"])
    }

    func testPersistAcrossInstances() throws {
        let dir = NSTemporaryDirectory() + "skerry-s3conn-\(ProcessInfo.processInfo.processIdentifier)"
        let path = dir + "/s3connections.json"
        defer { try? FileManager.default.removeItem(atPath: dir) }

        let connection = makeConnection(name: "Example")
        var stored: S3Connection?
        do {
            let s1 = S3ConnectionStore(path: path)
            s1.upsert(connection)
            stored = s1.get(connection.id)
        }
        let s2 = S3ConnectionStore(path: path)
        XCTAssertEqual(s2.get(connection.id), stored)
    }

    func testPersistWritesSecretsOwnerOnlyAndReplacesInsecureFile() throws {
        let dir = NSTemporaryDirectory() + "skerry-s3perm-\(UUID().uuidString)"
        let path = dir + "/s3connections.json"
        defer { try? FileManager.default.removeItem(atPath: dir) }
        func permissions() throws -> Int {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            return try XCTUnwrap(attributes[.posixPermissions] as? NSNumber).intValue & 0o777
        }

        let store = S3ConnectionStore(path: path)
        let connection = makeConnection(name: "Example")
        store.upsert(connection)
        XCTAssertEqual(try permissions(), 0o600)

        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
        store.upsert(connection)
        XCTAssertEqual(try permissions(), 0o600)
        XCTAssertEqual(S3ConnectionStore(path: path).get(connection.id), store.get(connection.id))
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: dir).filter { $0.hasPrefix(".skerry-") }
        XCTAssertEqual(leftovers, [])
    }

    func testEndpointURLParsesValidString() {
        let connection = makeConnection(name: "x")
        XCTAssertEqual(connection.endpointURL?.host, "s3.example.com")
    }

    func testCredentialsMatchStoredKeys() {
        let connection = makeConnection(name: "x", accessKeyID: "MYKEY")
        XCTAssertEqual(connection.credentials.accessKeyID, "MYKEY")
        XCTAssertEqual(connection.credentials.secretAccessKey, "secret")
    }
}
