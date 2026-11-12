import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif
import XCTest
@testable import SSHCore

final class ReviewHardeningTests: XCTestCase {
    func testPinnedParentSurvivesPathReplacement() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let parent = root.appendingPathComponent("parent")
        let moved = root.appendingPathComponent("moved")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        let fd = try PrivateFile.openParent(parent.appendingPathComponent("state").path)
        defer { _ = close(fd) }
        try FileManager.default.moveItem(at: parent, to: moved)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        try PrivateFile.write(Data("safe".utf8), parent: fd, name: "state")
        XCTAssertEqual(try Data(contentsOf: moved.appendingPathComponent("state")), Data("safe".utf8))
        XCTAssertFalse(FileManager.default.fileExists(atPath: parent.appendingPathComponent("state").path))
    }

    func testUntrustedSyncLinkCannotOverwriteTarget() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let target = root.appendingPathComponent("target")
        let link = root.appendingPathComponent("link")
        try Data("original".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: root.path)
        XCTAssertThrowsError(try FolderSyncProvider(path: link.path).push(SyncState()))
        XCTAssertEqual(try Data(contentsOf: target), Data("original".utf8))
    }

    func testKnownHostsReplacementPreservesExistingRecords() throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let path = root.appendingPathComponent("known_hosts")
        try Data("old:22 key".utf8).write(to: path)
        let store = KnownHosts(path: path.path)
        XCTAssertEqual(store.check(host: "new", port: 22, keyString: "other"), .learned)
        XCTAssertEqual(try String(contentsOf: path), "old:22 key\nnew:22 other\n")
        XCTAssertEqual(KnownHosts(path: path.path).check(host: "old", port: 22, keyString: "key"), .trusted)
    }

    func testIndependentStoresPreserveConcurrentAppends() throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("known_hosts").path
        let stores = (0..<12).map { _ in KnownHosts(path: path) }
        DispatchQueue.concurrentPerform(iterations: stores.count) { index in
            XCTAssertEqual(stores[index].check(host: "host-\(index)", port: 22, keyString: "key"), .learned)
        }
        let contents = try String(contentsOfFile: path)
        XCTAssertEqual(contents.split(separator: "\n").count, stores.count)
        let reloaded = KnownHosts(path: path)
        for index in stores.indices {
            XCTAssertEqual(reloaded.check(host: "host-\(index)", port: 22, keyString: "key"), .trusted)
        }
    }

    func testPreCancelledFetchDoesNotCreateCache() async throws {
        let cache = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: cache) }
        let operation = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await ExternalBinaryFetcher.fetch(url: URL(string: "https://example.invalid/file")!,
                expectedSHA256: String(repeating: "0", count: 64), cacheDir: cache, binaryName: "file")
        }
        do {
            _ = try await operation.value
            XCTFail("expected cancellation")
        } catch is CancellationError {}
        XCTAssertFalse(FileManager.default.fileExists(atPath: cache.path))
    }

    func testCancellationStopsInFlightDownloadWithoutCaching() async throws {
        let started = expectation(description: "request started")
        let stopped = expectation(description: "request stopped")
        StalledBinaryProtocol.started = started
        StalledBinaryProtocol.stopped = stopped
        defer {
            StalledBinaryProtocol.started = nil
            StalledBinaryProtocol.stopped = nil
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StalledBinaryProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let cache = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: cache) }
        let operation = Task {
            try await ExternalBinaryFetcher.fetch(url: URL(string: "https://example.invalid/stall")!,
                expectedSHA256: String(repeating: "0", count: 64), cacheDir: cache, binaryName: "file", session: session)
        }
        await fulfillment(of: [started], timeout: 5)
        operation.cancel()
        do {
            _ = try await operation.value
            XCTFail("expected cancellation")
        } catch is CancellationError {}
        await fulfillment(of: [stopped], timeout: 5)
        XCTAssertFalse(FileManager.default.fileExists(atPath: cache.appendingPathComponent("file").path))
    }

    func testBothAuthenticationChallengeCallbacksAreForwarded() async {
        let handler = RejectingChallenges()
        let original = URLSession(configuration: .ephemeral, delegate: handler, delegateQueue: nil)
        defer { original.invalidateAndCancel() }
        let url = URL(string: "https://example.invalid/file")!
        let delegate = BoundedBinaryDownload(url: url, suppliedSession: original)
        let space = URLProtectionSpace(host: "example.invalid", port: 443, protocol: "https",
                                       realm: nil, authenticationMethod: NSURLAuthenticationMethodHTTPBasic)
        let challenge = URLAuthenticationChallenge(protectionSpace: space, proposedCredential: nil,
            previousFailureCount: 0, failureResponse: nil, error: nil, sender: ChallengeSender())
        let sessionCallback = expectation(description: "session callback")
        let taskCallback = expectation(description: "task callback")
        handler.expectedSession = original
        delegate.urlSession(original, didReceive: challenge) { disposition, _ in
            XCTAssertEqual(disposition, .cancelAuthenticationChallenge)
            sessionCallback.fulfill()
        }
        let task = original.dataTask(with: url)
        delegate.urlSession(original, task: task, didReceive: challenge) { disposition, _ in
            XCTAssertEqual(disposition, .rejectProtectionSpace)
            taskCallback.fulfill()
        }
        await fulfillment(of: [sessionCallback, taskCallback], timeout: 5)
        task.cancel()
    }
}

private final class RejectingChallenges: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    weak var expectedSession: URLSession?
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        XCTAssertTrue(session === expectedSession)
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        XCTAssertTrue(session === expectedSession)
        completionHandler(.rejectProtectionSpace, nil)
    }
}

private final class ChallengeSender: NSObject, URLAuthenticationChallengeSender {
    func use(_ credential: URLCredential, for challenge: URLAuthenticationChallenge) {}
    func continueWithoutCredential(for challenge: URLAuthenticationChallenge) {}
    func cancel(_ challenge: URLAuthenticationChallenge) {}
    func performDefaultHandling(for challenge: URLAuthenticationChallenge) {}
    func rejectProtectionSpaceAndContinue(with challenge: URLAuthenticationChallenge) {}
}


private final class StalledBinaryProtocol: URLProtocol {
    static var started: XCTestExpectation?
    static var stopped: XCTestExpectation?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() { Self.started?.fulfill() }
    override func stopLoading() { Self.stopped?.fulfill() }
}
