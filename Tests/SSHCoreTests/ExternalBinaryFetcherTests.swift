import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import SSHCore

/// Riktiga nätverksanrop mot en pinnad, oföränderlig GitHub-tag (inte ett
/// mockat svar) — samma rigör som repots övriga "verifierat mot RIKTIGT
/// X"-tester. `raw.githubusercontent.com/torvalds/linux/v6.6/COPYING` ändras
/// aldrig (tagg-pinnad), så testet är deterministiskt trots att det går mot
/// internet. Checksumman nedan verifierades separat (`curl` + `sha256sum`)
/// INNAN testet skrevs — testet bevisar alltså att fetcher-koden känner igen
/// en korrekt checksumma, inte att den bara accepterar vad den själv laddar ner.
final class ExternalBinaryFetcherTests: XCTestCase {
    private let sampleURL = URL(string: "https://raw.githubusercontent.com/torvalds/linux/v6.6/COPYING")!
    private let sampleSHA256 = "fb5a425bd3b3cd6071a3a9aff9909a859e7c1158d54d32e07658398cd67eb6a0"

    private func freshCacheDir() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("skerry-binfetch-test-\(UUID().uuidString)")
    }

    /// Fetches the shared sample while treating GitHub's anonymous rate limit
    /// as an unavailable-network condition rather than a product failure.
    private func fetchSample(cacheDir: URL, expectedSHA256: String? = nil) async throws -> URL {
        do {
            return try await ExternalBinaryFetcher.fetch(
                url: sampleURL,
                expectedSHA256: expectedSHA256 ?? sampleSHA256,
                cacheDir: cacheDir,
                binaryName: "sample")
        } catch ExternalBinaryError.downloadFailed(let message) where message.contains("HTTP 429") {
            throw XCTSkip("Nätverket svarade med HTTP 429 (rate limit): \(message)")
        }
    }

    override func setUp() async throws {
        // Nätverksberoende — hoppa tydligt över istället för att låta ett
        // sandboxat/offline CI-läge misslyckas förvirrande.
        var request = URLRequest(url: sampleURL)
        request.httpMethod = "HEAD"
        request.timeoutInterval = 5
        do {
            _ = try await URLSession.shared.data(for: request)
        } catch {
            throw XCTSkip("Ingen nätverksåtkomst i den här miljön: \(error)")
        }
    }

    func testDownloadsAndVerifiesRealFile() async throws {
        let cacheDir = freshCacheDir()
        defer { try? FileManager.default.removeItem(at: cacheDir) }

        let path = try await fetchSample(cacheDir: cacheDir)

        XCTAssertTrue(FileManager.default.fileExists(atPath: path.path))
        let data = try Data(contentsOf: path)
        XCTAssertEqual(ExternalBinaryFetcher.sha256Hex(data), sampleSHA256)

        let attrs = try FileManager.default.attributesOfItem(atPath: path.path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
        XCTAssertEqual(perms & 0o111, 0o111, "binären ska vara körbar (chmod 755)")
    }

    func testSecondFetchIsCacheHitAndSkipsNetwork() async throws {
        let cacheDir = freshCacheDir()
        defer { try? FileManager.default.removeItem(at: cacheDir) }

        let first = try await fetchSample(cacheDir: cacheDir)

        // En URL som INTE går att nå — om detta andra anrop av misstag
        // gjorde ett nätverksanrop skulle det kasta/hänga, inte returnera
        // tyst. Bevisar att cache-träffen faktiskt undviker nätverket, inte
        // bara att resultatet råkar stämma.
        let unreachable = URL(string: "https://127.0.0.1.invalid/does-not-exist")!
        let second = try await ExternalBinaryFetcher.fetch(
            url: unreachable, expectedSHA256: sampleSHA256,
            cacheDir: cacheDir, binaryName: "sample")

        XCTAssertEqual(first, second)
    }

    func testWrongChecksumIsRejectedAndNeverCached() async throws {
        let cacheDir = freshCacheDir()
        defer { try? FileManager.default.removeItem(at: cacheDir) }

        let wrongChecksum = String(repeating: "0", count: 64)
        do {
            _ = try await fetchSample(cacheDir: cacheDir, expectedSHA256: wrongChecksum)
            XCTFail("expected checksumMismatch")
        } catch ExternalBinaryError.checksumMismatch(let expected, let actual) {
            XCTAssertEqual(expected, wrongChecksum)
            XCTAssertEqual(actual, sampleSHA256)
        }

        // Den felaktiga nedladdningen ska ALDRIG ha skrivits till disk.
        XCTAssertFalse(FileManager.default.fileExists(atPath: cacheDir.appendingPathComponent("sample").path))
    }

    func testCorruptedCacheEntryIsRedownloaded() async throws {
        let cacheDir = freshCacheDir()
        defer { try? FileManager.default.removeItem(at: cacheDir) }
        try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
        let destination = cacheDir.appendingPathComponent("sample")
        try Data("korrupt-skräp, inte den riktiga filen".utf8).write(to: destination)

        let path = try await fetchSample(cacheDir: cacheDir)

        let data = try Data(contentsOf: path)
        XCTAssertEqual(ExternalBinaryFetcher.sha256Hex(data), sampleSHA256)
    }

}

final class ExternalBinaryFetcherValidationTests: XCTestCase {
    private let sampleSHA256 = "fb5a425bd3b3cd6071a3a9aff9909a859e7c1158d54d32e07658398cd67eb6a0"

    private func freshCacheDir() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("skerry-binfetch-test-\(UUID().uuidString)")
    }

    func testRejectsPathTraversalBeforeNetworkOrFilesystemChanges() async throws {
        let cacheDir = freshCacheDir()
        defer { try? FileManager.default.removeItem(at: cacheDir) }
        let unreachable = URL(string: "https://127.0.0.1.invalid/never-fetch")!
        do {
            _ = try await ExternalBinaryFetcher.fetch(
                url: unreachable,
                expectedSHA256: sampleSHA256,
                cacheDir: cacheDir,
                binaryName: "../outside")
            XCTFail("expected invalidBinaryName")
        } catch ExternalBinaryError.invalidBinaryName {
            // Expected: reject before creating the cache directory or making a request.
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: cacheDir.path))
    }

    func testRejectsMalformedChecksumBeforeNetworkOrFilesystemChanges() async throws {
        let cacheDir = freshCacheDir()
        defer { try? FileManager.default.removeItem(at: cacheDir) }
        let unreachable = URL(string: "https://127.0.0.1.invalid/never-fetch")!
        do {
            _ = try await ExternalBinaryFetcher.fetch(
                url: unreachable,
                expectedSHA256: "not-a-sha256",
                cacheDir: cacheDir,
                binaryName: "sample")
            XCTFail("expected invalidChecksum")
        } catch ExternalBinaryError.invalidChecksum {
            // Expected: reject before creating the cache directory or making a request.
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: cacheDir.path))
    }

}

private final class BinaryResponseProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let oversized = request.url!.path == "/oversized"
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
            headerFields: oversized ? ["Content-Length": "268435457"] : [:])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if request.url!.path == "/stream-oversized" {
            let chunk = Data(repeating: 0, count: 1024 * 1024)
            for _ in 0..<257 { client?.urlProtocol(self, didLoad: chunk) }
        } else if !oversized {
            client?.urlProtocol(self, didLoad: Data("first".utf8))
            client?.urlProtocol(self, didLoad: Data("second".utf8))
        }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class ExternalBinaryStreamingTests: XCTestCase {
    func testRedirectDestinationsAreValidatedBeforeFollowing() throws {
        let source = URL(string: "https://example.invalid/source")!
        let response = HTTPURLResponse(url: source, statusCode: 302, httpVersion: nil, headerFields: nil)!
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        for destination in ["http://example.invalid/file", "https://user:password@example.invalid/file", "https://example.invalid/file"] {
            let delegate = BoundedBinaryDownload(url: source)
            let request = URLRequest(url: URL(string: destination)!)
            let task = session.dataTask(with: source)
            var followed: URLRequest?
            delegate.urlSession(session, task: task, willPerformHTTPRedirection: response,
                newRequest: request, completionHandler: { followed = $0 })
            XCTAssertEqual(followed != nil, destination == "https://example.invalid/file")
            task.cancel()
        }
    }

    func testInjectedSessionStreamsAndRejectsOversizedContentLength() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [BinaryResponseProtocol.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let cache = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: cache) }
        let expected = ExternalBinaryFetcher.sha256Hex(Data("firstsecond".utf8))
        let path = try await ExternalBinaryFetcher.fetch(url: URL(string: "https://example.invalid/chunks")!,
            expectedSHA256: expected, cacheDir: cache, binaryName: "chunks", session: session)
        XCTAssertEqual(try Data(contentsOf: path), Data("firstsecond".utf8))
        for endpoint in ["oversized", "stream-oversized"] {
            do {
                _ = try await ExternalBinaryFetcher.fetch(url: URL(string: "https://example.invalid/\(endpoint)")!,
                    expectedSHA256: expected, cacheDir: cache, binaryName: "oversized", session: session)
                XCTFail("expected downloadTooLarge")
            } catch ExternalBinaryError.downloadTooLarge {}
        }
    }
}
