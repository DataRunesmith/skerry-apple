import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Hämtar och cachar en enskild extern binär (t.ex. `wireguard-go`,
/// `tailscale`) från en URL, verifierad mot en känd SHA256-checksumma innan
/// den någonsin skrivs till disk som "giltig". Motivering:
/// "Native WireGuard/Tailscale — inget externt beroende": Skerry ska kunna
/// ladda ner+köra dessa verktyg själv istället för att kräva att användaren
/// installerat dem separat, men en nedladdad binär är samma tillitsnivå som
/// ett `curl | sudo bash`-skript om checksumman inte verifieras.
///
/// Medvetet GENERISK (URL + förväntad checksumma in, verifierad sökväg ut) —
/// varken WireGuard- eller Tailscale-specifik. Anroparen (framtida UI-lager)
/// äger plattforms-/arkitekturval av URL och det publicerade checksum-värdet;
/// den här typen äger bara hämta+verifiera+cacha-mekaniken, så den kan
/// återanvändas för båda verktygen (och andra framtida) utan duplicering.
public enum ExternalBinaryError: Error, Sendable, Equatable {
    case downloadFailed(String)
    case checksumMismatch(expected: String, actual: String)
    case cacheWriteFailed(String)
    case invalidBinaryName
    case invalidChecksum
    case downloadTooLarge
}

public enum ExternalBinaryFetcher {
    /// Hämtar `url` till `cacheDir/binaryName` om den inte redan finns där
    /// med RÄTT checksumma (idempotent — ett andra anrop med samma
    /// parametrar gör ingen nätverkstrafik alls). En redan cachad fil med FEL
    /// checksumma (korrupt/manipulerad) tas bort och laddas ner på nytt,
    /// aldrig litad på tyst.
    ///
    /// Checksumman verifieras mot de NEDLADDADE bytesen INNAN något skrivs
    /// till disk — en manipulerad/fel binär hamnar aldrig i cachen ens
    /// tillfälligt.
    public static func fetch(
        url: URL,
        expectedSHA256: String,
        cacheDir: URL,
        binaryName: String,
        session: URLSession = .shared
    ) async throws -> URL {
        try Task.checkCancellation()
        guard
            !binaryName.isEmpty,
            binaryName != ".",
            binaryName != "..",
            !binaryName.contains("/"),
            !binaryName.contains("\\"),
            !binaryName.contains("\0")
        else {
            throw ExternalBinaryError.invalidBinaryName
        }
        guard url.scheme?.lowercased() == "https", url.host != nil, url.user == nil, url.password == nil else {
            throw ExternalBinaryError.downloadFailed("only HTTPS URLs without embedded credentials are allowed")
        }
        let expected = expectedSHA256.lowercased()
        guard expected.utf8.count == 64,
              expected.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else {
            throw ExternalBinaryError.invalidChecksum
        }

        do {
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
            if (try? FileManager.default.destinationOfSymbolicLink(atPath: cacheDir.path)) != nil {
                throw ExternalBinaryError.cacheWriteFailed("cache directory must not be a symbolic link")
            }
            let attributes = try FileManager.default.attributesOfItem(atPath: cacheDir.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory else {
                throw ExternalBinaryError.cacheWriteFailed("cache path is not a directory")
            }
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: cacheDir.path)
        } catch let error as ExternalBinaryError {
            throw error
        } catch {
            throw ExternalBinaryError.cacheWriteFailed("\(error)")
        }

        let destination = cacheDir.appendingPathComponent(binaryName)
        let cachedIsSymlink = (try? FileManager.default.destinationOfSymbolicLink(atPath: destination.path)) != nil
        if !cachedIsSymlink,
           let existing = try? Data(contentsOf: destination),
           sha256Hex(existing) == expected {
            return destination
        }
        // Finns men med fel checksumma (korrupt eller ett gammalt, felaktigt
        // cachat försök) — städa bort tyst, hämta rent på nytt nedan.
        try? FileManager.default.removeItem(at: destination)

        let data: Data
        do {
            data = try await BoundedBinaryDownload.download(url, suppliedSession: session)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as ExternalBinaryError {
            throw error
        } catch {
            if Task.isCancelled { throw CancellationError() }
            throw ExternalBinaryError.downloadFailed("network request failed")
        }

        try Task.checkCancellation()
        let actual = sha256Hex(data)
        guard actual == expected else {
            throw ExternalBinaryError.checksumMismatch(expected: expected, actual: actual)
        }

        do {
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
            // Skriv till en temporär fil i SAMMA katalog, byt sedan namn —
            // en process som läser `destination` mitt under en nedladdning
            // ska aldrig kunna se en halvskriven fil.
            let tmp = cacheDir.appendingPathComponent(".\(binaryName).\(UUID().uuidString).tmp")
            defer { try? FileManager.default.removeItem(at: tmp) }
            try Task.checkCancellation()
            try data.write(to: tmp)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tmp.path)
            try Task.checkCancellation()
            _ = try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: tmp, to: destination)
        } catch {
            throw ExternalBinaryError.cacheWriteFailed("\(error)")
        }

        return destination
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

// A separate session retains the injected configuration (including URLProtocol mocks),
// while enforcing redirect and memory limits before URLSession follows or buffers data.
final class BoundedBinaryDownload: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private static let limit = 256 * 1024 * 1024
    private let suppliedSession: URLSession?
    private var data = Data()

    init(url: URL, suppliedSession: URLSession? = nil) {
        self.suppliedSession = suppliedSession
        super.init()
    }
    private var failure: Error?
    private var continuation: CheckedContinuation<Data, Error>?

    private static func allowed(_ url: URL) -> Bool {
        url.scheme?.lowercased() == "https" && url.host != nil && url.user == nil && url.password == nil
    }

    private let cancellationLock = NSLock()
    private var cancelled = false
    private var activeTask: URLSessionDataTask?

    private func start(_ task: URLSessionDataTask) {
        cancellationLock.lock()
        activeTask = task
        if cancelled { task.cancel() }
        task.resume()
        cancellationLock.unlock()
    }

    private func cancel() {
        cancellationLock.lock()
        cancelled = true
        activeTask?.cancel()
        cancellationLock.unlock()
    }

    static func download(_ url: URL, suppliedSession: URLSession) async throws -> Data {
        let delegate = BoundedBinaryDownload(url: url, suppliedSession: suppliedSession)
        // The supplied delegate queue preserves the caller's challenge execution context.
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: suppliedSession.configuration, delegate: delegate, delegateQueue: queue)
        defer { session.invalidateAndCancel() }
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            let data: Data = try await withCheckedThrowingContinuation { continuation in
                delegate.continuation = continuation
                delegate.start(session.dataTask(with: url))
            }
            try Task.checkCancellation()
            return data
        }, onCancel: { delegate.cancel() })
    }

    // URLSession.delegate is the supported accessor for both delegate protocols.
    // Forward on the supplied queue, retaining its session identity for pinning policies.
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let original = suppliedSession, let handler = original.delegate else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        original.delegateQueue.addOperation {
            #if canImport(ObjectiveC)
            guard handler.responds(to: #selector(URLSessionDelegate.urlSession(_:didReceive:completionHandler:))) else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            handler.urlSession?(original, didReceive: challenge, completionHandler: completionHandler)
            #else
            handler.urlSession(original, didReceive: challenge, completionHandler: completionHandler)
            #endif
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let original = suppliedSession, let handler = original.delegate as? URLSessionTaskDelegate else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        original.delegateQueue.addOperation {
            #if canImport(ObjectiveC)
            guard handler.responds(to: #selector(URLSessionTaskDelegate.urlSession(_:task:didReceive:completionHandler:))) else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            handler.urlSession?(original, task: task, didReceive: challenge, completionHandler: completionHandler)
            #else
            handler.urlSession(original, task: task, didReceive: challenge, completionHandler: completionHandler)
            #endif
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        guard let url = request.url, Self.allowed(url) else {
            failure = ExternalBinaryError.downloadFailed("redirect destination must be HTTPS without embedded credentials")
            completionHandler(nil)
            task.cancel()
            return
        }
        completionHandler(request)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse,
              (200...299).contains(http.statusCode),
              let url = http.url, Self.allowed(url) else {
            failure = ExternalBinaryError.downloadFailed("HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1) or insecure redirect")
            completionHandler(.cancel)
            return
        }
        guard response.expectedContentLength <= Int64(Self.limit) else {
            failure = ExternalBinaryError.downloadTooLarge
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        guard failure == nil else { return }
        guard chunk.count <= Self.limit - data.count else {
            failure = ExternalBinaryError.downloadTooLarge
            data.removeAll()
            dataTask.cancel()
            return
        }
        data.append(chunk)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = failure ?? error {
            continuation?.resume(throwing: error)
        } else {
            continuation?.resume(returning: data)
        }
        continuation = nil
    }
}
