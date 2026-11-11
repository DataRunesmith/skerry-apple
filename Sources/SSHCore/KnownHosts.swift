import Foundation
import NIOConcurrencyHelpers
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Lagrar sedda värdnycklar (Trust-On-First-Use). Första gången en värd ses
/// lärs nyckeln in; nästa gång jämförs den. En ändrad nyckel är en varningssignal
/// (MITM eller ombyggd server) och avvisas.
///
/// Filformat (en rad per värd): `host:port ssh-ed25519 AAAA...`
/// Standardplats: `~/.skerry/known_hosts`. `path: nil` = endast i minne (test).
public final class KnownHosts {
    public enum Verdict: Sendable, Equatable {
        case trusted                    // matchar lagrad nyckel
        case learned                    // ny värd — nu inlärd
        case changed(stored: String)    // skiljer sig från lagrad nyckel
        case storageFailure             // kunde inte persistera en ny värdnyckel
    }

    private let path: String?
    private let lock = NIOLock()
    private var entries: [String: String]

    public static var defaultPath: String {
        (("~/.skerry/known_hosts") as NSString).expandingTildeInPath
    }

    public init(path: String? = KnownHosts.defaultPath) {
        self.path = path
        self.entries = KnownHosts.loadEntries(path: path)
    }

    private static func hasSafeParentDirectory(_ path: String) -> Bool {
        let directory = (path as NSString).deletingLastPathComponent
        var info = stat()
        if lstat(directory, &info) == 0 {
            return (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR)
        }
        return errno == ENOENT || errno == ENOTDIR
    }
    private static func loadEntries(path: String?) -> (entries: [String: String], failed: Bool) {
        guard let path, hasSafeParentDirectory(path) else {
            return ([:], path != nil)
        }
        // Open without following symlinks and bound the file before reading it.
        let fd = open(path, O_RDONLY | O_NOFOLLOW)
        if fd < 0 {
            return ([:], errno != ENOENT && errno != ENOTDIR)
        }
        defer { _ = close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              info.st_size >= 0, info.st_size <= 4 * 1024 * 1024
        else { return ([:], true) }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress, raw.count)
            }
            if count < 0 {
                if errno == EINTR { continue }
                return ([:], true)
            }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
            if data.count > 4 * 1024 * 1024 { return ([:], true) }
        }
        guard let text = String(data: data, encoding: .utf8) else { return ([:], true) }
        var out: [String: String] = [:]
        for line in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let parts = line.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { continue }
            out[String(parts[0])] = String(parts[1])
        }
        return (out, false)
    }

    /// Avgör hur en presenterad nyckel förhåller sig till vad vi sett tidigare.
    /// Lär in nyckeln (och persisterar) om värden är ny.
    public func check(host: String, port: Int, keyString: String) -> Verdict {
        let id = "\(host):\(port)"
        return lock.withLock {
            if let stored = entries[id] {
                return stored == keyString ? .trusted : .changed(stored: stored)
            }
            guard append(id: id, keyString: keyString) else {
                return .storageFailure
            }
            entries[id] = keyString
            return .learned
        }
    }

    // Anropas med låset hållet. A failed write must fail closed: learning a
    // key only in memory would silently disable TOFU after the next restart.
    private func append(id: String, keyString: String) -> Bool {
        guard let path else { return true } // Explicit in-memory mode for tests.
        let directory = (path as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(
                atPath: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
        } catch {
            return false
        }
        guard Self.hasSafeParentDirectory(path) else { return false }

        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, mode_t(0o600))
        guard fd >= 0 else { return false }
        defer { _ = close(fd) }

        let bytes = Array("\(id) \(keyString)\n".utf8)
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              info.st_size >= 0,
              info.st_size + off_t(bytes.count) <= 4 * 1024 * 1024,
              fchmod(fd, 0o600) == 0
        else {
            return false
        }
        var offset = 0
        while offset < bytes.count {
            let written = bytes.withUnsafeBytes { raw in
                write(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset)
            }
            if written < 0 {
                if errno == EINTR { continue }
                return false
            }
            if written == 0 { return false }
            offset += written
        }
        return fsync(fd) == 0
    }
}
