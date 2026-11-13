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
        case storageFailure             // could not persist a new host key
    }

    private let path: String?
    private let lock = NIOLock()
    private var entries: [String: String]
    private var storageUnavailable: Bool

    public static var defaultPath: String {
        (("~/.skerry/known_hosts") as NSString).expandingTildeInPath
    }

    public init(path: String? = KnownHosts.defaultPath) {
        self.path = path
        let loaded = KnownHosts.loadEntries(path: path)
        self.entries = loaded.entries
        self.storageUnavailable = loaded.failed
    }

    // Keep every lookup anchored to an open directory; reject symlink ancestors.
    private static func openParent(_ path: String, create: Bool) -> Int32 {
        let parts = path.split(separator: "/").map(String.init)
        guard let name = parts.last, name != ".", name != ".." else { return -1 }
        var parent = open(path.hasPrefix("/") ? "/" : ".", O_RDONLY | O_DIRECTORY)
        guard parent >= 0 else { return -1 }
        for component in parts.dropLast() {
            if create {
                if mkdirat(parent, component, mode_t(0o700)) != 0 && errno != EEXIST {
                    let saved = errno
                    _ = close(parent)
                    errno = saved
                    return -1
                }
            }
            let next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            let saved = errno
            _ = close(parent)
            guard next >= 0 else { errno = saved; return -1 }
            parent = next
        }
        return parent
    }
    private static func loadEntries(path: String?) -> (entries: [String: String], failed: Bool) {
        guard let path else { return ([:], false) }
        let parent = openParent(path, create: false)
        guard parent >= 0 else { return ([:], errno != ENOENT) }
        defer { _ = close(parent) }
        // Open without following symlinks and bound the file before reading it.
        let fd = openat(parent, (path as NSString).lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        if fd < 0 {
            return ([:], errno != ENOENT)
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
        guard let entries = parseEntries(data) else { return ([:], true) }
        return (entries, false)
    }

    /// Parses trust records; the last record for a host wins. Returns nil for invalid UTF-8.
    private static func parseEntries(_ data: Data) -> [String: String]? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        var out: [String: String] = [:]
        for line in text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let parts = line.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { continue }
            out[String(parts[0])] = String(parts[1])
        }
        return out
    }

    /// Avgör hur en presenterad nyckel förhåller sig till vad vi sett tidigare.
    /// Lär in nyckeln (och persisterar) om värden är ny.
    public func check(host: String, port: Int, keyString: String) -> Verdict {
        let id = "\(host):\(port)"
        return lock.withLock {
            if storageUnavailable { return .storageFailure }
            if let stored = entries[id] {
                return stored == keyString ? .trusted : .changed(stored: stored)
            }
            switch append(id: id, keyString: keyString) {
            case .failed:
                return .storageFailure
            case .existing(let stored):
                // Another store instance or process persisted this host first.
                entries[id] = stored
                return stored == keyString ? .trusted : .changed(stored: stored)
            case .appended:
                entries[id] = keyString
                return .learned
            }
        }
    }

    // Called with the lock held. A failed write must fail closed: learning a
    // key only in memory would silently disable TOFU after the next restart.
    private enum AppendResult { case appended, existing(String), failed }

    private func append(id: String, keyString: String) -> AppendResult {
        guard let path else { return .appended } // Explicit in-memory mode for tests.
        let parent = Self.openParent(path, create: true)
        guard parent >= 0 else { return .failed }
        defer { _ = close(parent) }
        // A stable sidecar lock serializes read/replace across store instances
        // and processes; locking the replaced inode would lose that protection.
        let lockFD = openat(parent, (path as NSString).lastPathComponent + ".lock",
                            O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, mode_t(0o600))
        guard lockFD >= 0 else { return .failed }
        defer { _ = close(lockFD) }
        var lockInfo = stat()
        guard fstat(lockFD, &lockInfo) == 0,
              (lockInfo.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              flock(lockFD, LOCK_EX) == 0 else { return .failed }
        defer { _ = flock(lockFD, LOCK_UN) }
        let bytes = Array("\(id) \(keyString)\n".utf8)
        guard bytes.count <= 4 * 1024 * 1024 else { return .failed }
        let fd = openat(parent, (path as NSString).lastPathComponent,
                        O_RDONLY | O_NOFOLLOW | O_NONBLOCK, mode_t(0o600))
        if fd < 0 {
            guard errno == ENOENT else { return .failed }
            do {
                try PrivateFile.write(Data("\(id) \(keyString)\n".utf8), parent: parent,
                                      name: (path as NSString).lastPathComponent)
                return .appended
            } catch { return .failed }
        }
        defer { _ = close(fd) }

        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
              info.st_size >= 0,
              info.st_size + off_t(bytes.count) <= 4 * 1024 * 1024,
              fchmod(fd, 0o600) == 0
        else {
            return .failed
        }
        // Build a replacement before publishing: short writes and fsync failures
        // affect only the temporary file, never the original trust records.
        var contents = Data()
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        do {
            contents = try file.read(upToCount: 4 * 1024 * 1024 + 1) ?? Data()
            // Recheck the persisted record under the sidecar lock: the cached map
            // may predate a write by another store instance or process.
            guard let persisted = Self.parseEntries(contents) else { return .failed }
            if let stored = persisted[id] { return .existing(stored) }
            guard contents.count + bytes.count <= 4 * 1024 * 1024 else { return .failed }
            if !contents.isEmpty && contents.last != 10 { contents.append(10) }
            contents.append(contentsOf: bytes)
            guard contents.count <= 4 * 1024 * 1024 else { return .failed }
            try PrivateFile.write(contents, parent: parent, name: (path as NSString).lastPathComponent)
            return .appended
        } catch { return .failed }
    }
}
