import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Tak på hur stor en synkfil får vara innan den läses in i minnet.
///
/// Filen kommer per design från en mapp vi INTE kontrollerar — en delad
/// iCloud-/Dropbox-/Drive-katalog. Någon med skrivrättigheter där (eller ett
/// kapat molnkonto) kan lägga dit en fil på flera gigabyte, och
/// `Data(contentsOf:)` allokerar hela längden innan något ens tittat på
/// innehållet. På en telefon är det en omedelbar OOM-död.
///
/// Värdet är identiskt med LinuxApps `MAX_SYNC_FILE_BYTES`. 64 MiB är långt
/// över allt verkligt: ett tillstånd med tusen värdar och lika många snippets
/// ligger under en megabyte. Taket finns för att stänga en klass av angrepp,
/// inte för att begränsa användaren.
public enum SyncFileLimits {
    public static let maxBytes = 64 * 1024 * 1024

    /// Preserve a shared sync-file symlink and atomically update its regular target.
    static func write(_ data: Data, to path: String) throws {
        let parent = try PrivateFile.openParent(path)
        defer { _ = close(parent) }
        try write(data, parent: parent, name: (path as NSString).lastPathComponent, remainingLinks: 40)
    }

    private static func write(_ data: Data, parent: Int32, name: String, remainingLinks: Int) throws {
        var info = stat()
        if fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
           (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFLNK) {
            var directory = stat()
            guard remainingLinks > 0, fstat(parent, &directory) == 0,
                  directory.st_uid == geteuid(), directory.st_mode & 0o022 == 0 else {
                throw CocoaError(.fileWriteNoPermission)
            }
            var buffer = [CChar](repeating: 0, count: 4096)
            let count = readlinkat(parent, name, &buffer, buffer.count)
            guard count > 0, count < buffer.count else { throw CocoaError(.fileWriteInvalidFileName) }
            guard let target = String(bytes: buffer.prefix(count).map { UInt8(bitPattern: $0) }, encoding: .utf8) else {
                throw CocoaError(.fileWriteInvalidFileName) // Never repair invalid UTF-8 into another name.
            }
            let targetDirectory = (target as NSString).deletingLastPathComponent
            // Walk the target directory one component at a time without following
            // links, anchored at the pinned link directory (or "/" for absolute targets).
            let targetParent = try openDirectoryNoFollow(from: parent, path: targetDirectory)
            defer { _ = close(targetParent) }
            // The resolved target directory must itself be trusted.
            var targetDirInfo = stat()
            guard fstat(targetParent, &targetDirInfo) == 0,
                  targetDirInfo.st_uid == geteuid(), targetDirInfo.st_mode & 0o022 == 0 else {
                throw CocoaError(.fileWriteNoPermission)
            }
            let targetName = (target as NSString).lastPathComponent
            var targetInfo = stat()
            guard fstatat(targetParent, targetName, &targetInfo, AT_SYMLINK_NOFOLLOW) == 0,
                  (targetInfo.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) ||
                  (targetInfo.st_mode & mode_t(S_IFMT)) == mode_t(S_IFLNK) else {
                throw CocoaError(.fileWriteInvalidFileName)
            }
            try write(data, parent: targetParent, name: targetName, remainingLinks: remainingLinks - 1)
        } else {
            try PrivateFile.write(data, parent: parent, name: name)
        }
    }

    /// Opens `path` relative to `base` (or "/" when absolute), refusing symlinks in every walked component.
    private static func openDirectoryNoFollow(from base: Int32, path: String) throws -> Int32 {
        var fd: Int32
        var components = path
        if path.hasPrefix("/") {
            // Absolute targets: resolve system-level links such as /var once (as
            // PrivateFile.openParent does), then walk without following links.
            // The resolved directory is authorized by the caller before any write.
            components = try PrivateFile.canonicalDirectory(path)
            fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        } else {
            fd = dup(base)
        }
        guard fd >= 0 else { throw CocoaError(.fileWriteInvalidFileName) }
        for part in components.split(separator: "/") where part != "." {
            let next = openat(fd, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            _ = close(fd)
            guard next >= 0 else { throw CocoaError(.fileWriteInvalidFileName) }
            fd = next
        }
        return fd
    }

    /// Läser en fil men vägrar mer än ``maxBytes``.
    ///
    /// Läser via `read(upToCount: maxBytes + 1)` i stället för att först
    /// fråga om filstorleken och sedan läsa: en storlekskoll följd av en
    /// läsning är två separata operationer, och filen kan växa emellan. Här
    /// är gränsen en egenskap hos själva läsningen, så det finns inget glapp
    /// att utnyttja.
    public static func read(_ path: String) throws -> Data {
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maxBytes + 1) ?? Data()
        guard data.count <= maxBytes else {
            throw SyncFileError.tooLarge(maxBytes: maxBytes)
        }
        return data
    }
}

public enum SyncFileError: Error, Equatable, CustomStringConvertible {
    case tooLarge(maxBytes: Int)

    public var description: String {
        switch self {
        case .tooLarge(let maxBytes):
            return "synkfilen är större än \(maxBytes / 1024 / 1024) MiB och lästes inte in — "
                + "en fil den här storleken kommer inte från Skerry"
        }
    }
}


/// En synktransport: hämta fjärrtillstånd och skriv tillbaka det sammanslagna.
/// Medvetet minimal så olika ryggar kan implementeras — iCloud Drive, Dropbox,
/// Syncthing, en Git-mapp, WebDAV — utan att kärnan bryr sig om vilken.
public protocol SyncProvider: Sendable {
    func pull() throws -> SyncState?
    func push(_ state: SyncState) throws
}

/// Enklaste transporten: en JSON-fil i en mapp som något annat synkar mellan
/// enheter (iCloud Drive-behållare, Dropbox, Syncthing, en klonad Git-mapp …).
/// Ingen inloggning, ingen server — bara en fil.
public struct FolderSyncProvider: SyncProvider {
    private let path: String

    public init(path: String) {
        self.path = (path as NSString).expandingTildeInPath
    }

    public func pull() throws -> SyncState? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        return try JSONDecoder().decode(SyncState.self, from: SyncFileLimits.read(path))
    }

    public func push(_ state: SyncState) throws {
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(state)
        guard data.count <= SyncFileLimits.maxBytes else {
            throw SyncFileError.tooLarge(maxBytes: SyncFileLimits.maxBytes)
        }
        try SyncFileLimits.write(data, to: path)
    }
}
