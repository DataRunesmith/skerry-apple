import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Writes files that hold credentials (WireGuard private keys, S3 secret keys).
enum PrivateFile {
    /// Pin the parent before creating or renaming anything. Ancestor symlinks are
    /// resolved once, then every component is opened without following links.
    static func openParent(_ path: String) throws -> Int32 {
        let directory = try canonicalDirectory(
            URL(fileURLWithPath: path).deletingLastPathComponent().path)
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw posixError() }
        for part in directory.split(separator: "/") {
            let next = openat(fd, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            let error = posixError()
            _ = close(fd)
            guard next >= 0 else { throw error }
            fd = next
        }
        return fd
    }

    /// Physical path of an existing directory (`realpath`). Unlike
    /// `resolvingSymlinksInPath`, this keeps `/private` on Darwin, so every
    /// component of the result is a real directory that `O_NOFOLLOW` accepts.
    static func canonicalDirectory(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else { throw posixError() }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    static func write(_ data: Data, to path: String) throws {
        let parent = try openParent(path)
        defer { _ = close(parent) }
        try write(data, parent: parent, name: (path as NSString).lastPathComponent)
    }

    static func write(_ data: Data, parent: Int32, name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0") else {
            throw CocoaError(.fileWriteInvalidFileName)
        }
        let temporaryName = ".skerry-" + UUID().uuidString
        let fd = openat(parent, temporaryName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw posixError() }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { _ = unlinkat(parent, temporaryName, 0) }
        guard fchmod(fd, 0o600) == 0 else { throw posixError() }
        try file.write(contentsOf: data)
        try file.synchronize()
        try file.close()
        guard renameat(parent, temporaryName, parent, name) == 0 else { throw posixError() }
        // Make the directory-entry change durable, and report a failure to do so.
        guard fsync(parent) == 0 else { throw posixError() }
    }

    private static func posixError() -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
}
