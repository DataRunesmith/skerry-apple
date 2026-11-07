import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Writes files that hold credentials (WireGuard private keys, S3 secret keys).
enum PrivateFile {
    /// Writes `data` to `path` so it is never readable by others, not even
    /// briefly: the bytes go to a 0600 temporary file created with `mkstemp` in
    /// the same directory, which then replaces `path` atomically with `rename`.
    static func write(_ data: Data, to path: String) throws {
        let directory = (path as NSString).deletingLastPathComponent
        var template = ((directory.isEmpty ? "." : directory) + "/.skerry-XXXXXX").utf8CString
        let fd = template.withUnsafeMutableBufferPointer { mkstemp($0.baseAddress!) }
        guard fd >= 0 else { throw posixError() }
        let temporaryPath = template.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { _ = unlink(temporaryPath) }
        guard fchmod(fd, 0o600) == 0 else { throw posixError() }
        try file.write(contentsOf: data)
        try file.synchronize()
        try file.close()
        guard rename(temporaryPath, path) == 0 else { throw posixError() }
    }

    private static func posixError() -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
}
