import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

#if canImport(Darwin) || canImport(Glibc)
/// An opened local upload entry. Children are opened relative to the held
/// directory descriptor, so replacing a path with a symlink cannot redirect a read.
public final class SFTPUploadSource {
    private let descriptor: Int32
    public let isDirectory: Bool

    private init(descriptor: Int32, isDirectory: Bool) {
        self.descriptor = descriptor
        self.isDirectory = isDirectory
    }

    deinit { _ = close(descriptor) }

    private static func posixError(_ code: Int32 = errno) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(code))
    }

    public static func open(_ url: URL) throws -> SFTPUploadSource {
        var path = url.path
        while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
        return try openEntry(parent: AT_FDCWD, name: path)
    }

    public func child(named name: String) throws -> SFTPUploadSource {
        guard isDirectory, !name.isEmpty, name != ".", name != "..", !name.contains("/") else {
            throw Self.posixError(EINVAL)
        }
        return try Self.openEntry(parent: descriptor, name: name)
    }

    private static func openEntry(parent: Int32, name: String) throws -> SFTPUploadSource {
        var before = stat()
        guard fstatat(parent, name, &before, AT_SYMLINK_NOFOLLOW) == 0 else { throw posixError() }
        let kind = before.st_mode & mode_t(S_IFMT)
        guard kind == mode_t(S_IFREG) || kind == mode_t(S_IFDIR) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL),
                          userInfo: [NSLocalizedDescriptionKey: "Symboliska länkar och specialfiler kan inte laddas upp."])
        }
        let directory = kind == mode_t(S_IFDIR)
        let flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | (directory ? O_DIRECTORY : 0)
        let fd = openat(parent, name, flags)
        guard fd >= 0 else { throw posixError() }
        var after = stat()
        guard fstat(fd, &after) == 0 else {
            let error = posixError()
            _ = close(fd)
            throw error
        }
        guard after.st_dev == before.st_dev, after.st_ino == before.st_ino,
              after.st_mode & mode_t(S_IFMT) == kind else {
            _ = close(fd)
            throw posixError(ESTALE)
        }
        return SFTPUploadSource(descriptor: fd, isDirectory: directory)
    }

    public func childNames() throws -> [String] {
        guard isDirectory else { throw Self.posixError(ENOTDIR) }
        let copy = dup(descriptor)
        guard copy >= 0 else { throw Self.posixError() }
        guard let directory = fdopendir(copy) else {
            let error = Self.posixError()
            _ = close(copy)
            throw error
        }
        defer { closedir(directory) }
        // The duplicate shares the file offset with `descriptor`; rewind so a
        // second call lists the directory again instead of returning nothing.
        rewinddir(directory)
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(directory) else {
                if errno != 0 { throw Self.posixError() }
                break
            }
            let name = withUnsafeBytes(of: entry.pointee.d_name) { bytes in
                String(validatingUTF8: bytes.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            guard let name else { throw Self.posixError(EILSEQ) }
            if name != "." && name != ".." { names.append(name) }
        }
        return names
    }

    public func read() throws -> Data {
        guard !isDirectory else { throw Self.posixError(EISDIR) }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        return try handle.readToEnd() ?? Data()
    }
}
#endif
