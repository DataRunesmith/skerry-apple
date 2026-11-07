import Foundation
import XCTest
@testable import SSHCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

#if canImport(Darwin) || canImport(Glibc)
final class SFTPUploadSourceTests: XCTestCase {
    func testRejectsLinksAndReadsNestedRegularFiles() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let selected = root.appendingPathComponent("selected")
        let nested = selected.appendingPathComponent("nested")
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        let secret = root.appendingPathComponent("secret")
        try Data("secret".utf8).write(to: secret)
        try Data("allowed".utf8).write(to: nested.appendingPathComponent("file"))
        try FileManager.default.createSymbolicLink(at: selected.appendingPathComponent("file-link"), withDestinationURL: secret)
        try FileManager.default.createSymbolicLink(at: selected.appendingPathComponent("dir-link"), withDestinationURL: root)
        try FileManager.default.createSymbolicLink(at: selected.appendingPathComponent("dangling"), withDestinationURL: root.appendingPathComponent("missing"))
        XCTAssertEqual(mkfifo(selected.appendingPathComponent("fifo").path, 0o600), 0)

        let source = try SFTPUploadSource.open(selected)
        XCTAssertTrue(source.isDirectory)
        XCTAssertEqual(Set(try source.childNames()), Set(["nested", "file-link", "dir-link", "dangling", "fifo"]))
        // A second listing must not be empty: the directory stream is rewound each time.
        XCTAssertEqual(Set(try source.childNames()), Set(["nested", "file-link", "dir-link", "dangling", "fifo"]))
        for name in ["file-link", "dir-link", "dangling", "fifo"] {
            XCTAssertThrowsError(try source.child(named: name), name)
        }
        XCTAssertThrowsError(try SFTPUploadSource.open(selected.appendingPathComponent("file-link")))
        let file = try source.child(named: "nested").child(named: "file")
        XCTAssertEqual(try file.read(), Data("allowed".utf8))
    }

    func testSubstitutionCannotRedirectOpenedDirectoryOrFile() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let selected = root.appendingPathComponent("selected")
        let nested = selected.appendingPathComponent("nested")
        let outside = root.appendingPathComponent("outside")
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        try Data("allowed".utf8).write(to: nested.appendingPathComponent("file"))
        try Data("secret".utf8).write(to: outside.appendingPathComponent("file"))
        let directory = try SFTPUploadSource.open(selected).child(named: "nested")
        let file = try directory.child(named: "file")
        try FileManager.default.moveItem(at: nested, to: selected.appendingPathComponent("moved"))
        try FileManager.default.createSymbolicLink(at: nested, withDestinationURL: outside)
        XCTAssertEqual(try directory.child(named: "file").read(), Data("allowed".utf8))
        let movedFile = selected.appendingPathComponent("moved/file")
        try FileManager.default.removeItem(at: movedFile)
        try FileManager.default.createSymbolicLink(at: movedFile, withDestinationURL: outside.appendingPathComponent("file"))
        XCTAssertThrowsError(try directory.child(named: "file"))
        XCTAssertEqual(try file.read(), Data("allowed".utf8))
        XCTAssertThrowsError(try directory.child(named: "../outside/file"))
    }
}
#endif
