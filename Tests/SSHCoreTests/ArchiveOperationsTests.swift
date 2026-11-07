import XCTest
import Foundation
@testable import SSHCore

final class ArchiveOperationsTests: XCTestCase {
    // MARK: - Citering (shell-injektionssäkerhet)

    func testShellQuoteEscapesEmbeddedSingleQuotes() {
        XCTAssertEqual(ArchiveOperations.shellQuote("plain"), "'plain'")
        XCTAssertEqual(ArchiveOperations.shellQuote("with space"), "'with space'")
        XCTAssertEqual(ArchiveOperations.shellQuote("it's"), "'it'\\''s'")
    }

    /// Bevisar att en filnamn-injektion FAKTISKT nollställs av citeringen —
    /// inte bara att strängen "ser rätt ut", utan att en RIKTIG shell (via
    /// `/bin/sh -c`) tolkar hela kommandot som EN sökväg, inte som ett
    /// avslutat citat + ett nytt kommando.
    func testShellQuoteSurvivesRealShellParsing() throws {
        let malicious = "innocent'; touch /tmp/skerry-injection-proof-\(UUID().uuidString); echo '"
        let quoted = ArchiveOperations.shellQuote(malicious)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "printf '%s' \(quoted)"]
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertEqual(output, malicious)
    }

    // MARK: - Kommandobyggare (rena strängar, ingen server)

    func testCreateTarGzCommand() {
        XCTAssertEqual(
            ArchiveOperations.createTarGzCommand(paths: ["a.txt", "b.txt"], archiveName: "out.tar.gz", in: "/home/x"),
            "cd '/home/x' && tar czf 'out.tar.gz' -- 'a.txt' 'b.txt'")
    }

    func testExtractTarGzCommand() {
        XCTAssertEqual(
            ArchiveOperations.extractTarGzCommand(archiveName: "out.tar.gz", in: "/home/x"),
            "cd '/home/x' && tar xzf 'out.tar.gz'")
    }

    /// `./`-prefix på arkivnamnet OCH `--` före sökvägarna — till skillnad
    /// från `tar -f` tar `zip` arkivnamnet som ett rent positionellt
    /// argument, så ett namn eller filnamn som börjar med `-` skulle
    /// annars tolkas som en flagga (verifierat
    /// empiriskt mot en riktig `zip`-binär innan fixen skrevs).
    func testCreateZipCommand() {
        XCTAssertEqual(
            ArchiveOperations.createZipCommand(paths: ["a.txt"], archiveName: "out.zip", in: "/home/x"),
            "cd '/home/x' && zip -r -q './out.zip' -- 'a.txt'")
    }

    func testExtractZipCommand() {
        let command = ArchiveOperations.extractZipCommand(archiveName: "out.zip", in: "/home/x")
        XCTAssertTrue(command.hasPrefix("cd '/home/x' && python3 -c "))
        XCTAssertTrue(command.hasSuffix(" './out.zip'"))
    }

    // MARK: - Riktig körning mot en RIKTIG tar/zip (LoopbackServer realExec: true)

    private func connectedRealExecSession(_ server: LoopbackServer) async throws -> SSHSession {
        let session = SSHSession(
            target: SSHTarget(host: "127.0.0.1", port: server.port, username: "tester"),
            auth: .password("hunter2"), knownHosts: KnownHosts(path: nil))
        try await session.connect()
        return session
    }

    func testCreateThenExtractTarGzRoundTripsRealFiles() async throws {
        let server = try LoopbackServer.start(password: "hunter2", realExec: true)
        defer { server.shutdown() }
        let session = try await connectedRealExecSession(server)

        try "hej".write(toFile: server.sftpRoot + "/a.txt", atomically: true, encoding: .utf8)
        try "då".write(toFile: server.sftpRoot + "/b.txt", atomically: true, encoding: .utf8)

        try await ArchiveOperations.createTarGz(
            paths: ["a.txt", "b.txt"], archiveName: "bundle.tar.gz", in: server.sftpRoot, over: session)
        XCTAssertTrue(FileManager.default.fileExists(atPath: server.sftpRoot + "/bundle.tar.gz"))

        let extractDir = server.sftpRoot + "/extracted"
        try FileManager.default.createDirectory(atPath: extractDir, withIntermediateDirectories: true)
        try FileManager.default.copyItem(
            atPath: server.sftpRoot + "/bundle.tar.gz", toPath: extractDir + "/bundle.tar.gz")
        try await ArchiveOperations.extractTarGz(archiveName: "bundle.tar.gz", in: extractDir, over: session)

        XCTAssertEqual(try String(contentsOfFile: extractDir + "/a.txt", encoding: .utf8), "hej")
        XCTAssertEqual(try String(contentsOfFile: extractDir + "/b.txt", encoding: .utf8), "då")

        await session.close()
    }

    func testCreateThenExtractZipRoundTripsRealFiles() async throws {
        let server = try LoopbackServer.start(password: "hunter2", realExec: true)
        defer { server.shutdown() }
        let session = try await connectedRealExecSession(server)

        try "innehåll".write(toFile: server.sftpRoot + "/c.txt", atomically: true, encoding: .utf8)

        try await ArchiveOperations.createZip(
            paths: ["c.txt"], archiveName: "bundle.zip", in: server.sftpRoot, over: session)
        XCTAssertTrue(FileManager.default.fileExists(atPath: server.sftpRoot + "/bundle.zip"))

        let extractDir = server.sftpRoot + "/extracted-zip"
        try FileManager.default.createDirectory(atPath: extractDir, withIntermediateDirectories: true)
        try FileManager.default.copyItem(
            atPath: server.sftpRoot + "/bundle.zip", toPath: extractDir + "/bundle.zip")
        try await ArchiveOperations.extractZip(archiveName: "bundle.zip", in: extractDir, over: session)

        XCTAssertEqual(try String(contentsOfFile: extractDir + "/c.txt", encoding: .utf8), "innehåll")

        await session.close()
    }

    /// En filnamn-injektion i `paths` får INTE läcka utanför tar-kommandot
    /// när det faktiskt körs mot en RIKTIG shell — inte bara att
    /// kommandosträngen "ser citerad ut" (se ovan), utan att den skadliga
    /// filen aldrig skapas när kommandot verkligen exekveras.
    func testCreateTarGzRejectsInjectionAttemptInPathAgainstRealShell() async throws {
        let server = try LoopbackServer.start(password: "hunter2", realExec: true)
        defer { server.shutdown() }
        let session = try await connectedRealExecSession(server)

        try "x".write(toFile: server.sftpRoot + "/real.txt", atomically: true, encoding: .utf8)
        let proofPath = server.sftpRoot + "/injected.txt"
        let malicious = "real.txt'; touch '\(proofPath)"

        // tar klagar (ingen sådan fil) men ska INTE köra det inbäddade
        // `touch`-kommandot — testar bara att injektionsfilen aldrig dyker upp.
        _ = try? await ArchiveOperations.createTarGz(
            paths: [malicious], archiveName: "bundle2.tar.gz", in: server.sftpRoot, over: session)

        XCTAssertFalse(FileManager.default.fileExists(atPath: proofPath))

        await session.close()
    }

    /// Ett filnamn (SFTP-post som ska arkiveras) OCH ett arkivnamn (helt
    /// användarstyrt i App/LinuxApp:s UI) som börjar med `-` ska packas
    /// och packas upp korrekt, inte tolkas som `zip`/`unzip`-flaggor.
    /// Utan `--`/`./`-fixen misslyckas det ena
    /// TYST med "Nothing to do!" och det andra ÄNNU TYSTARE (skriver bara
    /// ut hjälptext, extraherar ingenting, avslutar med kod 0) — verifierat
    /// manuellt mot en riktig zip/unzip-binär innan fixen skrevs, se
    /// kommentarerna i ArchiveOperations.swift.
    func testCreateThenExtractZipHandlesDashPrefixedNamesAgainstRealZip() async throws {
        let server = try LoopbackServer.start(password: "hunter2", realExec: true)
        defer { server.shutdown() }
        let session = try await connectedRealExecSession(server)

        try "dash-prefix-innehåll".write(toFile: server.sftpRoot + "/-T", atomically: true, encoding: .utf8)

        try await ArchiveOperations.createZip(
            paths: ["-T"], archiveName: "-dashed.zip", in: server.sftpRoot, over: session)
        XCTAssertTrue(FileManager.default.fileExists(atPath: server.sftpRoot + "/-dashed.zip"))

        let extractDir = server.sftpRoot + "/extracted-zip-dash"
        try FileManager.default.createDirectory(atPath: extractDir, withIntermediateDirectories: true)
        try FileManager.default.copyItem(
            atPath: server.sftpRoot + "/-dashed.zip", toPath: extractDir + "/-dashed.zip")
        try await ArchiveOperations.extractZip(archiveName: "-dashed.zip", in: extractDir, over: session)

        XCTAssertEqual(
            try String(contentsOfFile: extractDir + "/-T", encoding: .utf8), "dash-prefix-innehåll")

        await session.close()
    }
    func testZipExtractionRejectsEscapesAndDoesNotFollowLinks() async throws {
        let server = try LoopbackServer.start(password: "hunter2", realExec: true)
        defer { server.shutdown() }
        let session = try await connectedRealExecSession(server)

        let fixture = #"""
        import os, stat, sys, zipfile
        root = sys.argv[1]
        os.mkdir(root + '/dest')
        os.mkdir(root + '/outside')
        with open(root + '/outside/victim', 'w') as f: f.write('original')
        os.symlink(root + '/outside', root + '/dest/link')
        os.symlink(root + '/outside/victim', root + '/dest/filelink')
        os.link(root + '/outside/victim', root + '/dest/hardlink')
        with open(root + '/dest/normal', 'w') as f: f.write('old')
        archives = {
            'ancestor.zip': ('link/victim', 'attack'),
            'filelink.zip': ('filelink', 'attack'),
            'traversal.zip': ('../outside/victim', 'attack'),
            'absolute.zip': (root + '/outside/victim', 'attack'),
            'hardlink.zip': ('hardlink', 'safe replacement'),
            'normal.zip': ('normal', 'new'),
        }
        for filename, (name, data) in archives.items():
            with zipfile.ZipFile(root + '/dest/' + filename, 'w') as archive:
                archive.writestr(name, data)
        with zipfile.ZipFile(root + "/dest/-nested 'name.zip", 'w') as archive:
            archive.writestr('folder/', '')
            archive.writestr("folder/it's safe", 'nested data')
        with zipfile.ZipFile(root + '/dest/symlink.zip', 'w') as archive:
            archive.writestr('would-write', 'not written')
            link = zipfile.ZipInfo('archive-link')
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, '../outside')
        """#
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", "-c", fixture, server.sftpRoot]
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)

        let dest = server.sftpRoot + "/dest"
        for archive in ["ancestor.zip", "filelink.zip", "traversal.zip", "absolute.zip", "symlink.zip"] {
            do {
                try await ArchiveOperations.extractZip(archiveName: archive, in: dest, over: session)
                XCTFail("Expected extraction of \(archive) to fail")
            } catch { }
            XCTAssertEqual(try String(contentsOfFile: server.sftpRoot + "/outside/victim", encoding: .utf8), "original")
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dest + "/would-write"))

        try await ArchiveOperations.extractZip(archiveName: "hardlink.zip", in: dest, over: session)
        XCTAssertEqual(try String(contentsOfFile: dest + "/hardlink", encoding: .utf8), "safe replacement")
        XCTAssertEqual(try String(contentsOfFile: server.sftpRoot + "/outside/victim", encoding: .utf8), "original")
        try await ArchiveOperations.extractZip(archiveName: "normal.zip", in: dest, over: session)
        XCTAssertEqual(try String(contentsOfFile: dest + "/normal", encoding: .utf8), "new")
        try await ArchiveOperations.extractZip(archiveName: "-nested 'name.zip", in: dest, over: session)
        XCTAssertEqual(try String(contentsOfFile: dest + "/folder/it's safe", encoding: .utf8), "nested data")
        await session.close()
    }

    func testZipExtractionRefusesArchivesLargerThanFreeSpace() async throws {
        let server = try LoopbackServer.start(password: "hunter2", realExec: true)
        defer { server.shutdown() }
        let session = try await connectedRealExecSession(server)

        // 1,000 members whose central-directory sizes each claim almost 4 GiB.
        let fixture = #"""
        import os, struct, sys, zipfile
        root = sys.argv[1]
        os.mkdir(root + '/dest')
        path = root + '/dest/bomb.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for i in range(1000):
                archive.writestr('member-%d' % i, 'x')
        data = bytearray(open(path, 'rb').read())
        offset = data.find(b'PK\x01\x02')
        while offset != -1:
            struct.pack_into('<I', data, offset + 24, 0xFFFFFFF0)
            offset = data.find(b'PK\x01\x02', offset + 4)
        open(path, 'wb').write(data)
        """#
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", "-c", fixture, server.sftpRoot]
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)

        let dest = server.sftpRoot + "/dest"
        do {
            try await ArchiveOperations.extractZip(archiveName: "bomb.zip", in: dest, over: session)
            XCTFail("Expected extraction to fail for lack of space")
        } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: dest + "/member-0"))
        await session.close()
    }

}
