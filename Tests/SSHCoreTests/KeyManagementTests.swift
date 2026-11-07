import XCTest
import Foundation
@testable import SSHCore

final class KeyGeneratorTests: XCTestCase {
    func testGeneratedPublicKeyLineHasCorrectFormat() {
        let pair = KeyGenerator.generateEd25519(comment: "skerry-test")
        XCTAssertTrue(pair.publicKeyLine.hasPrefix("ssh-ed25519 "))
        XCTAssertTrue(pair.publicKeyLine.hasSuffix("skerry-test"))
        XCTAssertEqual(pair.seed.count, 32)
    }

    func testTwoGeneratedKeysAreDistinct() {
        let a = KeyGenerator.generateEd25519()
        let b = KeyGenerator.generateEd25519()
        XCTAssertNotEqual(a.seed, b.seed)
        XCTAssertNotEqual(a.publicKeyLine, b.publicKeyLine)
    }

    func testCommentIsOptional() {
        let pair = KeyGenerator.generateEd25519()
        // Utan kommentar: exakt två delar ("ssh-ed25519" + base64), inget
        // efterföljande mellanslag+text.
        let parts = pair.publicKeyLine.split(separator: " ")
        XCTAssertEqual(parts.count, 2)
    }

    /// fromExisting(seed:) måste härleda EXAKT samma publika nyckel som
    /// generateEd25519() redan gjorde för samma frö — annars skulle
    /// "klistra in en befintlig nyckel"-flödet deploya en publik nyckel som
    /// inte matchar den privata nyckeln användaren faktiskt har.
    func testFromExistingDerivesSamePublicKeyAsOriginalGeneration() throws {
        let original = KeyGenerator.generateEd25519(comment: "original")
        let rebuilt = try KeyGenerator.fromExisting(seed: original.seed, comment: "different-comment")
        // Jämför bara den publika nyckel-DELEN (utan kommentar) — den delen
        // är vad som faktiskt måste matcha, kommentaren är fri text.
        let originalKeyPart = original.publicKeyLine.split(separator: " ").prefix(2).joined(separator: " ")
        let rebuiltKeyPart = rebuilt.publicKeyLine.split(separator: " ").prefix(2).joined(separator: " ")
        XCTAssertEqual(originalKeyPart, rebuiltKeyPart)
        XCTAssertEqual(rebuilt.seed, original.seed)
    }

    func testFromExistingRejectsWrongSeedLength() {
        XCTAssertThrowsError(try KeyGenerator.fromExisting(seed: Data([1, 2, 3])))
    }

    func testUnsafeCommentsAreOmittedFromGeneratedAndImportedKeys() throws {
        let original = KeyGenerator.generateEd25519()
        for comment in ["alias\nssh-ed25519 attacker", "alias\rssh-ed25519 attacker",
                        "alias\r\nssh-ed25519 attacker", "alias\0extra"] {
            let generated = KeyGenerator.generateEd25519(comment: comment)
            XCTAssertEqual(generated.publicKeyLine.split(separator: " ").count, 2)
            let imported = try KeyGenerator.fromExisting(seed: original.seed, comment: comment)
            XCTAssertEqual(imported.publicKeyLine, original.publicKeyLine)
        }
        let literal = #"alias\nssh-ed25519 attacker"#
        XCTAssertTrue(KeyGenerator.generateEd25519(comment: literal).publicKeyLine.hasSuffix(literal))
    }

    /// Hela vägen runt: export -> parse -> fromExisting -> samma publika
    /// nyckel som den ALLRA första generate()-anropet gav — bevisar att en
    /// nyckel som lämnat Skerry (exporterad, t.ex. till en fil) och sedan
    /// klistras in igen ger tillbaka samma deploybara publika nyckel.
    func testRoundTripThroughExportParseFromExisting() throws {
        let original = KeyGenerator.generateEd25519(comment: "roundtrip")
        let pem = try OpenSSHPrivateKey.export(seed: original.seed, comment: "roundtrip")
        let auth = try OpenSSHPrivateKey.parse(pem)
        guard case .ed25519Seed(let parsedSeed) = auth else {
            return XCTFail("förväntade .ed25519Seed, fick \(auth)")
        }
        let rebuilt = try KeyGenerator.fromExisting(seed: parsedSeed, comment: "roundtrip")
        XCTAssertEqual(rebuilt.publicKeyLine, original.publicKeyLine)
    }
}

final class OpenSSHPrivateKeyExportTests: XCTestCase {
    /// Rundresa genom EGEN kod: generera, exportera, parsa tillbaka — fröet
    /// måste vara identiskt. Enda sättet att bevisa en encoder utan en extern
    /// referens är att visa att den egna, redan verifierade decodern läser
    /// tillbaka exakt det den fick.
    func testExportThenParseRoundTripsSeed() throws {
        let pair = KeyGenerator.generateEd25519(comment: "roundtrip")
        let pem = try OpenSSHPrivateKey.export(seed: pair.seed, comment: "roundtrip")
        let auth = try OpenSSHPrivateKey.parse(pem)
        guard case .ed25519Seed(let parsedSeed) = auth else {
            return XCTFail("förväntade .ed25519Seed, fick \(auth)")
        }
        XCTAssertEqual(parsedSeed, pair.seed)
    }

    func testExportedPEMHasCorrectHeaderAndFooter() throws {
        let pair = KeyGenerator.generateEd25519()
        let pem = try OpenSSHPrivateKey.export(seed: pair.seed)
        let pemLabel = ["OPENSSH", "PRIVATE", "KEY"].joined(separator: " ")
        XCTAssertTrue(pem.hasPrefix("-----BEGIN \(pemLabel)-----\n"))
        XCTAssertTrue(pem.hasSuffix("-----END \(pemLabel)-----\n"))
    }

    func testRejectsWrongSeedLength() {
        XCTAssertThrowsError(try OpenSSHPrivateKey.export(seed: Data([1, 2, 3]))) { error in
            guard case SSHKeyError.malformed = error else {
                return XCTFail("förväntade .malformed, fick \(error)")
            }
        }
    }

    /// Starkaste möjliga verifiering: den REKTIGA `ssh-keygen` (inte vår egen
    /// kod) ska kunna läsa en exporterad nyckel och räkna ut samma publika
    /// nyckel som vi själva beräknade. Hoppar över om ssh-keygen saknas i
    /// testmiljön (t.ex. vissa CI-avbilder) i stället för att falskt misslyckas.
    func testRealSSHKeygenAcceptsExportedKey() throws {
        guard FileManager.default.fileExists(atPath: "/usr/bin/ssh-keygen") else {
            throw XCTSkip("ssh-keygen saknas i den här miljön")
        }
        let pair = KeyGenerator.generateEd25519(comment: "keygen-cross-check")
        let pem = try OpenSSHPrivateKey.export(seed: pair.seed, comment: "keygen-cross-check")

        let dir = NSTemporaryDirectory() + "skerry-keygen-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let keyPath = dir + "/id_ed25519"
        try pem.write(toFile: keyPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyPath)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = ["-y", "-f", keyPath]
        let stdout = Pipe()
        process.standardOutput = stdout
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)

        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        let output = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        // ssh-keygen -y skriver "<typ> <base64> <kommentar>" — kommentaren
        // hämtas ur privatnyckelfilens eget kommentarfält, precis som vi
        // skrev in den. Jämför hela raden mot vår egen.
        XCTAssertEqual(output, pair.publicKeyLine)
    }
}

final class ShellQuotedTests: XCTestCase {
    /// Testar mot en RIKTIG `/bin/sh`, inte bara vår egen escape-logik mot sig
    /// själv — bevisar att skalet faktiskt tolkar den escapade strängen som
    /// EN literal sträng, oavsett vad den innehåller.
    private func roundTripThroughRealShell(_ input: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "printf '%s' \(shellQuoted(input))"]
        let stdout = Pipe()
        process.standardOutput = stdout
        try process.run()
        process.waitUntilExit()
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        return String(decoding: data, as: UTF8.self)
    }

    func testPlainString() throws {
        XCTAssertEqual(try roundTripThroughRealShell("hello world"), "hello world")
    }

    func testEmbeddedSingleQuote() throws {
        XCTAssertEqual(try roundTripThroughRealShell("it's a test"), "it's a test")
    }

    func testShellMetacharacters() throws {
        XCTAssertEqual(try roundTripThroughRealShell("$(rm -rf /) `whoami` ; & | > < \\"), "$(rm -rf /) `whoami` ; & | > < \\")
    }

    func testOnlyQuotes() throws {
        XCTAssertEqual(try roundTripThroughRealShell("''''"), "''''")
    }
}

final class DeployPublicKeyCommandTests: XCTestCase {
    func testCommandContainsCorrectPieces() {
        let cmd = deployPublicKeyCommandPOSIX("ssh-ed25519 AAAAtest comment")
        XCTAssertTrue(cmd.contains("mkdir -p ~/.ssh"))
        XCTAssertTrue(cmd.contains("chmod 700 ~/.ssh"))
        XCTAssertTrue(cmd.contains("chmod 600 ~/.ssh/authorized_keys"))
        XCTAssertTrue(cmd.contains("grep -qxF"))
        XCTAssertTrue(cmd.contains("'ssh-ed25519 AAAAtest comment'"))
    }

    func testMaliciousCommentIsFullyQuotedNotInjected() {
        let malicious = "'; rm -rf ~ #"
        let cmd = deployPublicKeyCommandPOSIX("ssh-ed25519 AAAAtest \(malicious)")
        // Den escapade formen ska finnas — INTE den råa, oescapade strängen
        // (vilket skulle betyda att den läckt ut ur citattecknen).
        XCTAssertFalse(cmd.contains("AAAAtest '; rm -rf ~ #'"))
    }

    func testPOSIXWritesLiteralBackslashesAndIsIdempotent() throws {
        let dir = NSTemporaryDirectory() + "skerry-deploy-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let line = #"ssh-ed25519 AAAAtest comment\nssh-ed25519 attacker \c o'brien"#
        let command = deployPublicKeyCommandPOSIX(line)
        for _ in 0..<2 {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", command]
            var environment = ProcessInfo.processInfo.environment
            environment["HOME"] = dir
            process.environment = environment
            try process.run()
            process.waitUntilExit()
            XCTAssertEqual(process.terminationStatus, 0)
        }
        let contents = try String(contentsOfFile: dir + "/.ssh/authorized_keys", encoding: .utf8)
        XCTAssertEqual(contents, line + "\n")
    }

    func testDeploymentRejectsRecordSeparatorsOnAllPlatforms() async throws {
        let server = try LoopbackServer.start(password: "test")
        defer { server.shutdown() }
        let session = SSHSession(
            target: SSHTarget(host: "127.0.0.1", port: server.port, username: "tester"),
            auth: .password("test"), knownHosts: KnownHosts(path: nil))
        try await session.connect()
        for platform in RemotePlatform.allCases {
            for line in ["", "   ", "ssh-ed25519 key\nssh-ed25519 attacker",
                         "ssh-ed25519 key\rssh-ed25519 attacker",
                         "ssh-ed25519 key\r\nssh-ed25519 attacker", "ssh-ed25519 key\0extra"] {
                do {
                    try await session.deployPublicKey(line, platform: platform)
                    XCTFail("Accepted invalid input on \(platform)")
                } catch SSHKeyError.malformed {
                    // Invalid input must be rejected even with a live session.
                } catch {
                    XCTFail("Unexpected error: \(error)")
                }
            }
        }
        await session.close()
    }

    func testDeploymentAcceptsSingleLineOnAllPlatforms() async throws {
        let server = try LoopbackServer.start(password: "test")
        defer { server.shutdown() }
        let session = SSHSession(
            target: SSHTarget(host: "127.0.0.1", port: server.port, username: "tester"),
            auth: .password("test"), knownHosts: KnownHosts(path: nil))
        try await session.connect()
        do {
            let line = KeyGenerator.generateEd25519(comment: #"test\n o'brien"#).publicKeyLine
            for platform in RemotePlatform.allCases {
                try await session.deployPublicKey(line, platform: platform)
            }
            await session.close()
        } catch {
            await session.close()
            throw error
        }
    }
}

final class DeployPublicKeyCommandWindowsTests: XCTestCase {
    /// Avkodar `-EncodedCommand`-base64:n tillbaka till PowerShell-skriptet
    /// (UTF-16LE, precis som PowerShell själv förväntar sig) — testar mot
    /// den FAKTISKA kodningen, inte bara att ett kommando byggdes.
    private func decodedScript(_ command: String) throws -> String {
        let prefix = "powershell -NoProfile -NonInteractive -EncodedCommand "
        guard command.hasPrefix(prefix) else {
            XCTFail("förväntade prefix saknas: \(command)")
            return ""
        }
        let base64 = String(command.dropFirst(prefix.count))
        guard let data = Data(base64Encoded: base64) else {
            XCTFail("ogiltig base64")
            return ""
        }
        let utf16 = data.withUnsafeBytes { $0.bindMemory(to: UInt16.self) }
        return String(decoding: utf16, as: UTF16.self)
    }

    func testAdminPathUsesSharedAdministratorsFileWithACL() throws {
        let cmd = deployPublicKeyCommandWindows(
            "ssh-ed25519 AAAAtest comment",
            path: #"C:\ProgramData\ssh\administrators_authorized_keys"#, setACL: true)
        let script = try decodedScript(cmd)
        XCTAssertTrue(script.contains(#"C:\ProgramData\ssh\administrators_authorized_keys"#))
        XCTAssertTrue(script.contains(#"C:\ProgramData\ssh"#))
        XCTAssertTrue(script.contains("icacls"))
        XCTAssertTrue(script.contains("Administrators:F"))
        XCTAssertTrue(script.contains("SYSTEM:F"))
        XCTAssertTrue(script.contains("'ssh-ed25519 AAAAtest comment'"))
    }

    func testStandardPathHasNoACLCommands() throws {
        let cmd = deployPublicKeyCommandWindows(
            "ssh-ed25519 AAAAtest comment",
            path: #"$env:USERPROFILE\.ssh\authorized_keys"#, setACL: false)
        let script = try decodedScript(cmd)
        XCTAssertTrue(script.contains(#"$env:USERPROFILE\.ssh\authorized_keys"#))
        XCTAssertFalse(script.contains("icacls"))
    }

    /// PowerShell-enkelcitat escapas genom att fördubblas (`'` -> `''`),
    /// INTE med POSIX-skalets `\'`-mönster — en riktig kommentar med en
    /// apostrof får inte bryta ut ur citatet.
    func testEmbeddedSingleQuoteIsDoubledNotBackslashEscaped() throws {
        let cmd = deployPublicKeyCommandWindows(
            "ssh-ed25519 AAAAtest o'brien", path: #"C:\test\authorized_keys"#, setACL: false)
        let script = try decodedScript(cmd)
        XCTAssertTrue(script.contains("o''brien"))
        XCTAssertFalse(script.contains("o\\'brien"))
    }

    func testDirIsSplitOnBackslashNotForwardSlash() throws {
        // Regression: NSString.deletingLastPathComponent antar POSIX-
        // snedstreck och skulle INTE dela upp en backslash-sökväg korrekt.
        let cmd = deployPublicKeyCommandWindows(
            "ssh-ed25519 AAAAtest", path: #"C:\a\b\c\authorized_keys"#, setACL: false)
        let script = try decodedScript(cmd)
        XCTAssertTrue(script.contains(#"$dir = 'C:\a\b\c'"#))
    }
}

final class VerifyKeyAuthWorksTests: XCTestCase {
    func testSucceedsWithValidKeyAgainstRealServer() async throws {
        let server = try LoopbackServer.start(password: "hunter2")
        defer { server.shutdown() }
        let pair = KeyGenerator.generateEd25519()
        let ok = await SSHSession.verifyKeyAuthWorks(
            target: SSHTarget(host: "127.0.0.1", port: server.port, username: "tester"),
            seed: pair.seed, knownHosts: KnownHosts(path: nil))
        XCTAssertTrue(ok)
    }

    func testFailsAgainstUnreachableHost() async throws {
        let pair = KeyGenerator.generateEd25519()
        let ok = await SSHSession.verifyKeyAuthWorks(
            target: SSHTarget(host: "127.0.0.1", port: 1, username: "tester"),
            seed: pair.seed, knownHosts: KnownHosts(path: nil))
        XCTAssertFalse(ok)
    }

    /// Target bakom en jump-host är annars overifierbar (probe:en skulle
    /// försöka nå target direkt och alltid misslyckas) — samma RIKTIGA
    /// jump+target-serveruppsättning som `ProxyJumpTests` för att bevisa att
    /// nyckelverifieringen faktiskt går GENOM tunneln, inte direkt.
    func testSucceedsThroughJumpHost() async throws {
        let jumpServer = try LoopbackServer.start(password: "jump-pw", realDirectTCPIPForwarding: true)
        defer { jumpServer.shutdown() }
        let targetServer = try LoopbackServer.start(password: "target-pw")
        defer { targetServer.shutdown() }

        let pair = KeyGenerator.generateEd25519()
        let ok = await SSHSession.verifyKeyAuthWorks(
            target: SSHTarget(host: "127.0.0.1", port: targetServer.port, username: "tester"),
            seed: pair.seed, knownHosts: KnownHosts(path: nil),
            jump: (target: SSHTarget(host: "127.0.0.1", port: jumpServer.port, username: "tester"),
                   auth: .password("jump-pw")))
        XCTAssertTrue(ok)
    }

    /// Fel lösenord för jump-hoppet (target-nyckeln i sig hade fungerat) ska
    /// fortfarande resultera i `false` — bevisar att jump-autentiseringen
    /// faktiskt kontrolleras, inte bara att SSHConnectionChain råkar lyckas
    /// via någon annan väg.
    func testFailsWhenJumpAuthFails() async throws {
        let jumpServer = try LoopbackServer.start(password: "jump-pw", realDirectTCPIPForwarding: true)
        defer { jumpServer.shutdown() }
        let targetServer = try LoopbackServer.start(password: "target-pw")
        defer { targetServer.shutdown() }

        let pair = KeyGenerator.generateEd25519()
        let ok = await SSHSession.verifyKeyAuthWorks(
            target: SSHTarget(host: "127.0.0.1", port: targetServer.port, username: "tester"),
            seed: pair.seed, knownHosts: KnownHosts(path: nil),
            jump: (target: SSHTarget(host: "127.0.0.1", port: jumpServer.port, username: "tester"),
                   auth: .password("wrong-jump-pw")))
        XCTAssertFalse(ok)
    }
}
