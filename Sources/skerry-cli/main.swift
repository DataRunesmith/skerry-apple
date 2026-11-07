import Foundation
import SSHCore
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

// skerry-cli — bevisar SSH-kärnan mot en riktig server.
//
//   skerry-cli <user@host[:port]> "<kommando>"
//   skerry-cli -L [bindHost:]bindPort:targetHost:targetPort <user@host[:port]>
//   skerry-cli -R [bindHost:]bindPort:targetHost:targetPort <user@host[:port]>
//   skerry-cli -D [bindHost:]bindPort <user@host[:port]>
//   skerry-cli -J <[user@]jumphost[:port]> <user@host[:port]> "<kommando>"
//
// ProxyJump: antingen en `ProxyJump`-rad i ~/.ssh/config (parsas automatiskt,
// se SSHConfig.swift) ELLER `-J` explicit på kommandoraden (samma
// destinationssyntax som huvudmålet — alias eller [user@]host[:port]),
// samma mönster som riktig `ssh -J`. `-J` vinner om båda är satta. Jump-hoppet
// återanvänder SAMMA autentisering (miljövariabler/nyckelfråga) som
// huvudmålet — v1-förenkling, täcker det vanliga fallet med samma identitet
// överallt. Separat auth per hopp är inte byggt.
//
// Lösenord läses från miljövariabeln SKERRY_PASSWORD (annars frågas det via
// stdin). Ed25519-nyckel (rått 32-byte frö, hex) kan ges via SKERRY_ED25519_HEX.

/// `sig_atomic_t`, inte `Bool`/klass — signalhanteraren nedan är en
/// C-funktionspekare (kan inte fånga kontext) och får bara skriva till
/// enkla globala/statiska variabler av den här typen på ett säkert sätt.
nonisolated(unsafe) var interrupted: sig_atomic_t = 0

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(Data((msg + "\n").utf8))
    exit(2)
}

// Terminal state shared with the signal handlers below. The handlers are C
// function pointers, so they can only reach globals, and they only make
// async-signal-safe calls (tcsetattr, signal, sigprocmask, raise, write).
nonisolated(unsafe) var promptVisible = termios()
nonisolated(unsafe) var promptHidden = termios()
nonisolated(unsafe) var promptText: UnsafeMutablePointer<CChar>?

/// Signals that end the process: show the terminal again, then let the signal
/// take its default action once the handler returns.
let promptTerminatingSignals: [Int32] = [SIGINT, SIGQUIT, SIGHUP, SIGTERM, SIGPIPE]
/// Job-control stops: show the terminal while stopped, hide it again on resume.
let promptStopSignals: [Int32] = [SIGTSTP, SIGTTIN, SIGTTOU]

func promptRestoreAndTerminate(_ sig: Int32) {
    _ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &promptVisible)
    _ = signal(sig, SIG_DFL)
    _ = raise(sig)  // Blocked inside the handler; delivered when it returns.
}

func promptRestoreAndStop(_ sig: Int32) {
    _ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &promptVisible)
    _ = signal(sig, SIG_DFL)
    var unblock = sigset_t()
    sigemptyset(&unblock)
    sigaddset(&unblock, sig)
    _ = sigprocmask(SIG_UNBLOCK, &unblock, nil)
    _ = raise(sig)  // The process stops here and continues after SIGCONT.
    _ = signal(sig, promptRestoreAndStop)
    _ = tcsetattr(STDIN_FILENO, TCSAFLUSH, &promptHidden)
    if let promptText {
        _ = write(STDERR_FILENO, "\n", 1)
        _ = write(STDERR_FILENO, promptText, strlen(promptText))
    }
}

/// Reads a password without echo when stdin is a terminal. The terminal is
/// restored on every exit path, including interrupts; a stop (Ctrl-Z) shows the
/// terminal while stopped and resumes the hidden prompt afterwards. Piped input
/// is read as one line, as before.
func readPassword(prompt: String) -> String? {
    guard isatty(STDIN_FILENO) == 1, tcgetattr(STDIN_FILENO, &promptVisible) == 0 else {
        FileHandle.standardError.write(Data(prompt.utf8))
        return readLine(strippingNewline: true)
    }
    promptHidden = promptVisible
    promptHidden.c_lflag &= ~tcflag_t(ECHO | ECHONL)
    promptText = strdup(prompt)
    defer { free(promptText); promptText = nil }

    // Install the handlers before hiding input so no signal can leave it hidden.
    let previous = promptTerminatingSignals.map { ($0, signal($0, promptRestoreAndTerminate)) }
        + promptStopSignals.map { ($0, signal($0, promptRestoreAndStop)) }
    defer {
        _ = tcsetattr(STDIN_FILENO, TCSANOW, &promptVisible)
        for (sig, handler) in previous.reversed() { _ = signal(sig, handler) }
        FileHandle.standardError.write(Data("\n".utf8))
    }
    guard tcsetattr(STDIN_FILENO, TCSANOW, &promptHidden) == 0 else { return nil }
    // Prompt only once input is hidden, so nothing typed after it can echo.
    FileHandle.standardError.write(Data(prompt.utf8))
    return readLine(strippingNewline: true)
}

/// `ssh -L`/`-R`-syntax (samma strängformat för båda): `[bindHost:]bindPort:targetHost:targetPort`.
/// `bindHost` är valfri (default 127.0.0.1) — särskiljs från `targetHost` genom att
/// räkna `:`-delade segment bakifrån, eftersom `targetHost` (men aldrig
/// `bindHost`/portarna) kan innehålla ytterligare kolon (IPv6) i teorin;
/// v1 stödjer bara den vanliga 3- eller 4-delade formen.
struct LocalForwardSpec {
    let bindHost: String
    let bindPort: Int
    let targetHost: String
    let targetPort: Int

    /// `bindPort: 0` betyder "valfri OS-tilldelad port" (giltigt), men
    /// `targetPort` måste vara en riktig port — `0` där vore aldrig meningsfullt.
    private static func parsePort(_ value: String, allowZero: Bool) -> Int? {
        guard let port = Int(value), port >= (allowZero ? 0 : 1), port <= 65_535 else { return nil }
        return port
    }

    init?(_ spec: String) {
        let parts = spec.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        switch parts.count {
        case 3:
            guard let bp = Self.parsePort(parts[0], allowZero: true), !parts[1].isEmpty,
                  let tp = Self.parsePort(parts[2], allowZero: false)
            else { return nil }
            bindHost = "127.0.0.1"
            bindPort = bp
            targetHost = parts[1]
            targetPort = tp
        case 4:
            guard !parts[0].isEmpty, let bp = Self.parsePort(parts[1], allowZero: true), !parts[2].isEmpty,
                  let tp = Self.parsePort(parts[3], allowZero: false)
            else { return nil }
            bindHost = parts[0]
            bindPort = bp
            targetHost = parts[2]
            targetPort = tp
        default:
            return nil
        }
    }
}

/// `ssh -D`-syntax: `[bindHost:]bindPort` — inget mål, klienten (SOCKS5) väljer
/// det per anslutning, till skillnad från `-L`/`-R`s fasta mål.
struct DynamicForwardSpec {
    let bindHost: String
    let bindPort: Int

    init?(_ spec: String) {
        let parts = spec.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        switch parts.count {
        case 1:
            guard let bp = Int(parts[0]), bp >= 0, bp <= 65_535 else { return nil }
            bindHost = "127.0.0.1"
            bindPort = bp
        case 2:
            guard !parts[0].isEmpty, let bp = Int(parts[1]), bp >= 0, bp <= 65_535 else { return nil }
            bindHost = parts[0]
            bindPort = bp
        default:
            return nil
        }
    }
}

var cliArgs = Array(CommandLine.arguments.dropFirst())
var explicitProxyJump: String?
if cliArgs.first == "-J" {
    guard cliArgs.count >= 2 else {
        fail("Användning: skerry-cli -J <[user@]jumphost[:port]> <[user@]host[:port]> \"<kommando>\"")
    }
    explicitProxyJump = cliArgs[1]
    cliArgs.removeFirst(2)
}
var localForward: LocalForwardSpec?
var remoteForward: LocalForwardSpec?
var dynamicForward: DynamicForwardSpec?
if cliArgs.first == "-L" || cliArgs.first == "-R" {
    let flag = cliArgs[0]
    guard cliArgs.count >= 3, let spec = LocalForwardSpec(cliArgs[1]) else {
        fail("Användning: skerry-cli \(flag) [bindHost:]bindPort:targetHost:targetPort <[user@]host[:port]>")
    }
    if flag == "-L" { localForward = spec } else { remoteForward = spec }
    cliArgs.removeFirst(2)
} else if cliArgs.first == "-D" {
    guard cliArgs.count >= 3, let spec = DynamicForwardSpec(cliArgs[1]) else {
        fail("Användning: skerry-cli -D [bindHost:]bindPort <[user@]host[:port]>")
    }
    dynamicForward = spec
    cliArgs.removeFirst(2)
}
let anyForward = localForward != nil || remoteForward != nil || dynamicForward != nil

let args = cliArgs
guard args.count >= (anyForward ? 1 : 2) else {
    fail("Användning: skerry-cli <[user@]host-eller-alias[:port]> \"<kommando>\"")
}

/// Löser upp `user@host:port` (delar valfria) ELLER ett alias ur
/// `~/.ssh/config` till en konkret destination. Uttryckliga delar (user,
/// port) vinner över configen. Delad mellan huvudmålet och ett ev.
/// `ProxyJump`-hopp (samma parsningslogik oavsett vilken av dem det gäller).
func resolveDestination(_ dest: String) -> (host: String, port: Int, username: String, cfg: ResolvedHost) {
    var explicitUser: String?
    var token = dest
    if let atIdx = dest.firstIndex(of: "@") {
        explicitUser = String(dest[dest.startIndex..<atIdx])
        token = String(dest[dest.index(after: atIdx)...])
    }
    var explicitPort: Int?
    if let colon = token.lastIndex(of: ":"), let p = Int(token[token.index(after: colon)...]) {
        explicitPort = p
        token = String(token[token.startIndex..<colon])
    }
    let cfg = SSHConfig.load().resolve(token)
    guard let username = explicitUser ?? cfg.user else {
        fail("Ingen användare: ange user@host eller sätt User för \(token) i ~/.ssh/config")
    }
    return (cfg.hostName, explicitPort ?? cfg.port, username, cfg)
}

let (hostPart, port, username, cfg) = resolveDestination(args[0])
let command = anyForward ? "" : args[1]

// Autentisering. Ordning: uttrycklig nyckelfil > rått frö > lösenord >
// IdentityFile ur ssh-config > standardnyckel (~/.ssh/id_ed25519) > lösenordsfråga.
let env = ProcessInfo.processInfo.environment
let auth: SSHAuth
func loadKey(_ path: String) -> SSHAuth {
    do { return try OpenSSHPrivateKey.load(path: path) }
    catch SSHKeyError.encrypted { fail("Nyckeln \(path) är lösenfras-skyddad — stöds inte än.") }
    catch SSHKeyError.unsupportedKeyType(let t) { fail("Nyckeltypen \(t) stöds inte än (endast Ed25519).") }
    catch { fail("Kunde inte läsa nyckeln \(path): \(error)") }
}

let defaultKey = ("~/.ssh/id_ed25519" as NSString).expandingTildeInPath
if let keyFile = env["SKERRY_KEY_FILE"] {
    auth = loadKey(keyFile)
} else if let hex = env["SKERRY_ED25519_HEX"], let seed = Data(hexString: hex) {
    auth = .ed25519Seed(seed)
} else if let pw = env["SKERRY_PASSWORD"] {
    auth = .password(pw)
} else if let idf = cfg.identityFile, FileManager.default.fileExists(atPath: idf) {
    FileHandle.standardError.write(Data("Använder \(idf) (ssh-config)\n".utf8))
    auth = loadKey(idf)
} else if FileManager.default.fileExists(atPath: defaultKey) {
    FileHandle.standardError.write(Data("Använder \(defaultKey)\n".utf8))
    auth = loadKey(defaultKey)
} else {
    guard let line = readPassword(prompt: "Lösenord för \(username)@\(hostPart): ") else { fail("Kunde inte läsa lösenordet säkert.") }
    auth = .password(line)
}

let target = SSHTarget(host: hostPart, port: port, username: username)
let session = SSHSession(target: target, auth: auth)

// ProxyJump ur ~/.ssh/config (om satt) — återanvänder SAMMA auth som
// huvudmålet (se filhuvudets kommentar för varför). Jump-sessionen MÅSTE
// stängas EFTER huvudsessionen (se doc-kommentaren på SSHSession.connect(via:)
// för varför den ordningen inte är valfri).
var jumpSession: SSHSession?
if let proxyJump = explicitProxyJump ?? cfg.proxyJump {
    let (jumpHost, jumpPort, jumpUsername, _) = resolveDestination(proxyJump)
    FileHandle.standardError.write(Data("Hoppar via \(jumpUsername)@\(jumpHost):\(jumpPort) (ProxyJump)\n".utf8))
    let jump = SSHSession(target: SSHTarget(host: jumpHost, port: jumpPort, username: jumpUsername), auth: auth)
    jumpSession = jump
}

do {
    if let jumpSession {
        try await jumpSession.connect()
        try await session.connect(via: jumpSession)
    } else {
        try await session.connect()
    }
    if let spec = localForward {
        // `signal()`s hanterare är en C-funktionspekare — den kan inte fånga
        // kontext, bara referera globalt/statiskt tillstånd. Görs bara
        // jobb-fritt (sätter en flagga); själva stängningen sker i
        // vänteloopen nedan, som är async-säker.
        signal(SIGINT) { _ in interrupted = 1 }
        let forward = try await session.openLocalPortForward(
            bindHost: spec.bindHost, bindPort: spec.bindPort,
            targetHost: spec.targetHost, targetPort: spec.targetPort)
        FileHandle.standardError.write(Data("""
        Vidarebefordrar \(spec.bindHost):\(forward.actualBindPort) -> \
        \(spec.targetHost):\(spec.targetPort) via \(hostPart):\(port). Ctrl+C avslutar.\n
        """.utf8))
        while interrupted == 0 {
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        await forward.close()
        await session.close()
        await jumpSession?.close()
        exit(0)
    }
    if let spec = remoteForward {
        signal(SIGINT) { _ in interrupted = 1 }
        let forward = try await session.openRemotePortForward(
            bindHost: spec.bindHost, bindPort: spec.bindPort,
            targetHost: spec.targetHost, targetPort: spec.targetPort)
        FileHandle.standardError.write(Data("""
        Fjärrvidarebefordrar \(hostPart):\(forward.actualBindPort) -> \
        \(spec.targetHost):\(spec.targetPort) (lokalt) via \(hostPart):\(port). Ctrl+C avslutar.\n
        """.utf8))
        while interrupted == 0 {
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        await forward.close()
        await session.close()
        await jumpSession?.close()
        exit(0)
    }
    if let spec = dynamicForward {
        signal(SIGINT) { _ in interrupted = 1 }
        let forward = try await session.openDynamicPortForward(bindHost: spec.bindHost, bindPort: spec.bindPort)
        FileHandle.standardError.write(Data("""
        SOCKS5-proxy på \(spec.bindHost):\(forward.actualBindPort) via \(hostPart):\(port). Ctrl+C avslutar.\n
        """.utf8))
        while interrupted == 0 {
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        await forward.close()
        await session.close()
        await jumpSession?.close()
        exit(0)
    }
    for try await chunk in session.execute(command) {
        let handle = chunk.stream == .stderr ? FileHandle.standardError : FileHandle.standardOutput
        handle.write(Data(chunk.bytes))
    }
    await session.close()
    await jumpSession?.close()
} catch let SSHError.remoteExit(status) {
    await session.close()
    await jumpSession?.close()
    exit(Int32(status))
} catch let SSHError.hostKeyRejected(info) {
    await session.close()
    await jumpSession?.close()
    fail("""
    ⚠️  VÄRDNYCKELN HAR ÄNDRATS för \(hostPart):\(port)!
        Presenterad nyckel: \(info.keyType) \(info.sha256Fingerprint)
        Det kan vara en man-in-the-middle-attack — eller så har servern byggts om.
        Litar du på ändringen: ta bort raden för \(hostPart):\(port) ur
        \(KnownHosts.defaultPath) och anslut igen.
    """)
} catch {
    await session.close()
    await jumpSession?.close()
    fail("Fel: \(error)")
}

extension Data {
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else { return nil }
            bytes.append(UInt8(hi << 4 | lo))
            i += 2
        }
        self = Data(bytes)
    }
}
