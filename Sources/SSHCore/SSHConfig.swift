import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Uppslaget resultat för ett värdalias ur `~/.ssh/config`.
public struct ResolvedHost: Sendable, Equatable {
    public var hostName: String
    public var user: String?
    public var port: Int
    public var identityFile: String?
    public var proxyJump: String?
    /// OpenSSH:s `ForwardAgent`. Bara ett uttryckligt ja räknas — allt annat,
    /// inklusive nyckelns frånvaro, är nej. Att gissa fel åt det hållet vore
    /// att slå på agentvidarebefordran åt någon som inte bett om det, och då
    /// kan vem som helst med root på fjärrvärden använda deras nycklar så
    /// länge sessionen lever.
    public var forwardAgent: Bool = false
    /// OpenSSH:s `RemoteCommand` — kommandot som körs direkt efter anslutning.
    /// Motsvarar ``Host/startupCommand``.
    public var remoteCommand: String?
}

/// Minimal läsare av OpenSSH:s klientkonfiguration (`~/.ssh/config`). Stöder
/// `Host`-block med jokertecken (`*`, `?`) och negation (`!`), `Include`, samt
/// de vanligaste nycklarna. Semantik enligt OpenSSH: **första värdet vinner**
/// per nyckel. `Match` stöds för de kriterier som går att avgöra utan en
/// pågående anslutning (`all`, `host`); allt annat lämnar blocket inaktivt —
/// se ``matchIsActive(_:_:)``.
public struct SSHConfig: Sendable {
    private enum Entry: Sendable {
        case host([String])
        /// Ett `Match`-block, med kriterieraden bevarad rå. Utvärderas först
        /// i `resolve`, eftersom `host`-kriteriet beror på vilket alias som
        /// slås upp — till skillnad från `host`, vars mönster står i posten.
        case match(String)
        case setting(String, String)
    }
    private let entries: [Entry]

    public static var defaultPath: String {
        (("~/.ssh/config") as NSString).expandingTildeInPath
    }

    /// Största antal `Include`-nivåer som följs. Samma gräns som OpenSSH:s
    /// egen (`readconf.c`, `MAX_READCONF_DEPTH` = 16), och av samma skäl: en
    /// config som direkt eller indirekt inkluderar sig själv ska ge en
    /// trunkerad läsning, inte en oändlig loop.
    private static let maxIncludeDepth = 16
    private static let maxFileReads = 256
    private static let maxBytes = 8 * 1024 * 1024
    private static let maxEntries = 100_000
    private static let maxDirectoryEntries = 4096
    private static let maxIncludePatterns = 4096
    private static let maxGlobWork = 4_000_000

    private struct FileIdentity: Hashable {
        let device: UInt64
        let inode: UInt64
    }

    private struct LoadState {
        var bounded: Bool
        var fileReads = 0
        var bytes = 0
        var entries = 0
        var directoryEntries = 0
        var includePatterns = 0
        var globWork = 0
        var exhausted = false
        var active: Set<FileIdentity> = []
    }

    private init(entries: [Entry]) {
        self.entries = entries
    }

    /// Läser en config-TEXT utan att röra filsystemet. `Include`-rader hoppas
    /// över — det finns ingen katalog att lösa dem mot. Använd
    /// ``load(path:)`` när filen finns på disk.
    public init(text: String) {
        var out: [Entry] = []
        var state = LoadState(bounded: false)
        SSHConfig.collectEntries(text: text, baseDir: nil, depth: 0, into: &out, state: &state)
        self.entries = out
    }

    /// Läser en config från disk och FÖLJER `Include`-rader.
    ///
    /// Det här är skillnaden mellan att läsa en modern `~/.ssh/config` och att
    /// läsa ingenting alls: `Include ~/.ssh/config.d/*` är hur de flesta
    /// verktyg (1Password, Colima, OrbStack m.fl.) säger åt användaren att
    /// lägga upp sin config, och då står det inte en enda `Host`-rad i
    /// huvudfilen.
    ///
    /// Cycles are skipped. Disk loads stop when their shared limits are reached:
    /// 256 file attempts, 8 MiB read, 100,000 entries and host patterns, 4,096
    /// directory entries, 4,096 include patterns, or 4,000,000 glob work units.
    /// Only regular files are read.
    /// The entries collected before a limit was reached are returned.
    public static func load(path: String = SSHConfig.defaultPath) -> SSHConfig {
        var out: [Entry] = []
        var state = LoadState(bounded: true)
        loadFile(path, baseDir: (path as NSString).deletingLastPathComponent,
                 depth: 0, into: &out, state: &state)
        return SSHConfig(entries: out)
    }

    // Count attempted reads as well as successful ones. Read from the opened
    // regular file in bounded chunks, so its size cannot change between a size
    // check and an unbounded read. Inodes also identify symlink and hard-link cycles.
    private static func loadFile(
        _ path: String, baseDir: String, depth: Int, into out: inout [Entry],
        state: inout LoadState
    ) {
        guard !state.exhausted else { return }
        guard state.fileReads < maxFileReads else { state.exhausted = true; return }
        state.fileReads += 1
        let fd = open(path, O_RDONLY | O_NONBLOCK)
        guard fd >= 0 else { return }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else { return }
        let identity = FileIdentity(device: UInt64(truncatingIfNeeded: info.st_dev), inode: UInt64(truncatingIfNeeded: info.st_ino))
        guard !state.active.contains(identity) else { return }

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = min(buffer.count, maxBytes - state.bytes + 1)
            let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, count) }
            if n < 0 {
                if errno == EINTR { continue }
                return
            }
            if n == 0 { break }
            guard n <= maxBytes - state.bytes else { state.exhausted = true; return }
            state.bytes += n
            data.append(contentsOf: buffer.prefix(n))
        }
        guard let text = String(data: data, encoding: .utf8) else { return }
        state.active.insert(identity)
        defer { state.active.remove(identity) }
        collectEntries(text: text, baseDir: baseDir, depth: depth, into: &out, state: &state)
    }

    /// Includes are expanded inline, preserving first-value-wins ordering.
    /// Disk loads stop at the shared budgets; text-only parsing remains unlimited.
    private static func collectEntries(
        text: String, baseDir: String?, depth: Int, into out: inout [Entry],
        state: inout LoadState
    ) {
        var lineStart = text.startIndex
        while lineStart < text.endIndex {
            guard !state.exhausted else { return }
            let lineEnd = text[lineStart...].firstIndex(where: { $0 == "\n" || $0 == "\r" }) ?? text.endIndex
            let rawLine = text[lineStart..<lineEnd]
            lineStart = lineEnd == text.endIndex ? lineEnd : text.index(after: lineEnd)
            guard let (key, value) = SSHConfig.tokenize(String(rawLine)) else { continue }
            if key == "include" {
                guard let baseDir, depth < maxIncludeDepth else { continue }
                for included in resolveInclude(value, baseDir: baseDir, state: &state) {
                    guard !state.exhausted else { return }
                    loadFile(included, baseDir: baseDir, depth: depth + 1, into: &out, state: &state)
                }
                continue
            }
            if state.bounded {
                guard state.entries < maxEntries else { state.exhausted = true; return }
                state.entries += 1
            }
            switch key {
            case "host":
                let patterns = value.split(
                    maxSplits: state.bounded ? maxEntries : Int.max,
                    whereSeparator: { $0 == " " || $0 == "\t" })
                if state.bounded {
                    guard patterns.count <= maxEntries - state.entries else { state.exhausted = true; return }
                    state.entries += patterns.count
                }
                out.append(.host(patterns.map(String.init)))
            case "match":
                out.append(.match(value))
            default:
                out.append(.setting(key, value))
            }
        }
    }

    /// Resolves an `Include` line to concrete files. A line may list several
    /// paths, each with `~` and/or wildcards; relative paths are resolved
    /// against the root config's directory (OpenSSH uses `~/.ssh`, the same
    /// directory in practice, but this also holds when the file lives elsewhere).
    ///
    /// Matches are sorted, as `glob(3)` returns them to OpenSSH, because the
    /// first value per key wins. A missing file is skipped instead of failing as
    /// OpenSSH does: otherwise one stale line left by an uninstalled tool would
    /// stop every host from loading. Directory enumeration and glob matching
    /// share the load's budgets.
    private static func resolveInclude(_ value: String, baseDir: String, state: inout LoadState) -> [String] {
        var out: [String] = []
        var cursor = value.startIndex
        while cursor < value.endIndex {
            while cursor < value.endIndex && (value[cursor] == " " || value[cursor] == "\t") {
                cursor = value.index(after: cursor)
            }
            guard cursor < value.endIndex else { break }
            guard state.includePatterns < maxIncludePatterns else { state.exhausted = true; return [] }
            state.includePatterns += 1
            let start = cursor
            while cursor < value.endIndex && value[cursor] != " " && value[cursor] != "\t" {
                cursor = value.index(after: cursor)
            }
            guard out.count < maxFileReads else { state.exhausted = true; return [] }
            let expanded = (String(value[start..<cursor]) as NSString).expandingTildeInPath
            let full = (expanded as NSString).isAbsolutePath
                ? expanded : (baseDir as NSString).appendingPathComponent(expanded)
            guard expanded.contains("*") || expanded.contains("?") else {
                out.append(full)
                continue
            }
            let dir = (full as NSString).deletingLastPathComponent
            let pattern = (full as NSString).lastPathComponent
            guard let directory = opendir(dir) else { continue }
            var names: [String] = []
            let patternSize = pattern.utf8.count
            while let entry = readdir(directory) {
                state.directoryEntries += 1
                if state.directoryEntries > maxDirectoryEntries { state.exhausted = true; break }
                let nameCapacity = MemoryLayout.size(ofValue: entry.pointee.d_name)
                let name = withUnsafePointer(to: &entry.pointee.d_name) {
                    $0.withMemoryRebound(to: CChar.self, capacity: nameCapacity) {
                        String(validatingUTF8: $0)
                    }
                }
                guard let name, name != ".", name != ".." else { continue }
                // A conservative bound on comparisons made by glob's backtracking.
                let nameSize = name.utf8.count
                guard patternSize <= (maxGlobWork - state.globWork) / max(1, nameSize) else {
                    state.exhausted = true; break
                }
                state.globWork += patternSize * max(1, nameSize)
                if glob(pattern, name) { names.append(name) }
            }
            closedir(directory)
            guard !state.exhausted, out.count + names.count <= maxFileReads else {
                state.exhausted = true; return []
            }
            out += names.sorted().map { (dir as NSString).appendingPathComponent($0) }
        }
        return out
    }

    /// Konkreta värdalias (inte jokertecken/negation) i den ordning de står —
    /// underlag för att importera värdar till host-databasen.
    public var hostAliases: [String] {
        var seen = Set<String>()
        var out: [String] = []
        for entry in entries {
            guard case .host(let patterns) = entry else { continue }
            for p in patterns where !p.contains("*") && !p.contains("?") && !p.hasPrefix("!") {
                if seen.insert(p).inserted { out.append(p) }
            }
        }
        return out
    }

    /// Slår upp ett alias. Nycklar före första `Host` är globala (gäller alla).
    public func resolve(_ alias: String) -> ResolvedHost {
        var found: [String: String] = [:]
        var active = true  // global sektion tills första Host/Match
        for entry in entries {
            switch entry {
            case .host(let patterns):
                active = SSHConfig.hostMatches(patterns, alias)
            case .match(let criteria):
                active = SSHConfig.matchIsActive(criteria, alias)
            case .setting(let key, let value):
                if active, found[key] == nil { found[key] = value }
            }
        }
        return ResolvedHost(
            hostName: found["hostname"] ?? alias,
            user: found["user"],
            port: found["port"].flatMap { Int($0) } ?? 22,
            identityFile: found["identityfile"].map {
                ($0 as NSString).expandingTildeInPath
            },
            proxyJump: found["proxyjump"],
            forwardAgent: found["forwardagent"]?.lowercased() == "yes",
            remoteCommand: found["remotecommand"])
    }

    // MARK: - Parsning

    /// Delar en rad i (nyckel-gemener, värde). Stöder `Key Value`, `Key=Value`,
    /// `Key = Value` och citerade värden. Returnerar nil för tomma/kommentarrader.
    static func tokenize(_ line: String) -> (String, String)? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty || trimmed.hasPrefix("#") { return nil }
        guard let sep = trimmed.firstIndex(where: { $0 == " " || $0 == "\t" || $0 == "=" }) else {
            return (trimmed.lowercased(), "")
        }
        let key = String(trimmed[..<sep]).lowercased()
        var value = String(trimmed[trimmed.index(after: sep)...])
            .trimmingCharacters(in: CharacterSet(charactersIn: " \t="))
        if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") {
            value = String(value.dropFirst().dropLast())
        }
        return (key, value)
    }

    /// En värd matchar om minst ett positivt mönster matchar och inget negerat gör det.
    /// Plockar ut värdaliaset ur ett `ProxyJump`-värde.
    ///
    /// Syntaxen är `[user@]host[:port]`, och flera hopp kan anges
    /// kommaseparerat. Bara FÖRSTA hoppet returneras — anslutningskedjan
    /// stöder ändå bara ett hopp, så att importera en längre kedja skulle
    /// skapa en koppling som inte går att använda.
    ///
    /// `nil` när värdet är tomt eller `none` (OpenSSH:s sätt att stänga av
    /// ett ärvt `ProxyJump`).
    public static func proxyJumpAlias(_ value: String) -> String? {
        guard let first = value.split(separator: ",").first.map(String.init)?
            .trimmingCharacters(in: .whitespaces), !first.isEmpty else { return nil }
        if first.lowercased() == "none" { return nil }
        let withoutUser = first.split(separator: "@").last.map(String.init) ?? first
        // IPv6-literaler skrivs `[::1]:22` — allt före den avslutande
        // klammern hör till adressen, inte till porten.
        let host: String
        if let end = withoutUser.firstIndex(of: "]") {
            host = String(withoutUser[...end])
        } else {
            host = withoutUser.split(separator: ":").first.map(String.init) ?? withoutUser
        }
        return host.isEmpty ? nil : host
    }

    /// Avgör om ett `Match`-blocks kriterier gäller för `alias`.
    ///
    /// OpenSSH kräver att ALLA kriterier på raden är uppfyllda. Här kan bara
    /// två av dem avgöras: `all` (alltid) och `host <mönster>` (samma
    /// jokertecken- och negationsregler som `Host`). Resten — `exec`, `user`,
    /// `originalhost`, `localuser`, `tagged`, `final`, `canonical` — beror på
    /// en pågående anslutning, en kommandokörning eller en andra
    /// upplösningsomgång, inget av det finns här.
    ///
    /// Ett okänt eller oavgörbart kriterium gör blocket INAKTIVT, aldrig
    /// aktivt. Det är den enda riktning som är säker: ett block som felaktigt
    /// hoppas över ger samma resultat som innan `Match` stöddes alls, medan
    /// ett block som felaktigt aktiveras tyst byter ut användarens värdnamn,
    /// användare eller nyckel mot någon annans.
    ///
    /// `Match exec "..."` kommer aldrig att köras härifrån. Att köra ett
    /// godtyckligt skalkommando för att avgöra en konfigurationsrad är inte
    /// en funktion som saknas, det är en vi inte vill ha.
    static func matchIsActive(_ criteria: String, _ alias: String) -> Bool {
        // Delas BARA på blanksteg. Ett `host`-kriterium tar en kommaseparerad
        // mönsterlista (`Match host *.internal,!hemlig.internal`); delas
        // kommatecknen redan här blir listans andra mönster ett eget, okänt
        // kriterium — vilket tyst gör varje negation till en avaktivering av
        // hela blocket. (Exakt den buggen fanns i Rust-porten först, och
        // fångades av dess negationstest.)
        let tokens = criteria
            .split(whereSeparator: { $0 == " " || $0 == "\t" })
            .map(String.init)
        guard !tokens.isEmpty else { return false }

        var i = 0
        var matchedSomething = false
        while i < tokens.count {
            switch tokens[i].lowercased() {
            case "all":
                matchedSomething = true
                i += 1
            case "host":
                // Kriteriet tar ett argument. Saknas det är raden trasig.
                guard i + 1 < tokens.count else { return false }
                let patterns = tokens[i + 1].split(separator: ",").map(String.init)
                guard SSHConfig.hostMatches(patterns, alias) else { return false }
                matchedSomething = true
                i += 2
            default:
                // Vi kan inte avgöra det, alltså gäller blocket inte.
                return false
            }
        }
        return matchedSomething
    }

    static func hostMatches(_ patterns: [String], _ host: String) -> Bool {
        guard !patterns.isEmpty else { return false }
        var matched = false
        for pattern in patterns {
            if pattern.hasPrefix("!") {
                if glob(String(pattern.dropFirst()), host) { return false }
            } else if glob(pattern, host) {
                matched = true
            }
        }
        return matched
    }

    /// Jokertecken-matchning med `*` (noll+ tecken) och `?` (exakt ett tecken).
    static func glob(_ pattern: String, _ text: String) -> Bool {
        let p = Array(pattern), t = Array(text)
        var pi = 0, ti = 0
        var star = -1, mark = 0
        while ti < t.count {
            if pi < p.count, p[pi] == "?" || p[pi] == t[ti] {
                pi += 1; ti += 1
            } else if pi < p.count, p[pi] == "*" {
                star = pi; mark = ti; pi += 1
            } else if star != -1 {
                pi = star + 1; mark += 1; ti = mark
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }
}
