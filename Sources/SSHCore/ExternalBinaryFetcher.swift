import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Hämtar och cachar en enskild extern binär (t.ex. `wireguard-go`,
/// `tailscale`) från en URL, verifierad mot en känd SHA256-checksumma innan
/// den någonsin skrivs till disk som "giltig". Motivering:
/// "Native WireGuard/Tailscale — inget externt beroende": Skerry ska kunna
/// ladda ner+köra dessa verktyg själv istället för att kräva att användaren
/// installerat dem separat, men en nedladdad binär är samma tillitsnivå som
/// ett `curl | sudo bash`-skript om checksumman inte verifieras.
///
/// Medvetet GENERISK (URL + förväntad checksumma in, verifierad sökväg ut) —
/// varken WireGuard- eller Tailscale-specifik. Anroparen (framtida UI-lager)
/// äger plattforms-/arkitekturval av URL och det publicerade checksum-värdet;
/// den här typen äger bara hämta+verifiera+cacha-mekaniken, så den kan
/// återanvändas för båda verktygen (och andra framtida) utan duplicering.
public enum ExternalBinaryError: Error, Sendable, Equatable {
    case downloadFailed(String)
    case checksumMismatch(expected: String, actual: String)
    case cacheWriteFailed(String)
    case invalidBinaryName
    case invalidChecksum
    case downloadTooLarge
}

public enum ExternalBinaryFetcher {
    /// Hämtar `url` till `cacheDir/binaryName` om den inte redan finns där
    /// med RÄTT checksumma (idempotent — ett andra anrop med samma
    /// parametrar gör ingen nätverkstrafik alls). En redan cachad fil med FEL
    /// checksumma (korrupt/manipulerad) tas bort och laddas ner på nytt,
    /// aldrig litad på tyst.
    ///
    /// Checksumman verifieras mot de NEDLADDADE bytesen INNAN något skrivs
    /// till disk — en manipulerad/fel binär hamnar aldrig i cachen ens
    /// tillfälligt.
    public static func fetch(
        url: URL,
        expectedSHA256: String,
        cacheDir: URL,
        binaryName: String,
        session: URLSession = .shared
    ) async throws -> URL {
        guard
            !binaryName.isEmpty,
            binaryName != ".",
            binaryName != "..",
            !binaryName.contains("/"),
            !binaryName.contains("\\"),
            !binaryName.contains("\0")
        else {
            throw ExternalBinaryError.invalidBinaryName
        }
        guard url.scheme?.lowercased() == "https", url.host != nil, url.user == nil, url.password == nil else {
            throw ExternalBinaryError.downloadFailed("endast HTTPS-URL:er utan inbäddade uppgifter tillåts")
        }
        let expected = expectedSHA256.lowercased()
        guard expected.utf8.count == 64,
              expected.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else {
            throw ExternalBinaryError.invalidChecksum
        }

        do {
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
            if (try? FileManager.default.destinationOfSymbolicLink(atPath: cacheDir.path)) != nil {
                throw ExternalBinaryError.cacheWriteFailed("cache directory must not be a symbolic link")
            }
            let attributes = try FileManager.default.attributesOfItem(atPath: cacheDir.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory else {
                throw ExternalBinaryError.cacheWriteFailed("cache path is not a directory")
            }
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: cacheDir.path)
        } catch let error as ExternalBinaryError {
            throw error
        } catch {
            throw ExternalBinaryError.cacheWriteFailed("\(error)")
        }

        let destination = cacheDir.appendingPathComponent(binaryName)
        let cachedIsSymlink = (try? FileManager.default.destinationOfSymbolicLink(atPath: destination.path)) != nil
        if !cachedIsSymlink,
           let existing = try? Data(contentsOf: destination),
           sha256Hex(existing) == expected {
            return destination
        }
        // Finns men med fel checksumma (korrupt eller ett gammalt, felaktigt
        // cachat försök) — städa bort tyst, hämta rent på nytt nedan.
        try? FileManager.default.removeItem(at: destination)

        let data: Data
        do {
            let (downloaded, response) = try await session.data(from: url)
            guard let http = response as? HTTPURLResponse,
                  (200...299).contains(http.statusCode),
                  http.url?.scheme?.lowercased() == "https"
            else {
                let status = (response as? HTTPURLResponse)?.statusCode ?? -1
                throw ExternalBinaryError.downloadFailed("HTTP \(status) eller osäker omdirigering för \(url.absoluteString)")
            }
            guard downloaded.count <= 256 * 1024 * 1024 else {
                throw ExternalBinaryError.downloadTooLarge
            }
            data = downloaded
        } catch let error as ExternalBinaryError {
            throw error
        } catch {
            throw ExternalBinaryError.downloadFailed("\(error)")
        }

        let actual = sha256Hex(data)
        guard actual == expected else {
            throw ExternalBinaryError.checksumMismatch(expected: expected, actual: actual)
        }

        do {
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
            // Skriv till en temporär fil i SAMMA katalog, byt sedan namn —
            // en process som läser `destination` mitt under en nedladdning
            // ska aldrig kunna se en halvskriven fil.
            let tmp = cacheDir.appendingPathComponent(".\(binaryName).\(UUID().uuidString).tmp")
            try data.write(to: tmp)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tmp.path)
            _ = try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: tmp, to: destination)
        } catch {
            throw ExternalBinaryError.cacheWriteFailed("\(error)")
        }

        return destination
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
