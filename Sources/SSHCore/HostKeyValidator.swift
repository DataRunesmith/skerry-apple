import Crypto
import Foundation
import NIOCore
import NIOSSH

/// TOFU-validering av värdnyckeln mot en `KnownHosts`-lagring. Okänd värd lärs
/// in; oförändrad accepteras; ändrad avvisas (MITM-skydd). Ersätter den tidigare
/// "acceptera allt"-stubben.
// Configuration is immutable, KnownHosts serializes its state with a lock, and
// the failure callback is invoked only on the validation promise's event loop.
final class TOFUHostKeyValidator: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    private static let ioQueue = DispatchQueue(label: "skerry.known-hosts.io")
    private let host: String
    private let port: Int
    private let store: KnownHosts
    // NIOSSH stänger inte anslutningen självt när vi avvisar — sessionen får
    // signalen härigenom så pågående anrop inte hänger.
    private let onFailure: (SSHError) -> Void

    init(host: String, port: Int, store: KnownHosts, onFailure: @escaping (SSHError) -> Void) {
        self.host = host
        self.port = port
        self.store = store
        self.onFailure = onFailure
    }

    func validateHostKey(
        hostKey: NIOSSHPublicKey,
        validationCompletePromise: EventLoopPromise<Void>
    ) {
        let keyString = String(openSSHPublicKey: hostKey)
        Self.ioQueue.async { [self] in
            let verdict = store.check(host: host, port: port, keyString: keyString)
            validationCompletePromise.futureResult.eventLoop.execute { [self] in
                switch verdict {
                case .trusted, .learned:
                    validationCompletePromise.succeed(())
                case .changed:
                    let info = fingerprint(of: hostKey)
                    let error = SSHError.hostKeyRejected(info)
                    onFailure(error)
                    validationCompletePromise.fail(error)
                case .storageFailure:
                    let error = SSHError.knownHostsUnavailable
                    onFailure(error)
                    validationCompletePromise.fail(error)
                }
            }
        }
    }
}

/// SHA256-fingeravtryck i samma format som `ssh-keygen -lf` ("SHA256:...").
func fingerprint(of key: NIOSSHPublicKey) -> HostKeyInfo {
    let ossh = String(openSSHPublicKey: key)     // "ssh-ed25519 AAAA..."
    let parts = ossh.split(separator: " ")
    let keyType = parts.first.map(String.init) ?? "?"
    var fp = "?"
    if parts.count >= 2, let blob = Data(base64Encoded: String(parts[1])) {
        var b64 = Data(SHA256.hash(data: blob)).base64EncodedString()
        while b64.hasSuffix("=") { b64.removeLast() }
        fp = "SHA256:" + b64
    }
    return HostKeyInfo(sha256Fingerprint: fp, keyType: keyType)
}
