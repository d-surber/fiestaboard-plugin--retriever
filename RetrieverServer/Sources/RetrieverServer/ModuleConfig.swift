import CryptoKit
import Foundation
import MachO
import RetrieverSourceKit

// The module config: which source modules this server may load.
//
// It is a small JSON file with a detached signature. The server loads only
// the modules it lists, and only while the signature verifies against the
// config key and the config has not expired. There is no unsigned mode. The
// signature is ECDSA P-256 over the file's bytes with SHA-256, in DER, which
// is what `openssl dgst -sha256 -sign` produces and what a Secure Enclave
// key produces, so a config can be signed on this Mac or anywhere else.
//
// Two keys are involved in loading a module. The code-signing identity says
// the module was built by the server's signer (see Signer). The config key
// says this installation is meant to run it.
struct ModuleConfig: Codable, Equatable {
    struct Module: Codable, Equatable {
        /// The module's signing identifier, which is also its XPC service name.
        let identifier: String
        /// Optionally, the hash of the one build that is allowed.
        var cdhash: String?
    }

    /// Counts signings. Informational: expiry, not this, is what retires an old config.
    var version: Int
    var expires: Date
    var modules: [Module]

    static let validity: TimeInterval = 90 * 86400   // how long a signing lasts by default
    static let warningDays = 14                      // warn daily from this many days before expiry

    static func decode(_ data: Data) -> ModuleConfig? {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(ModuleConfig.self, from: data)
    }

    func encoded() -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return ((try? encoder.encode(self)) ?? Data()) + Data("\n".utf8)
    }

    /// Whole days until expiry, rounded down; negative once expired.
    func daysRemaining(now: Date) -> Int {
        Int((expires.timeIntervalSince(now) / 86400).rounded(.down))
    }

    /// The warning to show from `warningDays` before expiry; empty before that.
    func warning(now: Date) -> String {
        let days = daysRemaining(now: now)
        guard days <= ModuleConfig.warningDays else { return "" }
        return days == 1 ? "module config expires in 1 day" : "module config expires in \(days) days"
    }
}

/// Whether there is a module config the server may act on.
enum ConfigVerdict: Equatable {
    case valid(ModuleConfig)
    case invalid(String)   // why not

    var modules: [ModuleConfig.Module] {
        if case .valid(let config) = self { return config.modules }
        return []
    }
}

/// Where the module config lives, and how it is checked.
enum ConfigStore {
    /// Root-owned, so that replacing the config or its key needs an administrator.
    static let installed = URL(fileURLWithPath: "/Library/Application Support/Retriever", isDirectory: true)

    static let configFile = "config.json"
    static let signatureFile = "config.sig"
    static let publicKeyFile = "config-key.pub"   // PEM; ignored when a key is built into the server
    static let keyBlobFile = "config-key.blob"    // a Secure Enclave key, usable only on this Mac, if signing is done here
    static let files = [configFile, signatureFile, publicKeyFile, keyBlobFile]

    /// Where a newly signed config waits to be installed by an administrator.
    static func pending(home: URL) -> URL {
        home.appendingPathComponent("Library/Application Support/Retriever/pending", isDirectory: true)
    }

    /// A config key built into the server at link time, in the section
    /// `__TEXT,__config_key`. It is covered by the server's code signature,
    /// so it cannot be swapped without re-signing the server. When present
    /// it is the only key trusted.
    static func builtInKey() -> String? {
        var size: UInt = 0
        let header = UnsafeRawPointer(#dsohandle).assumingMemoryBound(to: mach_header_64.self)
        guard let bytes = getsectiondata(header, "__TEXT", "__config_key", &size), size > 0 else { return nil }
        return String(decoding: UnsafeBufferPointer(start: bytes, count: Int(size)), as: UTF8.self)
    }

    /// The key configs must be signed with, and where it came from.
    static func trustedKey(in directory: URL, builtIn: String?) -> (pem: String, origin: String)? {
        if let builtIn { return (builtIn, "built into the server") }
        guard let pem = try? String(contentsOf: directory.appendingPathComponent(publicKeyFile), encoding: .utf8) else { return nil }
        return (pem, directory.appendingPathComponent(publicKeyFile).path)
    }

    static func verify(config: Data?, signature: Data?, publicKeyPEM: String?, now: Date) -> ConfigVerdict {
        guard let publicKeyPEM else { return .invalid("no config key") }
        guard let config else { return .invalid("no module config") }
        guard let signature else { return .invalid("module config is not signed") }
        guard let key = try? P256.Signing.PublicKey(pemRepresentation: publicKeyPEM) else { return .invalid("config key is unreadable") }
        guard let parsed = try? P256.Signing.ECDSASignature(derRepresentation: signature), key.isValidSignature(parsed, for: config) else {
            return .invalid("module config signature is not valid")
        }
        guard let decoded = ModuleConfig.decode(config) else { return .invalid("module config is unreadable") }
        guard decoded.expires > now else { return .invalid("module config expired") }
        return .valid(decoded)
    }

    static func load(from directory: URL, builtInKey: String?, now: Date) -> ConfigVerdict {
        verify(config: try? Data(contentsOf: directory.appendingPathComponent(configFile)),
               signature: try? Data(contentsOf: directory.appendingPathComponent(signatureFile)),
               publicKeyPEM: trustedKey(in: directory, builtIn: builtInKey)?.pem,
               now: now)
    }

    /// Changes when any of the files does, so the server can notice a new config.
    static func fingerprint(of directory: URL) -> String {
        files.map { name -> String in
            let attributes = try? FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(name).path)
            let modified = (attributes?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
            return "\(name):\(modified):\(attributes?[.size] as? Int ?? -1)"
        }.joined(separator: "|")
    }
}

/// The module config's own state, served like any source so that a page can
/// show an approaching expiry: {{retriever.module_config.data.warning}}.
final class ConfigSource: Source {
    struct Payload: Codable, Equatable {
        var expires = ""          // ISO 8601, or empty when there is no valid config
        var days_remaining = 0
        var warning = ""          // empty until `warningDays` before expiry
        var version = 0
    }

    let name = "module_config"

    let schema: JSON = [
        "type": "object",
        "properties": [
            "expires": ["type": "string", "format": "date-time"],
            "days_remaining": ["type": "integer"],
            "warning": ["type": "string"],
            "version": ["type": "integer"],
        ],
        "default": ["expires": "", "days_remaining": 0, "warning": "", "version": 0],
    ]

    var verdict: ConfigVerdict = .invalid("not loaded")
    var now: () -> Date = Date.init

    func fetch(_ done: @escaping (Entry) -> Void) {
        done(entry(now: now()))
    }

    func entry(now: Date) -> Entry {
        switch verdict {
        case .invalid(let reason):
            return failed(reason)
        case .valid(let config):
            guard config.expires > now else { return failed("module config expired") }
            return succeeded(Payload(expires: ISO8601DateFormatter().string(from: config.expires),
                                     days_remaining: config.daysRemaining(now: now),
                                     warning: config.warning(now: now),
                                     version: config.version))
        }
    }
}
