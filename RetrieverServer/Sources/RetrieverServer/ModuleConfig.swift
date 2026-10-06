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
    /// One module the config allows.
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

    static let defaultValidity: TimeInterval = 90 * 86400   // how long a signing lasts by default
    static let warningDays = 14                      // warn daily from this many days before expiry

    /// Reads a config from the bytes of its file; nil if they are not one.
    static func decode(_ data: Data) -> ModuleConfig? {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(ModuleConfig.self, from: data)
    }

    /// The bytes of the config's file, which are what is signed: the same every time for the same config.
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
enum ModuleConfigVerdict: Equatable {
    case valid(ModuleConfig)
    case invalid(String)   // why not

    var modules: [ModuleConfig.Module] {
        if case .valid(let config) = self { return config.modules }
        return []
    }
}

/// Where the module config lives, and how it is checked.
enum ModuleConfigStore {
    /// Root-owned, so that replacing the config or its key needs an administrator.
    static let installedFolder = URL(fileURLWithPath: "/Library/Application Support/Retriever", isDirectory: true)

    static let configFile = "config.json"
    static let signatureFile = "config.sig"
    static let publicKeyFile = "config-key.pub"   // PEM; ignored when a key is built into the server
    static let keyBlobFile = "config-key.blob"    // a Secure Enclave key, usable only on this Mac, if signing is done here
    static let fileNames = [configFile, signatureFile, publicKeyFile, keyBlobFile]

    /// Where a newly signed config waits to be installed by an administrator.
    static func pendingFolder(home: URL) -> URL {
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

    /// Decides whether a config may be acted on. The signature is checked over the file's bytes before anything in them is believed.
    /// - Parameter publicKeyPEM: the key the signature must verify against.
    static func verify(config: Data?, signature: Data?, publicKeyPEM: String?, now: Date) -> ModuleConfigVerdict {
        guard let publicKeyPEM else { return .invalid("no config key") }
        guard let config else { return .invalid("no module config") }
        guard let signature else { return .invalid("module config is not signed") }
        guard let key = try? P256.Signing.PublicKey(pemRepresentation: publicKeyPEM) else { return .invalid("config key is unreadable") }
        guard let parsed = try? P256.Signing.ECDSASignature(derRepresentation: signature), key.isValidSignature(parsed, for: config) else {
            return .invalid("module config signature is not valid")
        }
        guard let decoded = ModuleConfig.decode(config) else { return .invalid("module config is unreadable") }
        if let problem = problem(withModules: decoded.modules) { return .invalid(problem) }
        guard decoded.expires > now else { return .invalid("module config expired") }
        return .valid(decoded)
    }

    /// What is wrong with the modules a config lists, or nil: the first
    /// module with a problem of its own, or one listed twice. Two entries
    /// for one module would be two sources of one name.
    static func problem(withModules modules: [ModuleConfig.Module]) -> String? {
        if let problem = modules.lazy.compactMap(problem(with:)).first { return problem }
        var listed = Set<String>()
        for module in modules where !listed.insert(module.identifier).inserted {
            return "module config lists \(module.identifier) twice"
        }
        return nil
    }

    /// What is wrong with a module as a config lists it, or nil. Its
    /// identifier and code hash are written into a code-signing requirement,
    /// so neither may be anything but what it claims to be; and its source
    /// may not have a name the plugin keeps for itself.
    static func problem(with module: ModuleConfig.Module) -> String? {
        guard Signer.isModuleIdentifier(module.identifier) else {
            return "module config lists \"\(module.identifier)\", which is not a module's identifier"
        }
        let sourceName = String(module.identifier.dropFirst(Signer.moduleIdentifierPrefix.count))
        guard !Wire.reservedSourceNames.contains(sourceName) else {
            return "module config lists \(module.identifier), whose source would be named \"\(sourceName)\", a name the plugin keeps for itself"
        }
        if let cdhash = module.cdhash, !Signer.isCodeHash(cdhash) {
            return "module config pins \(module.identifier) to \"\(cdhash)\", which is not a code hash"
        }
        return nil
    }

    /// A short form of a config key for a person to compare: the first 16
    /// hexadecimal digits of the SHA-256 of the public key, in fours. Nil if
    /// `pem` is not a P-256 public key.
    static func keyFingerprint(pem: String) -> String? {
        guard let key = try? P256.Signing.PublicKey(pemRepresentation: pem) else { return nil }
        let digits = SHA256.hash(data: key.x963Representation).prefix(8).map { String(format: "%02x", $0) }.joined()
        return stride(from: 0, to: 16, by: 4).map { start in
            String(digits[digits.index(digits.startIndex, offsetBy: start)..<digits.index(digits.startIndex, offsetBy: start + 4)])
        }.joined(separator: " ")
    }

    /// Which key a config being installed must verify against, and whether
    /// that key is to be installed with it.
    enum KeyToTrust: Equatable {
        case builtIn(String)        // the server's own; nothing on disk counts
        case installed(String)      // the one already installed, kept
        case first(String)          // none was installed; this one comes with the config
        case replacement(String)    // a different one, asked for by name

        var pem: String {
            switch self {
            case .builtIn(let pem), .installed(let pem), .first(let pem), .replacement(let pem): return pem
            }
        }

        var isInstalledWithTheConfig: Bool {
            switch self {
            case .first, .replacement: return true
            case .builtIn, .installed: return false
            }
        }
    }

    /// Why no key could be chosen for a config being installed.
    enum KeyRefusal: Error, Equatable {
        case noKey
        case differentKey   // the config comes with a key that is not the installed one
    }

    /// Decides which key a waiting config is checked against.
    ///
    /// The installed key is what makes a config trustworthy, so a config
    /// never brings a different key in with it unless the administrator
    /// says so. Otherwise anything able to write the waiting files could
    /// have its own key, and so its own list of modules, installed.
    /// - Parameters:
    ///   - waiting: the key waiting beside the config, if any.
    ///   - replacingKey: the administrator asked for the key to be changed.
    static func keyToTrust(builtIn: String?, installed: String?, waiting: String?, replacingKey: Bool) throws -> KeyToTrust {
        if let builtIn { return .builtIn(builtIn) }
        guard let installed else {
            guard let waiting else { throw KeyRefusal.noKey }
            return .first(waiting)
        }
        guard let waiting, !isSameKey(installed, waiting) else { return .installed(installed) }
        guard replacingKey else { throw KeyRefusal.differentKey }
        return .replacement(waiting)
    }

    private static func isSameKey(_ first: String, _ second: String) -> Bool {
        guard let one = try? P256.Signing.PublicKey(pemRepresentation: first),
              let other = try? P256.Signing.PublicKey(pemRepresentation: second) else { return first == second }
        return one.rawRepresentation == other.rawRepresentation
    }

    /// Reads the config, its signature and its key from a folder and decides whether it may be acted on.
    static func load(from directory: URL, builtInKey: String?, now: Date) -> ModuleConfigVerdict {
        verify(config: try? Data(contentsOf: directory.appendingPathComponent(configFile)),
               signature: try? Data(contentsOf: directory.appendingPathComponent(signatureFile)),
               publicKeyPEM: trustedKey(in: directory, builtIn: builtInKey)?.pem,
               now: now)
    }

    /// Changes when any of the files does, so the server can notice a new config.
    static func fingerprint(of directory: URL) -> String {
        fileNames.map { name -> String in
            let attributes = try? FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(name).path)
            let modified = (attributes?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
            return "\(name):\(modified):\(attributes?[.size] as? Int ?? -1)"
        }.joined(separator: "|")
    }
}

/// The module config's own state, served like any source so that a page can
/// show an approaching expiry: {{retriever.module_config.data.warning}}.
final class ModuleConfigSource: Source {
    /// What a page can show of the config's state.
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

    var verdict: ModuleConfigVerdict = .invalid("not loaded")
    var now: () -> Date = Date.init

    func fetch(_ done: @escaping (Entry) -> Void) {
        done(entry(now: now()))
    }

    /// The source's entry at a moment: the config's state, or as the error why there is no valid config.
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
