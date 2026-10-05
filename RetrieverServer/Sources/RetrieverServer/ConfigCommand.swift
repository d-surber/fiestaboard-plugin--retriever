import CryptoKit
import Foundation
import LocalAuthentication
import RetrieverSourceKit
import Security

// The server's commands for the module config. They serve nothing and exit.
//
//   RetrieverServer config sign [--days N] [module identifier ...]
//       Run as yourself. Writes a config naming those modules (or, with
//       none named, the modules of the current config), signs it with this
//       Mac's config key, and leaves it waiting to be installed. The key
//       lives in the Secure Enclave and each signature needs Touch ID or
//       your password; the first signing creates it.
//
//   sudo RetrieverServer config install
//       Checks the waiting config's signature and copies it into the
//       root-owned location the server reads.
//
//   RetrieverServer status
//       Says which config key is trusted, whether the config is valid, when
//       it expires, and whether each module it lists can be reached.
//
// Signing and installing are separate on purpose: signing needs the person,
// installing needs an administrator, and neither step can do the other's job.
// A config can equally be signed elsewhere with ordinary tools:
//   openssl dgst -sha256 -sign key.pem -out config.sig config.json
enum ConfigCommand {
    static func run(_ arguments: [String]) -> Never {
        do {
            switch arguments.first {
            case "sign": try sign(Array(arguments.dropFirst()))
            case "install": try install()
            default: throw Problem("usage: RetrieverServer config sign [--days N] [module identifier ...] | config install")
            }
        } catch {
            print("\(error)")
            exit(1)
        }
        exit(0)
    }

    /// This program's full path, for the commands it tells the user to run.
    static var program: String { Bundle.main.executablePath ?? CommandLine.arguments[0] }

    struct Problem: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    // MARK: sign

    static func sign(_ arguments: [String]) throws {
        guard getuid() != 0 else { throw Problem("Sign as yourself, not with sudo: the config key answers to your Touch ID or password.") }
        var days = Int(ModuleConfig.validity / 86400)
        var identifiers: [String] = []
        var rest = arguments[...]
        while let argument = rest.popFirst() {
            if argument == "--days" {
                guard let value = rest.popFirst().flatMap(Int.init), value > 0 else { throw Problem("--days needs a number of days") }
                days = value
            } else {
                identifiers.append(argument)
            }
        }

        let pending = ConfigStore.pending(home: FileManager.default.homeDirectoryForCurrentUser)
        try FileManager.default.createDirectory(at: pending, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let previous = (try? Data(contentsOf: ConfigStore.installed.appendingPathComponent(ConfigStore.configFile))).flatMap(ModuleConfig.decode)

        let modules = identifiers.isEmpty ? (previous?.modules ?? []) : identifiers.map { ModuleConfig.Module(identifier: $0) }
        guard !modules.isEmpty else { throw Problem("Name the modules to allow, for example: config sign \(Signer.moduleIdentifier(for: "os"))") }
        let config = ModuleConfig(version: (previous?.version ?? 0) + 1,
                                  expires: Date().addingTimeInterval(TimeInterval(days) * 86400),
                                  modules: modules)
        let bytes = config.encoded()

        let (key, blob, created) = try configKey(pending: pending)
        if created { print("Created a config key in this Mac's Secure Enclave.") }
        print("Signing: approve with Touch ID or your password.")
        let signature = try key.signature(for: bytes)

        try bytes.write(to: pending.appendingPathComponent(ConfigStore.configFile))
        try signature.derRepresentation.write(to: pending.appendingPathComponent(ConfigStore.signatureFile))
        try Data(key.publicKey.pemRepresentation.utf8).write(to: pending.appendingPathComponent(ConfigStore.publicKeyFile))
        try blob.write(to: pending.appendingPathComponent(ConfigStore.keyBlobFile))

        print("Signed module config version \(config.version), valid for \(days) days, for:")
        for module in modules { print("  \(module.identifier)") }
        print("It is waiting in \(pending.path).")
        print("Install it with: sudo \"\(program)\" config install")
    }

    /// The Secure Enclave key configs are signed with on this Mac: the one
    /// already in use, or a new one. What is stored is a blob only this
    /// Mac's enclave can use, and only with the user present.
    static func configKey(pending: URL) throws -> (SecureEnclave.P256.Signing.PrivateKey, Data, created: Bool) {
        guard SecureEnclave.isAvailable else {
            throw Problem("This Mac has no Secure Enclave. Sign the config elsewhere with openssl (see the comment in ConfigCommand.swift).")
        }
        let context = LAContext()
        context.localizedReason = "sign the Retriever module config"
        for directory in [ConfigStore.installed, pending] {
            if let blob = try? Data(contentsOf: directory.appendingPathComponent(ConfigStore.keyBlobFile)),
               let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context) {
                return (key, blob, false)
            }
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           [.privateKeyUsage, .userPresence], &error) else {
            throw Problem("Could not set up the config key: \(String(describing: error?.takeRetainedValue()))")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access, authenticationContext: context)
        return (key, key.dataRepresentation, true)
    }

    // MARK: install

    static func install() throws {
        guard getuid() == 0 else { throw Problem("Installing needs an administrator: sudo \"\(program)\" config install") }
        guard let user = ProcessInfo.processInfo.environment["SUDO_USER"], let entry = getpwnam(user) else {
            throw Problem("Run this with sudo from your own account, so the waiting config can be found.")
        }
        let pending = ConfigStore.pending(home: URL(fileURLWithPath: String(cString: entry.pointee.pw_dir), isDirectory: true))
        func waiting(_ name: String) -> Data? { try? Data(contentsOf: pending.appendingPathComponent(name)) }

        // The key the config must verify against: one built into the server
        // wins; otherwise the one being installed with it, or already installed.
        let waitingKey = waiting(ConfigStore.publicKeyFile).map { String(decoding: $0, as: UTF8.self) }
        let trusted = ConfigStore.builtInKey() ?? waitingKey ?? ConfigStore.trustedKey(in: ConfigStore.installed, builtIn: nil)?.pem
        let verdict = ConfigStore.verify(config: waiting(ConfigStore.configFile), signature: waiting(ConfigStore.signatureFile),
                                         publicKeyPEM: trusted, now: Date())
        guard case .valid(let config) = verdict else {
            if case .invalid(let reason) = verdict { throw Problem("Not installed: \(reason) (looked in \(pending.path)).") }
            throw Problem("Not installed.")
        }

        let files = FileManager.default
        try files.createDirectory(at: ConfigStore.installed, withIntermediateDirectories: true)
        try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755], ofItemAtPath: ConfigStore.installed.path)
        for name in ConfigStore.files {
            guard let data = waiting(name) else { continue }
            let destination = ConfigStore.installed.appendingPathComponent(name)
            try data.write(to: destination, options: .atomic)
            try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o644], ofItemAtPath: destination.path)
            try? files.removeItem(at: pending.appendingPathComponent(name))
        }
        print("Installed module config version \(config.version) in \(ConfigStore.installed.path).")
        print("It expires in \(config.daysRemaining(now: Date())) days. The server picks it up within a minute.")
    }

    // MARK: status

    static func status() -> Never {
        let now = Date()
        let builtIn = ConfigStore.builtInKey()
        if let trusted = ConfigStore.trustedKey(in: ConfigStore.installed, builtIn: builtIn) {
            print("Config key: \(trusted.origin)")
        } else {
            print("Config key: none")
        }
        let verdict = ConfigStore.load(from: ConfigStore.installed, builtInKey: builtIn, now: now)
        switch verdict {
        case .invalid(let reason):
            print("Module config: \(reason). No modules are loaded.")
        case .valid(let config):
            let warning = config.warning(now: now)
            print("Module config: valid, version \(config.version), expires in \(config.daysRemaining(now: now)) days" + (warning.isEmpty ? "" : " (\(warning))"))
        }
        for module in verdict.modules {
            let pin = module.cdhash.map { ", pinned to build \($0.prefix(12))…" } ?? ""
            do {
                let source = try RemoteSource(service: module.identifier, cdhash: module.cdhash)
                let answered = DispatchSemaphore(value: 0)
                source.fetch { entry in
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                    let data = (try? encoder.encode(entry.data)).map { String(decoding: $0, as: UTF8.self) } ?? "?"
                    print("\(module.identifier)\(pin): ok; source \"\(source.name)\"; error \"\(entry.error)\"; data \(data)")
                    answered.signal()
                }
                answered.wait()
            } catch {
                print("\(module.identifier)\(pin): \(error)")
            }
        }
        exit(0)
    }
}
