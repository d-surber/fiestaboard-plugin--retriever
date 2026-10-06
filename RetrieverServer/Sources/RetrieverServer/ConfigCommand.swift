import CryptoKit
import Foundation
import LocalAuthentication
import RetrieverSourceKit
import Security

// The server's commands for the module config. They serve nothing and exit;
// `RetrieverServer help` describes them all.
//
// Signing and installing are separate on purpose: signing needs the person,
// installing needs an administrator, and neither step can do the other's job.
// The key lives in the Secure Enclave and each signature needs Touch ID or
// the account password; the first signing creates it. A config can equally
// be signed elsewhere with ordinary tools:
//   openssl dgst -sha256 -sign key.pem -out config.sig config.json
enum ConfigCommand {
    static func run(_ arguments: [String]) -> Never {
        do {
            let rest = Array(arguments.dropFirst())
            switch arguments.first {
            case "sign": try sign(rest)
            case "add": try add(rest)
            case "remove": try remove(rest)
            case "install": try install(rest)
            default: throw Problem("Unknown config command. See: \"\(program)\" help")
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

    /// `--days N`, `--pin` and `--replace-key`, and whatever else was given.
    struct Options: Equatable {
        var days = Int(ModuleConfig.validity / 86400)
        var pin = false
        var replaceKey = false
        var names: [String] = []

        init(_ arguments: [String]) throws {
            var rest = arguments[...]
            while let argument = rest.popFirst() {
                switch argument {
                case "--days":
                    guard let value = rest.popFirst().flatMap(Int.init), value > 0 else { throw Problem("--days needs a number of days") }
                    days = value
                case "--pin":
                    pin = true
                case "--replace-key":
                    replaceKey = true
                default:
                    names.append(argument)
                }
            }
        }
    }

    static var installedConfig: ModuleConfig? {
        (try? Data(contentsOf: ConfigStore.installed.appendingPathComponent(ConfigStore.configFile))).flatMap(ModuleConfig.decode)
    }

    /// The list after allowing `added`: each replaces any entry for the same module.
    static func allowing(_ added: [ModuleConfig.Module], in modules: [ModuleConfig.Module]) -> [ModuleConfig.Module] {
        modules.filter { existing in !added.contains { $0.identifier == existing.identifier } } + added
    }

    /// config sign: sign the current list again, or, with no config yet,
    /// a list of every installed module. Naming modules replaces the list.
    static func sign(_ arguments: [String]) throws {
        let options = try Options(arguments)
        var modules = options.names.map { ModuleConfig.Module(identifier: $0) }
        if let problem = ConfigStore.problem(withModules: modules) { throw Problem("Not signed: \(problem).") }
        if modules.isEmpty { modules = installedConfig?.modules ?? [] }
        if modules.isEmpty {
            modules = Installation.modules(in: Installation.programs).accepted.map { ModuleConfig.Module(identifier: $0.identifier) }
        }
        guard !modules.isEmpty else { throw Problem("There are no installed modules to allow. Install first: sudo \"\(program)\" install") }
        try stage(modules, days: options.days)
    }

    /// config add: allow a module, named by its program's path or its identifier.
    static func add(_ arguments: [String]) throws {
        let options = try Options(arguments)
        guard !options.names.isEmpty else { throw Problem("Name the module to allow: its program, or its identifier.") }
        let installed = Installation.modules(in: Installation.programs).accepted
        var added: [ModuleConfig.Module] = []
        for name in options.names {
            let module: Signer.Program
            if FileManager.default.fileExists(atPath: name) {
                do { module = try Signer.inspect(name) } catch { throw Problem("Not added: \(error).") }
            } else if let found = installed.first(where: { $0.identifier == name }) {
                module = found
            } else {
                throw Problem("Not added: no installed module is signed as \"\(name)\", and there is no such file.")
            }
            guard module.identifier.hasPrefix(Installation.moduleIdentifierPrefix) else {
                throw Problem("Not added: \(module.path) is signed as \"\(module.identifier)\", which is not a module.")
            }
            added.append(ModuleConfig.Module(identifier: module.identifier, cdhash: options.pin ? module.cdhash : nil))
        }
        try stage(allowing(added, in: installedConfig?.modules ?? []), days: options.days)
    }

    /// config remove: stop allowing a module.
    static func remove(_ arguments: [String]) throws {
        let options = try Options(arguments)
        let current = installedConfig?.modules ?? []
        let remaining = current.filter { !options.names.contains($0.identifier) }
        guard remaining.count < current.count else { throw Problem("Nothing removed: the config allows none of those.") }
        try stage(remaining, days: options.days)
    }

    /// Shows what a config would allow, signs it, and leaves it waiting to be installed.
    static func stage(_ modules: [ModuleConfig.Module], days: Int) throws {
        guard getuid() != 0 else { throw Problem("Sign as yourself, not with sudo: the config key answers to your Touch ID or password.") }
        let pending = ConfigStore.pending(home: FileManager.default.homeDirectoryForCurrentUser)
        try FileManager.default.createDirectory(at: pending, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let config = ModuleConfig(version: (installedConfig?.version ?? 0) + 1,
                                  expires: Date().addingTimeInterval(TimeInterval(days) * 86400),
                                  modules: modules)
        let bytes = config.encoded()

        print("Module config version \(config.version), valid for \(days) days, will allow:")
        if modules.isEmpty { print("  no modules") }
        for module in modules {
            print("  \(module.identifier)" + (module.cdhash.map { ", only the build \($0)" } ?? ""))
        }

        if let problem = ConfigStore.problem(withModules: modules) { throw Problem("Not signed: \(problem).") }
        let (key, blob, created) = try configKey(pending: pending)
        if created { print("Created a config key in this Mac's Secure Enclave.") }
        print("Config key: \(ConfigStore.keyFingerprint(pem: key.publicKey.pemRepresentation) ?? "unreadable")")
        print("Signing: approve with Touch ID or your password.")
        let signature = try key.signature(for: bytes)

        try bytes.write(to: pending.appendingPathComponent(ConfigStore.configFile))
        try signature.derRepresentation.write(to: pending.appendingPathComponent(ConfigStore.signatureFile))
        try Data(key.publicKey.pemRepresentation.utf8).write(to: pending.appendingPathComponent(ConfigStore.publicKeyFile))
        try blob.write(to: pending.appendingPathComponent(ConfigStore.keyBlobFile))

        print("Signed. It is waiting in \(pending.path).")
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

    /// config install: check the config waiting in the invoking account's
    /// folder and put it where the server reads it.
    static func install(_ arguments: [String]) throws {
        let options = try Options(arguments)
        guard getuid() == 0 else { throw Problem("Installing needs an administrator: sudo \"\(program)\" config install") }
        guard let account = InvokingAccount.fromSudo() else {
            throw Problem("Run this with sudo from your own account, so the waiting config can be found.")
        }
        let pending = ConfigStore.pending(home: account.home)

        // Each waiting file is read once, with the account's own access, and
        // what is checked is what is installed.
        let waiting = try account.withItsAccess {
            Dictionary(uniqueKeysWithValues: ConfigStore.files.compactMap { name in
                (try? Data(contentsOf: pending.appendingPathComponent(name))).map { (name, $0) }
            })
        }
        let waitingKey = waiting[ConfigStore.publicKeyFile].map { String(decoding: $0, as: UTF8.self) }
        let installedKey = try? String(contentsOf: ConfigStore.installed.appendingPathComponent(ConfigStore.publicKeyFile), encoding: .utf8)

        let key: ConfigStore.KeyToTrust
        do {
            key = try ConfigStore.keyToTrust(builtIn: ConfigStore.builtInKey(), installed: installedKey, waiting: waitingKey,
                                             replacingKey: options.replaceKey)
        } catch ConfigStore.KeyRefusal.differentKey {
            throw Problem("""
                Not installed: the waiting config comes with config key \(waitingKey.flatMap(ConfigStore.keyFingerprint) ?? "unreadable"),
                which is not the installed one, \(installedKey.flatMap(ConfigStore.keyFingerprint) ?? "unreadable").
                If you mean to change the config key: sudo "\(program)" config install --replace-key
                """)
        } catch {
            throw Problem("Not installed: no config key (looked in \(pending.path)).")
        }
        let verdict = ConfigStore.verify(config: waiting[ConfigStore.configFile], signature: waiting[ConfigStore.signatureFile],
                                         publicKeyPEM: key.pem, now: Date())
        guard case .valid(let config) = verdict else {
            if case .invalid(let reason) = verdict { throw Problem("Not installed: \(reason) (looked in \(pending.path)).") }
            throw Problem("Not installed.")
        }

        // The key and its enclave blob go in only when the key is new here.
        var installing = [ConfigStore.configFile, ConfigStore.signatureFile]
        if key.isInstalledWithTheConfig { installing += [ConfigStore.publicKeyFile, ConfigStore.keyBlobFile] }

        let files = FileManager.default
        try files.createDirectory(at: ConfigStore.installed, withIntermediateDirectories: true)
        try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755], ofItemAtPath: ConfigStore.installed.path)
        for name in installing {
            guard let data = waiting[name] else { continue }
            let destination = ConfigStore.installed.appendingPathComponent(name)
            try data.write(to: destination, options: .atomic)
            try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o644], ofItemAtPath: destination.path)
        }
        try account.withItsAccess {
            for name in waiting.keys { try? files.removeItem(at: pending.appendingPathComponent(name)) }
        }

        print("Installed module config version \(config.version) in \(ConfigStore.installed.path). It allows:")
        if config.modules.isEmpty { print("  no modules") }
        for module in config.modules {
            print("  \(module.identifier)" + (module.cdhash.map { ", only the build \($0)" } ?? ""))
        }
        let fingerprint = ConfigStore.keyFingerprint(pem: key.pem) ?? "unreadable"
        switch key {
        case .first: print("Its config key, \(fingerprint), is now the one this Mac trusts. It should be the one shown when you signed.")
        case .replacement: print("The config key was replaced. This Mac now trusts \(fingerprint).")
        case .installed, .builtIn: break
        }
        print("It expires in \(config.daysRemaining(now: Date())) days. The server picks it up within a minute.")
    }

    // MARK: status

    static func status() -> Never {
        let now = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser
        let installed = Installation.modules(in: Installation.programs)
        print("Programs: \(Installation.programs.path)" + (installed.accepted.isEmpty ? " (no modules installed)" : ""))
        for module in installed.accepted { print("  installed module \(module.identifier), build \(module.cdhash.prefix(12))…") }
        for name in installed.refused { print("  \(name): not signed by this server's signer") }
        print("Transport key: " + (Installation.transportKey(home: home).flatMap(Wire.key(base64:)) != nil
                                    ? Installation.transportKeyFile(home: home).path : "none for this account"))
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
