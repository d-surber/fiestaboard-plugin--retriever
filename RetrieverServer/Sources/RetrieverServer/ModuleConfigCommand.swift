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
enum ModuleConfigCommand {
    /// Runs one `config` command and exits: 0 if it did what was asked, 1
    /// with the reason printed if not.
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

    /// Why a command could not do what was asked, in words for the person who ran it.
    struct Problem: Error, CustomStringConvertible {
        let description: String
        init(_ description: String) { self.description = description }
    }

    // MARK: sign

    /// `--days N`, `--pin`, `--replace-key`, `--name NAME` and any number
    /// of `--set PARAMETER=VALUE`, and whatever else was given.
    struct Options: Equatable {
        var days = Int(ModuleConfig.defaultValidity / 86400)
        var pin = false
        var replaceKey = false
        /// The name to serve a source under, from `--name`.
        var sourceName: String?
        /// What the module is to be asked, from each `--set`.
        var parameters: SourceParameters = [:]
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
                case "--name":
                    guard let name = rest.popFirst() else { throw Problem("--name needs the name to serve the source under") }
                    sourceName = name
                case "--set":
                    guard let setting = rest.popFirst(), let equals = setting.firstIndex(of: "="), equals != setting.startIndex else {
                        throw Problem("--set needs a parameter and its value, as in: --set days_from_today=1")
                    }
                    parameters[String(setting[..<equals])] = ModuleConfigCommand.parameterValue(String(setting[setting.index(after: equals)...]))
                default:
                    names.append(argument)
                }
            }
        }
    }

    /// A parameter's value as typed on a command line: a whole number, a
    /// number, `true` or `false` if it reads as one, and otherwise text.
    /// Quotes around it make it text whatever it reads as.
    static func parameterValue(_ written: String) -> JSON {
        if written.count >= 2, written.hasPrefix("\""), written.hasSuffix("\"") { return .string(String(written.dropFirst().dropLast())) }
        if written == "true" { return .bool(true) }
        if written == "false" { return .bool(false) }
        if let whole = Int(written) { return .int(whole) }
        if let number = Double(written), number.isFinite { return .double(number) }
        return .string(written)
    }

    static var installedConfig: ModuleConfig? {
        (try? Data(contentsOf: ModuleConfigStore.installedFolder.appendingPathComponent(ModuleConfigStore.configFile))).flatMap(ModuleConfig.decode)
    }

    /// The list a change starts from: the one signed and waiting to be
    /// installed, if there is one, and otherwise the installed one. So
    /// several changes can be made one after another and installed together.
    static var listToChange: [ModuleConfig.Module] {
        let pendingFolder = ModuleConfigStore.pendingFolder(home: FileManager.default.homeDirectoryForCurrentUser)
        let waiting = (try? Data(contentsOf: pendingFolder.appendingPathComponent(ModuleConfigStore.configFile))).flatMap(ModuleConfig.decode)
        return (waiting ?? installedConfig)?.modules ?? []
    }

    /// The list after allowing `added`: each replaces any entry for a source of the same name.
    static func allowing(_ added: [ModuleConfig.Module], in modules: [ModuleConfig.Module]) -> [ModuleConfig.Module] {
        modules.filter { existing in !added.contains { $0.sourceName == existing.sourceName } } + added
    }

    /// config sign: sign the current list again, or, with no config yet,
    /// a list of every installed module. Naming modules replaces the list.
    static func sign(_ arguments: [String]) throws {
        let options = try Options(arguments)
        var modules = options.names.map { ModuleConfig.Module(identifier: $0) }
        if let problem = ModuleConfigStore.problem(withModules: modules) { throw Problem("Not signed: \(problem).") }
        if modules.isEmpty { modules = listToChange }
        if modules.isEmpty {
            modules = Installation.modules(in: Installation.programs).accepted.map { ModuleConfig.Module(identifier: $0.identifier) }
        }
        guard !modules.isEmpty else { throw Problem("There are no installed modules to allow. Install first: sudo \"\(program)\" install") }
        try signAndStage(modules, days: options.days)
    }

    /// config add: allow a source, naming its module by its program's path
    /// or its identifier; with `--name` and `--set`, under a name of its own
    /// and with something to ask the module.
    static func add(_ arguments: [String]) throws {
        let options = try Options(arguments)
        guard !options.names.isEmpty else { throw Problem("Name the module to allow: its program, or its identifier.") }
        guard options.names.count == 1 || (options.sourceName == nil && options.parameters.isEmpty) else {
            throw Problem("--name and --set say how one module is to be listed; name one module at a time with them.")
        }
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
            let entry = ModuleConfig.Module(identifier: module.identifier, cdhash: options.pin ? module.cdhash : nil,
                                            name: options.sourceName, parameters: options.parameters.isEmpty ? nil : options.parameters)
            if let problem = ModuleConfigStore.problem(with: entry) { throw Problem("Not added: \(problem).") }
            try askModuleAboutParameters(of: entry)
            added.append(entry)
        }
        try signAndStage(allowing(added, in: listToChange), days: options.days)
    }

    /// Puts an entry's parameters to its module before the entry is signed,
    /// so that a mistake is caught while the person who made it is there.
    /// The server asks again when it starts; that is the check that counts,
    /// and a module that cannot be asked now is left to it.
    /// - Throws: `Problem` if the module answers that it will not take them.
    static func askModuleAboutParameters(of entry: ModuleConfig.Module) throws {
        guard let parameters = entry.parameters else { return }
        guard let source = try? RemoteSource(serviceName: entry.identifier, cdhash: entry.cdhash, name: entry.name, parameters: parameters) else {
            print("\(entry.identifier) is not running here to be asked about its parameters; the server will ask it when it starts.")
            return
        }
        if let problem = source.parameterProblem { throw Problem("Not added: the source \"\(entry.sourceName)\" \(problem).") }
    }

    /// config remove: stop allowing a source, named by its own name, or
    /// every source of a module, named by the module's identifier.
    static func remove(_ arguments: [String]) throws {
        let options = try Options(arguments)
        let current = listToChange
        let remaining = current.filter { !options.names.contains($0.sourceName) && !options.names.contains($0.identifier) }
        guard remaining.count < current.count else { throw Problem("Nothing removed: the config allows none of those.") }
        try signAndStage(remaining, days: options.days)
    }

    /// Shows what a config would allow, signs it, and leaves it waiting to be installed.
    static func signAndStage(_ modules: [ModuleConfig.Module], days: Int) throws {
        guard getuid() != 0 else { throw Problem("Sign as yourself, not with sudo: the config key answers to your Touch ID or password.") }
        let pending = ModuleConfigStore.pendingFolder(home: FileManager.default.homeDirectoryForCurrentUser)
        try FileManager.default.createDirectory(at: pending, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let config = ModuleConfig(version: (installedConfig?.version ?? 0) + 1,
                                  expires: Date().addingTimeInterval(TimeInterval(days) * 86400),
                                  modules: modules)
        let bytes = config.encoded()

        print("Module config version \(config.version), valid for \(days) days, will allow:")
        printModules(modules)

        if let problem = ModuleConfigStore.problem(withModules: modules) { throw Problem("Not signed: \(problem).") }
        let (key, blob, created) = try signingKey(pendingFolder: pending)
        if created { print("Created a config key in this Mac's Secure Enclave.") }
        print("SourceConfig key: \(ModuleConfigStore.keyFingerprint(pem: key.publicKey.pemRepresentation) ?? "unreadable")")
        print("Signing: approve with Touch ID or your password.")
        let signature = try key.signature(for: bytes)

        try bytes.write(to: pending.appendingPathComponent(ModuleConfigStore.configFile))
        try signature.derRepresentation.write(to: pending.appendingPathComponent(ModuleConfigStore.signatureFile))
        try Data(key.publicKey.pemRepresentation.utf8).write(to: pending.appendingPathComponent(ModuleConfigStore.publicKeyFile))
        try blob.write(to: pending.appendingPathComponent(ModuleConfigStore.keyBlobFile))

        print("Signed. It is waiting in \(pending.path).")
        print("Install it with: sudo \"\(program)\" config install")
    }

    /// The Secure Enclave key configs are signed with on this Mac: the one
    /// already in use, or a new one. What is stored is a blob only this
    /// Mac's enclave can use, and only with the user present.
    static func signingKey(pendingFolder pending: URL) throws -> (SecureEnclave.P256.Signing.PrivateKey, Data, created: Bool) {
        guard SecureEnclave.isAvailable else {
            throw Problem("This Mac has no Secure Enclave. Sign the config elsewhere with openssl (see the comment in ModuleConfigCommand.swift).")
        }
        let context = LAContext()
        context.localizedReason = "sign the Retriever module config"
        for directory in [ModuleConfigStore.installedFolder, pending] {
            if let blob = try? Data(contentsOf: directory.appendingPathComponent(ModuleConfigStore.keyBlobFile)),
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
        let pendingFolder = ModuleConfigStore.pendingFolder(home: account.home)

        // Each waiting file is read once, with the account's own access, and
        // what is checked is what is installed.
        let waiting = try account.withItsAccess { waitingFiles(in: pendingFolder) }
        let key = try keyToTrust(for: waiting, replacingKey: options.replaceKey, lookedIn: pendingFolder)
        let verdict = ModuleConfigStore.verify(config: waiting[ModuleConfigStore.configFile], signature: waiting[ModuleConfigStore.signatureFile],
                                               publicKeyPEM: key.pem, now: Date())
        guard case .valid(let config) = verdict else {
            if case .invalid(let reason) = verdict { throw Problem("Not installed: \(reason) (looked in \(pendingFolder.path)).") }
            throw Problem("Not installed.")
        }

        // The key and its enclave blob go in only when the key is new here.
        var installing = [ModuleConfigStore.configFile, ModuleConfigStore.signatureFile]
        if key.isInstalledWithTheConfig { installing += [ModuleConfigStore.publicKeyFile, ModuleConfigStore.keyBlobFile] }
        try writeRootOwned(waiting.filter { installing.contains($0.key) }, into: ModuleConfigStore.installedFolder)
        try account.withItsAccess {
            for name in waiting.keys { try? FileManager.default.removeItem(at: pendingFolder.appendingPathComponent(name)) }
        }
        report(installed: config, trusting: key)
    }

    /// The contents of each of the module config's files that is waiting in `folder`, by file name.
    static func waitingFiles(in folder: URL) -> [String: Data] {
        Dictionary(uniqueKeysWithValues: ModuleConfigStore.fileNames.compactMap { name in
            (try? Data(contentsOf: folder.appendingPathComponent(name))).map { (name, $0) }
        })
    }

    /// Chooses the key the waiting config must verify against, by the rule in `ModuleConfigStore.keyToTrust`.
    /// - Throws: `Problem`, saying what to do, if there is no key or the
    ///   waiting key is not the installed one and was not asked for.
    static func keyToTrust(for waiting: [String: Data], replacingKey: Bool, lookedIn pendingFolder: URL) throws -> ModuleConfigStore.KeyToTrust {
        let waitingKey = waiting[ModuleConfigStore.publicKeyFile].map { String(decoding: $0, as: UTF8.self) }
        let installedKeyFile = ModuleConfigStore.installedFolder.appendingPathComponent(ModuleConfigStore.publicKeyFile)
        let installedKey = try? String(contentsOf: installedKeyFile, encoding: .utf8)
        do {
            return try ModuleConfigStore.keyToTrust(builtIn: ModuleConfigStore.builtInKey(), installed: installedKey, waiting: waitingKey,
                                                    replacingKey: replacingKey)
        } catch ModuleConfigStore.KeyRefusal.differentKey {
            throw Problem("""
                Not installed: the waiting config comes with config key \(waitingKey.flatMap(ModuleConfigStore.keyFingerprint) ?? "unreadable"),
                which is not the installed one, \(installedKey.flatMap(ModuleConfigStore.keyFingerprint) ?? "unreadable").
                If you mean to change the config key: sudo "\(program)" config install --replace-key
                """)
        } catch {
            throw Problem("Not installed: no config key (looked in \(pendingFolder.path)).")
        }
    }

    /// Writes files into `folder`, each owned by root and readable by all, as is the folder.
    static func writeRootOwned(_ contents: [String: Data], into folder: URL) throws {
        let files = FileManager.default
        try files.createDirectory(at: folder, withIntermediateDirectories: true)
        try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755], ofItemAtPath: folder.path)
        for (name, data) in contents {
            let destination = folder.appendingPathComponent(name)
            try data.write(to: destination, options: .atomic)
            try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o644], ofItemAtPath: destination.path)
        }
    }

    /// Tells the administrator what was installed: the modules allowed, and
    /// the config key if it is new to this Mac.
    static func report(installed config: ModuleConfig, trusting key: ModuleConfigStore.KeyToTrust) {
        print("Installed module config version \(config.version) in \(ModuleConfigStore.installedFolder.path). It allows:")
        printModules(config.modules)
        let fingerprint = ModuleConfigStore.keyFingerprint(pem: key.pem) ?? "unreadable"
        switch key {
        case .first: print("Its config key, \(fingerprint), is now the one this Mac trusts. It should be the one shown when you signed.")
        case .replacement: print("The config key was replaced. This Mac now trusts \(fingerprint).")
        case .installed, .builtIn: break
        }
        print("It expires in \(config.daysRemaining(now: Date())) days. The server picks it up within a minute.")
    }

    /// Lists the sources a config allows, one to a line: its name, its
    /// module, the build it is pinned to if it is, and what the module is asked.
    static func printModules(_ modules: [ModuleConfig.Module]) {
        if modules.isEmpty { print("  no modules") }
        for module in modules {
            print("  \(module.sourceName): \(module.identifier)" + (module.cdhash.map { ", only the build \($0)" } ?? "") + asked(of: module))
        }
    }

    /// What an entry asks of its module, for a person to read; "" if nothing.
    static func asked(of module: ModuleConfig.Module) -> String {
        guard let parameters = module.parameters, !parameters.isEmpty else { return "" }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        let settings = parameters.sorted { $0.key < $1.key }.map { name, value in
            "\(name)=" + ((try? encoder.encode(value)).map { String(decoding: $0, as: UTF8.self) } ?? "?")
        }
        return ", asked " + settings.joined(separator: " ")
    }

    // MARK: status

    /// status: what is installed, which keys are in use, whether the module
    /// config is valid, and whether each module it allows can be reached.
    static func status() -> Never {
        let now = Date()
        let home = FileManager.default.homeDirectoryForCurrentUser
        let installed = Installation.modules(in: Installation.programs)
        print("Programs: \(Installation.programs.path)" + (installed.accepted.isEmpty ? " (no modules installed)" : ""))
        for module in installed.accepted {
            print("  installed module \(module.identifier), build \(module.cdhash.prefix(12))…")
            for line in parametersTaken(by: module.identifier) { print("      \(line)") }
        }
        for name in installed.refused { print("  \(name): not signed by this server's signer") }

        let hasTransportKey = Installation.transportKey(home: home).flatMap(Wire.transportKey(base64:)) != nil
        print("Transport key: " + (hasTransportKey ? Installation.transportKeyFile(home: home).path : "none for this account"))
        let builtInKey = ModuleConfigStore.builtInKey()
        print("Config key: " + (ModuleConfigStore.trustedKey(in: ModuleConfigStore.installedFolder, builtIn: builtInKey)?.origin ?? "none"))

        let verdict = ModuleConfigStore.load(from: ModuleConfigStore.installedFolder, builtInKey: builtInKey, now: now)
        switch verdict {
        case .invalid(let reason):
            print("Module config: \(reason). No modules are loaded.")
        case .valid(let config):
            let warning = config.warning(now: now)
            print("Module config: valid, version \(config.version), expires in \(config.daysRemaining(now: now)) days" + (warning.isEmpty ? "" : " (\(warning))"))
        }
        for module in verdict.modules { print(reachability(of: module)) }
        exit(0)
    }

    /// What to tell a person about the parameters an installed module
    /// takes: a line for each, or one saying it could not be asked. Nothing
    /// for a module that takes none.
    static func parametersTaken(by identifier: String) -> [String] {
        guard let source = try? RemoteSource(serviceName: identifier) else { return ["could not be asked what parameters it takes"] }
        return ParametersSchema.summary(of: source.parametersSchema).map { "takes \($0)" }
    }

    /// One line saying whether a module can be reached and, if so, what its source reports now.
    static func reachability(of module: ModuleConfig.Module) -> String {
        let pin = module.cdhash.map { ", pinned to build \($0.prefix(12))…" } ?? ""
        let listed = "\(module.sourceName) (\(module.identifier)\(pin)\(asked(of: module)))"
        let source: RemoteSource
        do {
            source = try RemoteSource(serviceName: module.identifier, cdhash: module.cdhash, name: module.name, parameters: module.parameters ?? [:])
        } catch {
            return "\(listed): \(error)"
        }
        var line = ""
        let answered = DispatchSemaphore(value: 0)
        source.fetch(parameters: [:]) { entry in
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let data = (try? encoder.encode(entry.data)).map { String(decoding: $0, as: UTF8.self) } ?? "?"
            line = "\(listed): ok; error \"\(entry.error)\"; data \(data)"
            answered.signal()
        }
        answered.wait()   // a module answers or is given up on within RemoteSource.answerTimeout
        return line
    }
}
