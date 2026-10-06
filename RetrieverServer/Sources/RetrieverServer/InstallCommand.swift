import Foundation
import RetrieverSourceKit

// sudo RetrieverServer install
//
// Installs the server and the source modules found beside it, from wherever
// that is: a build folder, a download, a disk image. It signs nothing. Every
// program must already carry the signer of the server being run, and one
// that does not is refused. The programs and their launchd files go to
// root-owned locations, so replacing any of them needs an administrator.
enum InstallCommand {
    typealias Problem = ModuleConfigCommand.Problem

    /// Runs `install` and exits: 0 if everything was installed, 1 with the reason printed if not.
    static func run() -> Never {
        do { try install() } catch {
            print("\(error)")
            exit(1)
        }
        exit(0)
    }

    /// Installs the programs, sees that the account has a transport key, and
    /// starts the agents in the invoking account's session.
    /// - Throws: `Problem` if not run by an administrator through sudo, if the
    ///   server's own copy does not check, or if an agent cannot be started.
    static func install() throws {
        let program = ModuleConfigCommand.program
        guard getuid() == 0 else { throw Problem("Installing needs an administrator: sudo \"\(program)\" install") }
        guard let account = InvokingAccount.fromSudo() else {
            throw Problem("Run this with sudo from your own account, so the agents can be started for you.")
        }

        let installedServer = try installPrograms(besideServerAt: program)
        let keyNote = try account.withItsAccess { try ensureTransportKey(home: account.home) }
        let domain = "gui/\(account.uid)"

        for module in installedServer.modules {
            try startAgent(module.identifier, Installation.moduleAgent(identifier: module.identifier, program: module.path), in: domain)
            print("Installed module \(module.identifier).")
        }
        try startAgent(Signer.serverIdentifier, Installation.serverAgent(program: installedServer.path), in: domain)
        print("Installed the server. Programs are in \(Installation.programs.path).")
        print(keyNote)

        let verdict = ModuleConfigStore.load(from: ModuleConfigStore.installedFolder, builtInKey: ModuleConfigStore.builtInKey(), now: Date())
        if case .invalid(let reason) = verdict {
            print("No modules will be loaded yet: \(reason). As yourself, run:")
            print("  \"\(installedServer.path)\" config sign")
            print("then: sudo \"\(installedServer.path)\" config install")
        }
        print("For everything else: \"\(installedServer.path)\" help")
    }

    /// Copies this server, and the modules in the folder it was run from,
    /// into the root-owned programs folder. Each is checked there, after it
    /// is copied; a module that does not check is skipped and said so, and a
    /// server that does not check stops the install.
    /// - Returns: where the server now is, and each module with its identifier.
    static func installPrograms(besideServerAt program: String) throws -> (path: String, modules: [(identifier: String, path: String)]) {
        let files = FileManager.default
        try files.createDirectory(at: Installation.programs, withIntermediateDirectories: true)
        for directory in [Installation.root, Installation.programs] {
            try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755], ofItemAtPath: directory.path)
        }

        let installedServer: String
        do {
            installedServer = try Installation.installProgram(from: program, into: Installation.programs, as: Installation.serverName,
                                                              expecting: Signer.serverIdentifier)
        } catch let refusal as Installation.ProgramRefusal {
            throw Problem("Not installed: \(refusal). Sign the server and its modules with one identity first.")
        }

        // The folder is only a place to look: what counts is the check each
        // copy gets once it is where the folder's owner cannot reach it.
        let here = URL(fileURLWithPath: program).resolvingSymlinksInPath().deletingLastPathComponent()
        let (candidates, refused) = Installation.modules(in: here)
        for name in refused { print("Skipped \(name): not a module signed by this server's signer.") }
        var installedModules: [(identifier: String, path: String)] = []
        for candidate in candidates {
            let name = URL(fileURLWithPath: candidate.path).lastPathComponent
            do {
                let path = try Installation.installProgram(from: candidate.path, into: Installation.programs, as: name,
                                                           expecting: candidate.identifier)
                installedModules.append((candidate.identifier, path))
            } catch let refusal as Installation.ProgramRefusal {
                print("Skipped \(name): \(refusal).")
            }
        }
        return (installedServer, installedModules)
    }

    /// Makes sure the account has a transport key, making one if it has none.
    /// Run with the account's own access, since it is all in the account's folder.
    /// - Returns: what to tell the user about the key.
    static func ensureTransportKey(home: URL) throws -> String {
        guard Installation.transportKey(home: home) == nil else { return "The transport key is unchanged." }
        let files = FileManager.default
        let keyFile = Installation.transportKeyFile(home: home)
        let key = Installation.newTransportKey()
        try files.createDirectory(at: keyFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        try files.setAttributes([.posixPermissions: 0o700], ofItemAtPath: keyFile.deletingLastPathComponent().path)
        try Data((key + "\n").utf8).write(to: keyFile, options: .atomic)
        try files.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)
        return "A new transport key was made. Enter it in the plugin's settings: \(key)"
    }

    /// Writes an agent's launchd file, root-owned, and starts the agent in `domain`.
    static func startAgent(_ label: String, _ contents: [String: Any], in domain: String) throws {
        let file = Installation.agentFile(label)
        let data = try PropertyListSerialization.data(fromPropertyList: contents, format: .xml, options: 0)
        try data.write(to: file, options: .atomic)
        try FileManager.default.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o644], ofItemAtPath: file.path)
        launchctl("bootout", "\(domain)/\(label)")
        guard launchctl("bootstrap", domain, file.path) == 0 else { throw Problem("Could not start \(label).") }
    }

    /// Runs launchctl with these arguments, quietly.
    /// - Returns: its exit status, or -1 if it could not be run.
    @discardableResult
    static func launchctl(_ arguments: String...) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return -1 }
        process.waitUntilExit()
        return process.terminationStatus
    }
}
