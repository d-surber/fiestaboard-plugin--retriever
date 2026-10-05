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
    typealias Problem = ConfigCommand.Problem

    static func run() -> Never {
        do { try install() } catch {
            print("\(error)")
            exit(1)
        }
        exit(0)
    }

    static func install() throws {
        let program = ConfigCommand.program
        guard getuid() == 0 else { throw Problem("Installing needs an administrator: sudo \"\(program)\" install") }
        guard let user = ProcessInfo.processInfo.environment["SUDO_USER"], let entry = getpwnam(user) else {
            throw Problem("Run this with sudo from your own account, so the agents can be started for you.")
        }
        let uid = entry.pointee.pw_uid, gid = entry.pointee.pw_gid
        let home = URL(fileURLWithPath: String(cString: entry.pointee.pw_dir), isDirectory: true)
        let files = FileManager.default

        // What is being installed: this server, and the modules beside it.
        let server: Signer.Program
        do { server = try Signer.inspect(program) } catch {
            throw Problem("Not installed: \(error). Sign the server and its modules with one identity first.")
        }
        guard server.identifier == Signer.serverIdentifier else {
            throw Problem("Not installed: this program is signed as \"\(server.identifier)\", not as the server.")
        }
        let here = URL(fileURLWithPath: program).resolvingSymlinksInPath().deletingLastPathComponent()
        let (modules, refused) = Installation.modules(in: here)
        for name in refused { print("Skipped \(name): not a module signed by this server's signer.") }

        // Programs.
        try files.createDirectory(at: Installation.programs, withIntermediateDirectories: true)
        for directory in [Installation.root, Installation.programs] {
            try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755], ofItemAtPath: directory.path)
        }
        func place(_ source: String, as name: String) throws -> String {
            let destination = Installation.programs.appendingPathComponent(name)
            guard URL(fileURLWithPath: source).resolvingSymlinksInPath().path != destination.path else { return destination.path }
            let staged = Installation.programs.appendingPathComponent(".\(name).new")
            try? files.removeItem(at: staged)
            try files.copyItem(atPath: source, toPath: staged.path)
            try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o755], ofItemAtPath: staged.path)
            _ = try files.replaceItemAt(destination, withItemAt: staged)
            return destination.path
        }
        let installedServer = try place(server.path, as: Installation.serverName)
        var installedModules: [(identifier: String, path: String)] = []
        for module in modules {
            installedModules.append((module.identifier, try place(module.path, as: URL(fileURLWithPath: module.path).lastPathComponent)))
        }

        // The transport key: kept, carried over from an earlier per-account install, or made.
        let keyFile = Installation.transportKeyFile(home: home)
        let oldAgents = home.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        var keyNote = "The transport key is unchanged."
        if Installation.transportKey(home: home) == nil {
            let old = NSDictionary(contentsOf: oldAgents.appendingPathComponent("\(Signer.serverIdentifier).plist"))
            let carried = (old?["EnvironmentVariables"] as? [String: String])?["RETRIEVER_KEY"]
            let key = carried ?? Installation.newTransportKey()
            try files.createDirectory(at: keyFile.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data((key + "\n").utf8).write(to: keyFile, options: .atomic)
            try files.setAttributes([.ownerAccountID: Int(uid), .groupOwnerAccountID: Int(gid), .posixPermissions: 0o600], ofItemAtPath: keyFile.path)
            try files.setAttributes([.ownerAccountID: Int(uid), .groupOwnerAccountID: Int(gid), .posixPermissions: 0o700],
                                    ofItemAtPath: keyFile.deletingLastPathComponent().path)
            keyNote = carried != nil ? "The transport key was carried over; the plugin's settings need no change."
                                     : "A new transport key was made. Enter it in the plugin's settings: \(key)"
        }

        // Agents from an earlier per-account install give way to the root-owned ones.
        let domain = "gui/\(uid)"
        for name in (try? files.contentsOfDirectory(atPath: oldAgents.path)) ?? []
        where name.hasPrefix("local.retriever-") && name.hasSuffix(".plist") {
            launchctl("bootout", "\(domain)/\(name.dropLast(".plist".count))")
            try? files.removeItem(at: oldAgents.appendingPathComponent(name))
        }

        func agent(_ label: String, _ contents: [String: Any]) throws {
            let file = Installation.agentFile(label)
            let data = try PropertyListSerialization.data(fromPropertyList: contents, format: .xml, options: 0)
            try data.write(to: file, options: .atomic)
            try files.setAttributes([.ownerAccountID: 0, .groupOwnerAccountID: 0, .posixPermissions: 0o644], ofItemAtPath: file.path)
            launchctl("bootout", "\(domain)/\(label)")
            guard launchctl("bootstrap", domain, file.path) == 0 else { throw Problem("Could not start \(label).") }
        }
        for module in installedModules {
            try agent(module.identifier, Installation.moduleAgent(identifier: module.identifier, program: module.path))
            print("Installed module \(module.identifier).")
        }
        try agent(Signer.serverIdentifier, Installation.serverAgent(program: installedServer))
        print("Installed the server. Programs are in \(Installation.programs.path).")
        print(keyNote)

        let verdict = ConfigStore.load(from: ConfigStore.installed, builtInKey: ConfigStore.builtInKey(), now: Date())
        if case .invalid(let reason) = verdict {
            print("No modules will be loaded yet: \(reason). As yourself, run:")
            print("  \"\(installedServer)\" config sign")
            print("then: sudo \"\(installedServer)\" config install")
        }
        print("For everything else: \"\(installedServer)\" help")
    }

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
