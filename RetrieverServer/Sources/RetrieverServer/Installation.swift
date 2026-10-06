import Foundation
import RetrieverSourceKit

/// Where an installed Retriever lives.
///
/// Everything that decides what runs is owned by root: the programs, the
/// launchd files that start them, and the module config. Only the transport
/// key, which is one account's secret, is in that account's own folder.
enum Installation {
    static let root = ModuleConfigStore.installedFolder
    static let programs = root.appendingPathComponent("bin", isDirectory: true)
    static let launchAgents = URL(fileURLWithPath: "/Library/LaunchAgents", isDirectory: true)
    static let serverName = "RetrieverServer"
    static let modulePrefix = "RetrieverSource"
    static let moduleIdentifierPrefix = Signer.moduleIdentifierPrefix

    /// The key shared with the plugin: base64 of 32 bytes, readable only by its owner.
    static func transportKeyFile(home: URL) -> URL {
        home.appendingPathComponent("Library/Application Support/Retriever/transport.key")
    }

    /// Where launchd looks for the agent with this label.
    static func agentFile(_ label: String) -> URL { launchAgents.appendingPathComponent("\(label).plist") }

    /// The launchd file for the server: started at login and kept running,
    /// except in an account that has no transport key, where it exits cleanly.
    static func serverAgent(program: String) -> [String: Any] {
        ["Label": Signer.serverIdentifier,
         "ProgramArguments": [program],
         "RunAtLoad": true,
         "KeepAlive": ["SuccessfulExit": false],
         "LimitLoadToSessionType": "Aqua"]
    }

    /// The launchd file for a module: started when the server first asks for
    /// its service, whose name is the module's signing identifier.
    static func moduleAgent(identifier: String, program: String) -> [String: Any] {
        ["Label": identifier,
         "ProgramArguments": [program],
         "MachServices": [identifier: true],
         "LimitLoadToSessionType": "Aqua"]
    }

    /// Names in a folder that could be module programs: by name only, the signature decides.
    static func moduleCandidates(in names: [String]) -> [String] {
        names.filter { $0.hasPrefix(modulePrefix) && !$0.contains(".") }.sorted()
    }

    /// The modules in `directory` that are signed by this program's signer
    /// and carry a module identifier, and the candidates that are not.
    static func modules(in directory: URL, inspect: (String) throws -> Signer.Program = Signer.inspect)
        -> (accepted: [Signer.Program], refused: [String]) {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        var accepted: [Signer.Program] = []
        var refused: [String] = []
        for name in moduleCandidates(in: names) {
            let path = directory.appendingPathComponent(name).path
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue,
                  FileManager.default.isExecutableFile(atPath: path) else { continue }
            if let program = try? inspect(path), program.identifier.hasPrefix(moduleIdentifierPrefix) {
                accepted.append(program)
            } else {
                refused.append(name)
            }
        }
        return (accepted, refused)
    }

    /// Why a program was not installed.
    enum ProgramRefusal: Error, CustomStringConvertible, Equatable {
        case notSignedByThisSigner(String)
        case signedAs(String, expected: String)

        var description: String {
            switch self {
            case .notSignedByThisSigner(let name): return "\(name) is not signed by this server's signer"
            case .signedAs(let found, let expected): return "it is signed as \"\(found)\", not as \"\(expected)\""
            }
        }
    }

    /// Copies a program into `directory` and checks the copy before it
    /// replaces anything.
    ///
    /// The source is somewhere its owner can still write. So what is checked
    /// is the copy, already in the directory only root can change, and never
    /// the file it came from: a program swapped after an earlier look at it
    /// fails here. The copy is of the file's bytes, so a link is never
    /// installed as a link to somewhere else.
    /// - Parameters:
    ///   - identifier: the signing identifier the installed program must have.
    ///   - owner: who is to own it; nil leaves it the caller's, for tests.
    ///   - inspect: reads a program's signature, refusing any not signed by this program's signer.
    /// - Returns: the installed program's path.
    /// - Throws: `ProgramRefusal` if the copy does not check, leaving `directory` as it was; or a file error.
    static func installProgram(from source: String, into directory: URL, as name: String, expecting identifier: String,
                               owner: (uid: Int, gid: Int)? = (0, 0),
                               inspect: (String) throws -> Signer.Program = Signer.inspect) throws -> String {
        let files = FileManager.default
        let destination = directory.appendingPathComponent(name)
        let staged = directory.appendingPathComponent(".\(name).new")
        try? files.removeItem(at: staged)
        try Data(contentsOf: URL(fileURLWithPath: source)).write(to: staged)
        do {
            var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o755]
            if let owner {
                attributes[.ownerAccountID] = owner.uid
                attributes[.groupOwnerAccountID] = owner.gid
            }
            try files.setAttributes(attributes, ofItemAtPath: staged.path)
            guard let copy = try? inspect(staged.path) else { throw ProgramRefusal.notSignedByThisSigner(name) }
            guard copy.identifier == identifier else { throw ProgramRefusal.signedAs(copy.identifier, expected: identifier) }
            _ = try files.replaceItemAt(destination, withItemAt: staged)
        } catch {
            try? files.removeItem(at: staged)
            throw error
        }
        return destination.path
    }

    /// A new transport key: 32 random bytes, in base64.
    static func newTransportKey() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
    }

    /// The account's transport key as its file holds it, or nil if there is no file. Not checked for being a key.
    static func transportKey(home: URL) -> String? {
        (try? String(contentsOf: transportKeyFile(home: home), encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
