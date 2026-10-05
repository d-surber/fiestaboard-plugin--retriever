import Foundation

/// What the server asks a source module, over XPC. Both answers are JSON, so
/// the interface is the same for every source.
@objc public protocol SourceService {
    /// A `SourceDescription`.
    func describe(reply: @escaping (Data) -> Void)
    /// An `Entry`.
    func fetch(reply: @escaping (Data) -> Void)
}

public struct SourceDescription: Codable, Equatable {
    public let name: String
    public let schema: JSON

    public init(name: String, schema: JSON) {
        self.name = name
        self.schema = schema
    }
}

/// Runs a source as a module: a program that serves the one source to the
/// server over XPC, and to nobody else.
public enum SourceHost {
    /// Serves `source` under the service name for its name, and never
    /// returns. launchd must have that name registered for this program.
    public static func run(_ source: Source) -> Never {
        setvbuf(stdout, nil, _IOLBF, 0)
        let service = Signer.moduleIdentifier(for: source.name)
        // `<module> --service` prints the service name, for the installer.
        if CommandLine.arguments.dropFirst().first == "--service" {
            print(service)
            exit(0)
        }
        logToUserFile()
        let listener = NSXPCListener(machServiceName: service)
        do {
            // Only the server, signed by the signer of this module, may connect.
            listener.setConnectionCodeSigningRequirement(try Signer.requirement(identifier: Signer.serverIdentifier))
        } catch {
            log("\(service): \(error); serving nobody")
            exit(1)
        }
        let delegate = Delegate(Exported(source))
        listener.delegate = delegate
        listener.resume()
        log("\(service): ready")
        withExtendedLifetime(delegate) { RunLoop.main.run() }
        exit(0)
    }

    /// The source, as the XPC service the server calls.
    final class Exported: NSObject, SourceService {
        let source: Source

        init(_ source: Source) { self.source = source }

        func describe(reply: @escaping (Data) -> Void) {
            reply((try? JSONEncoder().encode(SourceDescription(name: source.name, schema: source.schema))) ?? Data())
        }

        func fetch(reply: @escaping (Data) -> Void) {
            source.fetch { entry in reply((try? JSONEncoder().encode(entry)) ?? Data()) }
        }
    }

    final class Delegate: NSObject, NSXPCListenerDelegate {
        let exported: Exported

        init(_ exported: Exported) { self.exported = exported }

        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: SourceService.self)
            connection.exportedObject = exported
            connection.resume()
            return true
        }
    }
}
