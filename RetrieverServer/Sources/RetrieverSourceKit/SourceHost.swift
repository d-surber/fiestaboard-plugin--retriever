import Foundation

/// What the server asks a source module, over XPC. Questions and answers are
/// JSON, so the interface is the same for every source.
@objc public protocol SourceService {
    /// A `SourceDescription`.
    func describe(reply: @escaping (Data) -> Void)
    /// What is wrong with these `SourceParameters`, in words; "" if the source can be asked with them.
    func problem(withParameters parameters: Data, reply: @escaping (String) -> Void)
    /// An `Entry`, asked for with these `SourceParameters`.
    func fetch(parameters: Data, reply: @escaping (Data) -> Void)
}

/// What a module says it is: the name of its source, the shape of its data,
/// and the parameters it takes.
public struct SourceDescription: Codable, Equatable {
    public let name: String
    public let schema: JSON
    public let parametersSchema: JSON

    public init(name: String, schema: JSON, parametersSchema: JSON) {
        self.name = name
        self.schema = schema
        self.parametersSchema = parametersSchema
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
        let delegate = ConnectionAcceptor(ExportedSource(source))
        listener.delegate = delegate
        listener.resume()
        log(.verbose, "\(service): ready")
        withExtendedLifetime(delegate) { RunLoop.main.run() }
        exit(0)
    }

    /// The source, as the XPC service the server calls.
    final class ExportedSource: NSObject, SourceService {
        let source: Source

        init(_ source: Source) { self.source = source }

        func describe(reply: @escaping (Data) -> Void) {
            let description = SourceDescription(name: source.name, schema: source.schema, parametersSchema: source.parametersSchema)
            reply((try? JSONEncoder().encode(description)) ?? Data())
        }

        func problem(withParameters parameters: Data, reply: @escaping (String) -> Void) {
            guard let parameters = try? JSONDecoder().decode(SourceParameters.self, from: parameters) else {
                return reply("its parameters could not be read")
            }
            reply(source.problem(with: parameters) ?? "")
        }

        func fetch(parameters: Data, reply: @escaping (Data) -> Void) {
            guard let parameters = try? JSONDecoder().decode(SourceParameters.self, from: parameters) else {
                return reply((try? JSONEncoder().encode(source.failed("its parameters could not be read"))) ?? Data())
            }
            source.fetch(parameters: parameters) { entry in reply((try? JSONEncoder().encode(entry)) ?? Data()) }
        }
    }

    /// Hands the source to each connection the listener lets through; the listener's signing requirement has already decided who that may be.
    final class ConnectionAcceptor: NSObject, NSXPCListenerDelegate {
        let exported: ExportedSource

        init(_ exported: ExportedSource) { self.exported = exported }

        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: SourceService.self)
            connection.exportedObject = exported
            connection.resume()
            return true
        }
    }
}
