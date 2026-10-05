import Foundation
import RetrieverSourceKit

/// A source that lives in a module: a separate program, reached over XPC.
///
/// The server only talks to a module that is signed by the server's own
/// signer and carries the identifier of the service it was asked for. The
/// module, for its part, only answers the server. A module that fails the
/// check is not connected to, and so cannot serve anything.
final class RemoteSource: Source {
    let service: String
    let cdhash: String?
    let name: String
    let schema: JSON

    /// Makes a connection to a service, optionally pinned to one build. Replaced in tests.
    typealias Connect = (_ service: String, _ cdhash: String?) throws -> NSXPCConnection

    private let connect: Connect

    /// A connection to the module registered as `service`, held to the signature requirement.
    static let signedConnection: Connect = { service, cdhash in
        let connection = NSXPCConnection(machServiceName: service)
        connection.setCodeSigningRequirement(try Signer.requirement(identifier: service, cdhash: cdhash))
        return connection
    }

    enum Failure: Error, CustomStringConvertible {
        case unavailable(String)   // not installed, or refused for its signature
        case wrongName(String)

        var description: String {
            switch self {
            case .unavailable(let reason): return "unavailable or refused (\(reason))"
            case .wrongName(let name): return "describes itself as \"\(name)\", which is not the source this service is for"
            }
        }
    }

    /// Asks the module what it is. Blocks for up to `timeout`.
    init(service: String, cdhash: String? = nil, timeout: TimeInterval = 3,
         connect: @escaping Connect = RemoteSource.signedConnection) throws {
        self.service = service
        self.cdhash = cdhash
        self.connect = connect
        let answer = Self.call(service, cdhash, connect, timeout: timeout) { $0.describe(reply: $1) }
        guard case .success(let data) = answer, let description = try? JSONDecoder().decode(SourceDescription.self, from: data) else {
            if case .failure(let failure) = answer { throw failure }
            throw Failure.unavailable("its description could not be read")
        }
        guard Signer.moduleIdentifier(for: description.name) == service else { throw Failure.wrongName(description.name) }
        name = description.name
        schema = description.schema
    }

    func fetch(_ done: @escaping (Entry) -> Void) {
        DispatchQueue.global().async {
            switch Self.call(self.service, self.cdhash, self.connect, timeout: 3, { $0.fetch(reply: $1) }) {
            case .success(let data):
                done((try? JSONDecoder().decode(Entry.self, from: data)) ?? self.failed("module's answer could not be read"))
            case .failure(let failure):
                log("\(self.service): \(failure)")
                done(self.failed("module unavailable"))
            }
        }
    }

    /// One question to a module on a connection of its own. Returns the
    /// answer, or why there was none.
    private static func call(_ service: String, _ cdhash: String?, _ connect: Connect, timeout: TimeInterval,
                             _ ask: (SourceService, @escaping (Data) -> Void) -> Void) -> Result<Data, Failure> {
        let connection: NSXPCConnection
        do { connection = try connect(service, cdhash) } catch { return .failure(.unavailable("\(error)")) }
        connection.remoteObjectInterface = NSXPCInterface(with: SourceService.self)
        connection.resume()
        defer { connection.invalidate() }

        let lock = NSLock()
        let answered = DispatchSemaphore(value: 0)
        var result: Result<Data, Failure>?
        func finish(_ value: Result<Data, Failure>) {
            lock.lock()
            defer { lock.unlock() }
            guard result == nil else { return }
            result = value
            answered.signal()
        }
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            finish(.failure(.unavailable((error as NSError).localizedDescription)))
        }
        guard let module = proxy as? SourceService else { return .failure(.unavailable("no service interface")) }
        ask(module) { finish(.success($0)) }
        if answered.wait(timeout: .now() + timeout) == .timedOut { finish(.failure(.unavailable("no answer in \(timeout) s"))) }
        lock.lock()
        defer { lock.unlock() }
        return result ?? .failure(.unavailable("no answer"))
    }
}
