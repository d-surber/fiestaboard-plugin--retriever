import Foundation
import RetrieverSourceKit

/// A source that lives in a module: a separate program, reached over XPC.
///
/// The server only talks to a module that is signed by the server's own
/// signer and carries the identifier of the serviceName it was asked for. The
/// module, for its part, only answers the server. A module that fails the
/// check is not connected to, and so cannot serve anything.
final class RemoteSource: Source {
    let serviceName: String
    let cdhash: String?
    let name: String
    let schema: JSON

    /// Makes a connection to a serviceName, optionally pinned to one build. Replaced in tests.
    typealias Connect = (_ serviceName: String, _ cdhash: String?) throws -> NSXPCConnection

    private let connect: Connect

    /// A connection to the module registered as `serviceName`, held to the signature requirement.
    static let signedConnection: Connect = { serviceName, cdhash in
        let connection = NSXPCConnection(machServiceName: serviceName)
        connection.setCodeSigningRequirement(try Signer.requirement(identifier: serviceName, cdhash: cdhash))
        return connection
    }

    /// Why a module gave no answer, or gave one that cannot be used.
    enum Failure: Error, CustomStringConvertible {
        case unavailable(String)   // not installed, or refused for its signature
        case wrongName(String)

        var description: String {
            switch self {
            case .unavailable(let reason): return "unavailable or refused (\(reason))"
            case .wrongName(let name): return "describes itself as \"\(name)\", which is not the source this serviceName is for"
            }
        }
    }

    /// How long a module has to answer one question. A retrieve gives every
    /// source the same, so a module that says nothing is reported by
    /// whichever of the two notices first.
    static let answerTimeout: TimeInterval = 3

    /// Asks the module what it is. Blocks for up to `timeout`.
    /// - Throws: `Failure` if it cannot be reached, is refused for its
    ///   signature, or describes itself as some other source.
    init(serviceName: String, cdhash: String? = nil, timeout: TimeInterval = RemoteSource.answerTimeout,
         connect: @escaping Connect = RemoteSource.signedConnection) throws {
        self.serviceName = serviceName
        self.cdhash = cdhash
        self.connect = connect
        let answer = Self.ask(serviceName, cdhash, connect, timeout: timeout) { $0.describe(reply: $1) }
        guard case .success(let data) = answer, let description = try? JSONDecoder().decode(SourceDescription.self, from: data) else {
            if case .failure(let failure) = answer { throw failure }
            throw Failure.unavailable("its description could not be read")
        }
        guard Signer.moduleIdentifier(for: description.name) == serviceName else { throw Failure.wrongName(description.name) }
        name = description.name
        schema = description.schema
    }

    func fetch(_ done: @escaping (Entry) -> Void) {
        DispatchQueue.global().async {
            switch Self.ask(self.serviceName, self.cdhash, self.connect, timeout: Self.answerTimeout, { $0.fetch(reply: $1) }) {
            case .success(let data):
                done((try? JSONDecoder().decode(Entry.self, from: data)) ?? self.failed("module's answer could not be read"))
            case .failure(let failure):
                log("\(self.serviceName): \(failure)")
                done(self.failed("module unavailable"))
            }
        }
    }

    /// One question to a module on a connection of its own. Returns the
    /// answer, or why there was none.
    private static func ask(_ serviceName: String, _ cdhash: String?, _ connect: Connect, timeout: TimeInterval,
                             _ ask: (SourceService, @escaping (Data) -> Void) -> Void) -> Result<Data, Failure> {
        let connection: NSXPCConnection
        do { connection = try connect(serviceName, cdhash) } catch { return .failure(.unavailable("\(error)")) }
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
        guard let module = proxy as? SourceService else { return .failure(.unavailable("no serviceName interface")) }
        ask(module) { finish(.success($0)) }
        if answered.wait(timeout: .now() + timeout) == .timedOut { finish(.failure(.unavailable("no answer in \(timeout) s"))) }
        lock.lock()
        defer { lock.unlock() }
        return result ?? .failure(.unavailable("no answer"))
    }
}
