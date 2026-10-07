import Foundation
import RetrieverSourceKit

/// A source served by a module: a separate program, reached over XPC, asked
/// what one entry of the module config says to ask it.
///
/// The server only talks to a module that is signed by the server's own
/// signer and carries the identifier of the service it was asked for. The
/// module, for its part, only answers the server. A module that fails the
/// check is not connected to, and so cannot serve anything.
///
/// One module may be several sources: each entry that lists it has its own
/// name and its own parameters, and is its own `RemoteSource`.
final class RemoteSource: Source {
    let serviceName: String
    let cdhash: String?
    /// The name the source is served under: the entry's, or failing that the module's own.
    let name: String
    let schema: JSON
    let parametersSchema: JSON
    /// What the entry asks of the module on every fetch.
    let parameters: SourceParameters
    /// What the module found wrong with `parameters`, if anything. While
    /// there is something, the module is not asked for data: the source
    /// reports this instead, so that the mistake shows wherever the source does.
    let parameterProblem: String?

    /// Makes a connection to a service, optionally pinned to one build. Replaced in tests.
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
            case .wrongName(let name): return "describes itself as \"\(name)\", which is not the source this service is for"
            }
        }
    }

    /// How long a module has to answer one question. A retrieve gives every
    /// source the same, so a module that says nothing is reported by
    /// whichever of the two notices first.
    static let answerTimeout: TimeInterval = 3

    /// Asks the module what it is and whether it can be asked with these
    /// parameters. Blocks for up to twice `timeout`.
    /// - Parameters:
    ///   - name: the name to serve the source under; nil for the module's own.
    ///   - parameters: what to ask the module on every fetch.
    /// - Throws: `Failure` if the module cannot be reached, is refused for
    ///   its signature, or describes itself as some other module's source.
    ///   Parameters it does not accept are not a failure to reach it: see `parameterProblem`.
    init(serviceName: String, cdhash: String? = nil, name: String? = nil, parameters: SourceParameters = [:],
         timeout: TimeInterval = RemoteSource.answerTimeout, connect: @escaping Connect = RemoteSource.signedConnection) throws {
        self.serviceName = serviceName
        self.cdhash = cdhash
        self.parameters = parameters
        self.connect = connect

        let described: Result<Data, Failure> = Self.ask(serviceName, cdhash, connect, timeout: timeout) { $0.describe(reply: $1) }
        guard case .success(let data) = described, let description = try? JSONDecoder().decode(SourceDescription.self, from: data) else {
            if case .failure(let failure) = described { throw failure }
            throw Failure.unavailable("its description could not be read")
        }
        // A module answers only for the source its signature names, whatever an entry calls it.
        guard Signer.moduleIdentifier(for: description.name) == serviceName else { throw Failure.wrongName(description.name) }
        self.name = name ?? description.name
        schema = description.schema
        parametersSchema = description.parametersSchema

        let encoded = Self.encoded(parameters)
        let checked: Result<String, Failure> = Self.ask(serviceName, cdhash, connect, timeout: timeout) {
            $0.problem(withParameters: encoded, reply: $1)
        }
        switch checked {
        case .success(let problem): parameterProblem = problem.isEmpty ? nil : problem
        case .failure(let failure): throw failure
        }
    }

    /// Asks the module for its data, with this entry's parameters. The
    /// `parameters` argument is not used: what a module is asked is fixed by
    /// the signed config, never by whoever is asking.
    func fetch(parameters _: SourceParameters, _ done: @escaping (Entry) -> Void) {
        if let parameterProblem { return done(failed(parameterProblem)) }
        let encoded = Self.encoded(parameters)
        DispatchQueue.global().async {
            let answer: Result<Data, Failure> = Self.ask(self.serviceName, self.cdhash, self.connect, timeout: Self.answerTimeout) {
                $0.fetch(parameters: encoded, reply: $1)
            }
            switch answer {
            case .success(let data):
                done((try? JSONDecoder().decode(Entry.self, from: data)) ?? self.failed("module's answer could not be read"))
            case .failure(let failure):
                log("\(self.name) (\(self.serviceName)): \(failure)")
                done(self.failed("module unavailable"))
            }
        }
    }

    private static func encoded(_ parameters: SourceParameters) -> Data {
        (try? JSONEncoder().encode(parameters)) ?? Data("{}".utf8)
    }

    /// One question to a module on a connection of its own. Returns the
    /// answer, or why there was none.
    private static func ask<Answer>(_ serviceName: String, _ cdhash: String?, _ connect: Connect, timeout: TimeInterval,
                                    _ question: (SourceService, @escaping (Answer) -> Void) -> Void) -> Result<Answer, Failure> {
        let connection: NSXPCConnection
        do { connection = try connect(serviceName, cdhash) } catch { return .failure(.unavailable("\(error)")) }
        connection.remoteObjectInterface = NSXPCInterface(with: SourceService.self)
        connection.resume()
        defer { connection.invalidate() }

        let lock = NSLock()
        let answered = DispatchSemaphore(value: 0)
        var result: Result<Answer, Failure>?
        func finish(_ value: Result<Answer, Failure>) {
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
        question(module) { finish(.success($0)) }
        if answered.wait(timeout: .now() + timeout) == .timedOut { finish(.failure(.unavailable("no answer in \(timeout) s"))) }
        lock.lock()
        defer { lock.unlock() }
        return result ?? .failure(.unavailable("no answer"))
    }
}
