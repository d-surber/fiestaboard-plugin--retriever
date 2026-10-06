import CryptoKit
import Foundation
import Network
import RetrieverSourceKit

/// Listens for the plugin's requests and answers them.
///
/// Anything that has not shown the key costs the server as little as it can
/// be made to: no response, no line of its own in the log, a place among a
/// limited number of open connections, and that only for a limited time.
final class RequestListener {
    struct Limits {
        /// How long a connection has to deliver a whole request. The plugin
        /// sends one in a single write and gives up on a fetch after 4 s.
        var requestTimeout: TimeInterval = 10
        /// How long the sources have to answer; the plugin's 4 s must cover it.
        var sourceTimeout: TimeInterval = 3
        /// Connections open at once. One plugin makes one at a time; the
        /// rest is room for something else on the network knocking.
        var maxOpenConnections = 32
    }

    private let key: SymmetricKey
    private let state: ServerState
    private let serverInfo: [String: JSON]
    private let limits: Limits
    private let queue: DispatchQueue
    private var listener: NWListener?
    private var openConnections = 0
    private var unanswered = UnansweredTally()
    private var answeredRequests = AnsweredRequests()

    /// - Parameters:
    ///   - state: what is served. Used only on `queue`.
    ///   - queue: where every connection is handled; the server's one thread of work.
    init(key: SymmetricKey, state: ServerState, serverInfo: [String: JSON], limits: Limits = Limits(), queue: DispatchQueue = .main) {
        self.key = key
        self.state = state
        self.serverInfo = serverInfo
        self.limits = limits
        self.queue = queue
    }

    /// Starts listening.
    /// - Parameters:
    ///   - port: the port to listen on; `.any` picks a free one.
    ///   - serviceName: if given, the name to advertise by Bonjour, which is
    ///     what lets a sleep proxy wake the Mac for a request.
    ///   - onStateChange: told each state the listener passes through, on `queue`.
    /// - Throws: if the port cannot be listened on.
    func start(on port: NWEndpoint.Port, advertisedAs serviceName: String?, onStateChange: @escaping (NWListener.State) -> Void = { _ in }) throws {
        let listener = try NWListener(using: .tcp, on: port)
        if let serviceName { listener.service = NWListener.Service(name: serviceName, type: "_http._tcp") }
        listener.stateUpdateHandler = onStateChange
        listener.newConnectionHandler = { [weak self] in self?.accept($0) }
        listener.start(queue: queue)
        self.listener = listener
    }

    /// The port being listened on, once the listener is ready.
    var port: NWEndpoint.Port? { listener?.port }

    /// Writes to the log how many connections went unanswered since the last
    /// such line, if any did and that line was long enough ago. Called from
    /// time to time so that a count is not left waiting for the next knock.
    func logUnanswered(now: Date = Date()) {
        if let summary = unanswered.summary(now: now) { log(summary) }
    }

    // MARK: One connection

    /// A connection, from being accepted until it is closed.
    private final class Exchange {
        let connection: NWConnection
        var isClosed = false
        var requestDeadline: DispatchWorkItem?

        init(_ connection: NWConnection) { self.connection = connection }
    }

    private func accept(_ connection: NWConnection) {
        guard openConnections < limits.maxOpenConnections else {
            connection.cancel()
            return noteUnanswered("too many connections")
        }
        openConnections += 1
        let exchange = Exchange(connection)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed: connection.cancel()
            case .cancelled: self?.openConnections -= 1
            default: break
            }
        }
        connection.start(queue: queue)

        let deadline = DispatchWorkItem { [weak self] in self?.sayNothing(exchange, "no request in time") }
        exchange.requestDeadline = deadline
        queue.asyncAfter(deadline: .now() + limits.requestTimeout, execute: deadline)

        readRequest(exchange) { [weak self] request in
            guard let self, !exchange.isClosed else { return }
            exchange.requestDeadline?.cancel()
            guard let request else { return self.sayNothing(exchange, "not a request") }
            self.answer(request, exchange)
        }
    }

    /// Receives until `HTTPRequest.parse` has a whole request. Calls `done`
    /// with the request line and the body, or with nil if what arrived can
    /// never be a request or the connection ended first.
    private func readRequest(_ exchange: Exchange, _ buffer: Data = Data(), _ done: @escaping ((line: String, body: Data)?) -> Void) {
        switch HTTPRequest.parse(buffer) {
        case .complete(let line, let body): return done((line, body))
        case .invalid: return done(nil)
        case .incomplete: break
        }
        exchange.connection.receive(minimumIncompleteLength: 1, maximumLength: HTTPRequest.maxBytes) { [weak self] data, _, _, error in
            guard error == nil, let data, !data.isEmpty else { return done(nil) }
            self?.readRequest(exchange, buffer + data, done)
        }
    }

    private func answer(_ request: (line: String, body: Data), _ exchange: Exchange) {
        let words = request.line.split(separator: " ")
        guard words.count >= 2, let path = URLComponents(string: String(words[1]))?.path, Wire.paths.contains(path) else {
            return sayNothing(exchange, "unknown path")
        }
        guard words[0] == "POST" else { return sayNothing(exchange, "not POST") }

        let accepted: Wire.Accepted
        do {
            accepted = try Wire.open(request: request.body, path: path, key: key)
        } catch {
            // Only a request that decrypted is told why it is refused.
            guard let status = (error as? Wire.Failure)?.status else { return sayNothing(exchange, "does not decrypt") }
            return respond(exchange, path, status)
        }

        // The plugin makes every request anew, with an ID of its own. The same
        // one again is a recording played back, by someone who need not have
        // the key, and gets what anyone without the key gets.
        guard answeredRequests.admit(accepted.id, now: Date()) else { return sayNothing(exchange, "request repeated") }

        // The sequence number goes with the sources asked, whatever happens to
        // the state while they answer.
        let sequenceNumber = state.config.seq
        func send<Body: Codable>(_ data: Body) {
            guard let body = try? Wire.seal(response: data, id: accepted.id, seq: sequenceNumber, path: path, key: key) else {
                return respond(exchange, path, "500 Internal Server Error")
            }
            respond(exchange, path, "200 OK", body)
        }
        if path == Wire.serverPath { send(serverInfo) }
        else if path == Wire.configPath { send(state.config.schemas) }
        else { retrieve(from: state.sources, timeout: limits.sourceTimeout, on: queue) { send($0) } }

        // A module that could not be reached is tried again now that a
        // request has come, after this one is answered so it is not held up.
        if state.incomplete { queue.async { [state] in state.refresh(retryingModules: true) } }
    }

    /// Sends a status and a body, and closes. Only for a request that decrypted.
    private func respond(_ exchange: Exchange, _ path: String, _ status: String, _ body: Data = Data()) {
        guard !exchange.isClosed else { return }
        exchange.isClosed = true
        let head = "HTTP/1.1 \(status)\r\nContent-Type: application/octet-stream\r\n" +
                   "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        let connection = exchange.connection
        connection.send(content: Data(head.utf8) + body, completion: .contentProcessed { _ in connection.cancel() })
        // A client that never reads its answer is not waited on for long.
        queue.asyncAfter(deadline: .now() + limits.requestTimeout) { connection.cancel() }
        log("\(path) from \(connection.endpoint) -> \(status)")
    }

    /// Closes the connection without a response: for anything that has not
    /// shown the key. Nothing it sent reaches the log, only that it happened.
    private func sayNothing(_ exchange: Exchange, _ reason: String) {
        guard !exchange.isClosed else { return }
        exchange.isClosed = true
        exchange.requestDeadline?.cancel()
        exchange.connection.cancel()
        noteUnanswered(reason)
    }

    private func noteUnanswered(_ reason: String) {
        unanswered.record(reason)
        logUnanswered()
    }
}

/// Counts the connections that were given no response, by reason, and turns
/// the counts into a log line no more often than once in `interval`.
///
/// Whoever causes these has not shown the key, and must not be able to fill
/// the log: however many there are, they cost one line in each interval.
struct UnansweredTally {
    var interval: TimeInterval = 60
    private var counts: [String: Int] = [:]
    private var lastSummary: Date?

    mutating func record(_ reason: String) {
        counts[reason, default: 0] += 1
    }

    /// The line to log now, or nil if nothing has been counted since the
    /// last one or the last one was less than `interval` ago. Counting
    /// starts afresh once a line is given.
    mutating func summary(now: Date) -> String? {
        guard !counts.isEmpty else { return nil }
        if let lastSummary, now.timeIntervalSince(lastSummary) < interval { return nil }
        let total = counts.values.reduce(0, +)
        let reasons = counts.sorted { $0.key < $1.key }.map { "\($0.value) \($0.key)" }.joined(separator: ", ")
        counts = [:]
        lastSummary = now
        return "\(total) connection\(total == 1 ? "" : "s") given no response (\(reasons))"
    }
}

/// Remembers the requests answered lately, so that none is answered twice.
///
/// A request is good for as long as its timestamp is within `Wire.maxSkew`
/// of the server's clock, either side, so a copy of one could be sent again
/// for up to twice that. Its ID is remembered for that long. Only requests
/// that decrypted are remembered, so only a holder of the key can add to
/// the memory, and it is bounded all the same.
struct AnsweredRequests {
    var remembersFor: TimeInterval = 2 * Wire.maxSkew + 1
    var capacity = 4096
    private var forgetAt: [String: Date] = [:]

    /// Whether a request with this ID is to be answered: true the first time
    /// within the remembered period, false after that.
    mutating func admit(_ id: String, now: Date) -> Bool {
        if let forget = forgetAt[id], forget > now { return false }
        if forgetAt.count >= capacity { forgetAt = forgetAt.filter { $0.value > now } }
        // Still full: more requests in two minutes than a plugin makes in a
        // day. The oldest go, which is the most that can then be replayed.
        if forgetAt.count >= capacity {
            for (old, _) in forgetAt.sorted(by: { $0.value < $1.value }).prefix(capacity / 4) { forgetAt[old] = nil }
        }
        forgetAt[id] = now.addingTimeInterval(remembersFor)
        return true
    }
}
