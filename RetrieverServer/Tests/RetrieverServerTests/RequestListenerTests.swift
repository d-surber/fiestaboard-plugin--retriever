import CryptoKit
import Foundation
import Network
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

private let key = SymmetricKey(data: Data(repeating: 7, count: 32))

/// A listener on a free port of this machine, serving the stand-in sources.
private final class RunningListener {
    let queue = DispatchQueue(label: "request-listener-tests")
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let state: ServerState
    let listener: RequestListener
    let port: UInt16

    init(_ limits: RequestListener.Limits = RequestListener.Limits()) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let state = ServerState(builtIn: vectorSources, directory: directory, builtInKey: nil) { _ in [] }
        queue.sync { _ = state.refresh() }
        self.state = state
        let queue = self.queue
        let listener = RequestListener(key: key, state: state, serverInfo: vectorServerInfo, limits: limits, queue: queue)
        self.listener = listener
        let ready = DispatchSemaphore(value: 0)
        try listener.start(on: .any, advertisedAs: nil) { if case .ready = $0 { ready.signal() } }
        guard ready.wait(timeout: .now() + 5) == .success, let port = queue.sync(execute: { listener.port }) else {
            throw CocoaError(.featureUnsupported)
        }
        self.port = port.rawValue
    }

    deinit { try? FileManager.default.removeItem(at: directory) }
}

/// What a client saw of one connection.
private enum Outcome: Equatable {
    case closedWithNothingSent
    case answered(Data)
    case stillOpen
}

/// A client's end of a connection, over plain sockets so that nothing of the
/// server's own code is on this side of the test.
private final class ClientConnection {
    private let descriptor: Int32

    init(port: UInt16) throws {
        descriptor = socket(AF_INET, SOCK_STREAM, 0)
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        try #require(connected == 0)
    }

    deinit { close(descriptor) }

    func send(_ bytes: Data) {
        bytes.withUnsafeBytes { _ = Darwin.send(descriptor, $0.baseAddress, bytes.count, 0) }
    }

    /// Reads until the server closes the connection or `seconds` pass with nothing arriving.
    func outcome(within seconds: Double) -> Outcome {
        var limit = timeval(tv_sec: Int(seconds), tv_usec: Int32((seconds - Double(Int(seconds))) * 1_000_000))
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        var received = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = recv(descriptor, &buffer, buffer.count, 0)
            if count > 0 { received.append(contentsOf: buffer[..<count]); continue }
            if count == 0 || errno == ECONNRESET { return received.isEmpty ? .closedWithNothingSent : .answered(received) }
            return received.isEmpty ? .stillOpen : .answered(received)
        }
    }
}

private func httpRequest(_ line: String, body: Data = Data()) -> Data {
    Data("\(line)\r\nContent-Length: \(body.count)\r\n\r\n".utf8) + body
}

private func sealedRequest(path: String, timestamp: Date = Date(), id: String = "abc123") throws -> Data {
    let plaintext = Data(#"{"timestamp": \#(Int(timestamp.timeIntervalSince1970)), "request_id": "\#(id)"}"#.utf8)
    return try ChaChaPoly.seal(plaintext, using: key, authenticating: Wire.requestAuthenticatedData(path)).combined
}

/// The status line and the body of an HTTP response.
private func parts(of response: Data) throws -> (status: String, body: Data) {
    let headEnd = try #require(response.range(of: Data("\r\n\r\n".utf8)))
    let head = String(decoding: response[..<headEnd.lowerBound], as: UTF8.self)
    return (String(head.split(separator: "\r\n")[0]), Data(response[headEnd.upperBound...]))
}

/// These tests wait on real connections. They run one at a time so that
/// their waiting does not use up the threads the other tests run on.
@Suite(.serialized) struct ListenerOverRealConnections {
    @Test(arguments: [Wire.serverInfoPath, Wire.configPath, Wire.retrievePath])
    func answersARequestThatShowsTheKey(path: String) throws {
        let running = try RunningListener()
        let client = try ClientConnection(port: running.port)
        client.send(httpRequest("POST \(path) HTTP/1.1", body: try sealedRequest(path: path)))
        guard case .answered(let response) = client.outcome(within: 5) else { Issue.record("no answer"); return }
        let (status, body) = try parts(of: response)
        #expect(status == "HTTP/1.1 200 OK")
        let plaintext = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: body), using: key, authenticating: Wire.responseAuthenticatedData(path))
        let answer = try JSONDecoder().decode(Wire.Response<JSON>.self, from: plaintext)
        #expect(answer.id == "abc123")
        #expect(answer.configFingerprint == running.queue.sync { running.state.sourceConfig.fingerprint })
    }

    @Test func aRequestThatDecryptsButIsRefusedIsToldWhy() throws {
        let running = try RunningListener()
        let client = try ClientConnection(port: running.port)
        let stale = try sealedRequest(path: Wire.retrievePath, timestamp: Date().addingTimeInterval(-3600))
        client.send(httpRequest("POST /retrieve HTTP/1.1", body: stale))
        guard case .answered(let response) = client.outcome(within: 5) else { Issue.record("no answer"); return }
        #expect(try parts(of: response).status == "HTTP/1.1 400 Stale Timestamp")
    }

    @Test(arguments: [
        httpRequest("GET /retrieve HTTP/1.1"),
        httpRequest("FOO /retrieve HTTP/1.1"),
        Data("hello\r\n\r\n".utf8),
        httpRequest("POST /nowhere HTTP/1.1", body: Data(repeating: 1, count: 40)),
        httpRequest("POST /retrieve HTTP/1.1", body: Data(repeating: 1, count: 40)),
        httpRequest("POST /retrieve HTTP/1.1"),
        Data("POST /retrieve HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".utf8),
        Data("POST /retrieve HTTP/1.1\r\nX: ".utf8) + Data(repeating: 97, count: 17000) + Data("\r\n\r\n".utf8),
    ])
    func saysNothingToARequestThatHasNotShownTheKey(request: Data) throws {
        let running = try RunningListener()
        let client = try ClientConnection(port: running.port)
        client.send(request)
        #expect(client.outcome(within: 5) == .closedWithNothingSent)
    }

    @Test func saysNothingToARequestSealedWithAnotherKey() throws {
        let running = try RunningListener()
        let client = try ClientConnection(port: running.port)
        let other = SymmetricKey(data: Data(repeating: 8, count: 32))
        let body = try ChaChaPoly.seal(Data(#"{"timestamp": \#(Int(Date().timeIntervalSince1970)), "request_id": "x"}"#.utf8), using: other,
                                       authenticating: Wire.requestAuthenticatedData(Wire.retrievePath)).combined
        client.send(httpRequest("POST /retrieve HTTP/1.1", body: body))
        #expect(client.outcome(within: 5) == .closedWithNothingSent)
    }

    @Test(arguments: [
        Data(),
        Data("POST /retrieve HTTP/1.1\r\n".utf8),
        Data("POST /retrieve HTTP/1.1\r\nContent-Length: 100\r\n\r\nonly this much".utf8),
    ])
    func closesAConnectionThatDoesNotDeliverARequestInTime(sent: Data) throws {
        let running = try RunningListener(RequestListener.Limits(requestTimeout: 0.3))
        let client = try ClientConnection(port: running.port)
        client.send(sent)
        #expect(client.outcome(within: 5) == .closedWithNothingSent)
    }

    @Test func aRequestIsAnsweredOnceAndARecordingOfItGetsNothing() throws {
        let running = try RunningListener()
        let request = httpRequest("POST /retrieve HTTP/1.1", body: try sealedRequest(path: Wire.retrievePath, id: "only-once"))
        let first = try ClientConnection(port: running.port)
        first.send(request)
        guard case .answered(let response) = first.outcome(within: 5) else { Issue.record("no answer"); return }
        #expect(try parts(of: response).status == "HTTP/1.1 200 OK")

        let playedBack = try ClientConnection(port: running.port)
        playedBack.send(request)
        #expect(playedBack.outcome(within: 5) == .closedWithNothingSent)

        let another = try ClientConnection(port: running.port)
        another.send(httpRequest("POST /retrieve HTTP/1.1", body: try sealedRequest(path: Wire.retrievePath, id: "a-new-one")))
        guard case .answered = another.outcome(within: 5) else { Issue.record("a new request went unanswered"); return }
    }

    @Test func aConnectionWithinItsTimeIsLeftOpen() throws {
        let running = try RunningListener(RequestListener.Limits(requestTimeout: 30))
        let client = try ClientConnection(port: running.port)
        #expect(client.outcome(within: 1) == .stillOpen)
    }

    @Test func holdsNoMoreConnectionsThanItsLimitAndFreesThemWhenTheyClose() throws {
        let running = try RunningListener(RequestListener.Limits(requestTimeout: 30, maxOpenConnections: 2))
        var idle: [ClientConnection]? = [try ClientConnection(port: running.port), try ClientConnection(port: running.port)]
        #expect(idle?[0].outcome(within: 0.5) == .stillOpen)

        let oneTooMany = try ClientConnection(port: running.port)
        #expect(oneTooMany.outcome(within: 5) == .closedWithNothingSent)

        idle = nil   // the two close; their places come free
        var answered = false
        for _ in 0..<20 where !answered {
            let client = try ClientConnection(port: running.port)
            client.send(httpRequest("POST /server HTTP/1.1", body: try sealedRequest(path: Wire.serverInfoPath)))
            if case .answered = client.outcome(within: 1) { answered = true } else { Thread.sleep(forTimeInterval: 0.1) }
        }
        #expect(answered)
    }
}

// MARK: The log

@Test func unansweredConnectionsCostOneLogLineAnInterval() {
    var tally = UnansweredTally(interval: 60)
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    #expect(tally.summary(now: start) == nil)

    tally.record("not a request")
    #expect(tally.summary(now: start) == "1 connection given no response (1 not a request)")

    for _ in 0..<10_000 { tally.record("does not decrypt") }
    tally.record("not POST")
    #expect(tally.summary(now: start.addingTimeInterval(59)) == nil)
    #expect(tally.summary(now: start.addingTimeInterval(60)) == "10001 connections given no response (10000 does not decrypt, 1 not POST)")
    #expect(tally.summary(now: start.addingTimeInterval(600)) == nil)
}

@Test func aLargeLogIsSetAsideAndOnlyOneEarlierLogIsKept() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let log = directory.appendingPathComponent("RetrieverServer.log")

    try Data(repeating: 65, count: 100).write(to: log)
    #expect(LogFile.rotateIfLarge(log, maxByteCount: 100) == false)   // at the limit is not past it
    #expect(FileManager.default.fileExists(atPath: LogFile.earlier(log).path) == false)

    try Data(repeating: 66, count: 101).write(to: log)
    #expect(LogFile.rotateIfLarge(log, maxByteCount: 100))
    #expect(FileManager.default.fileExists(atPath: log.path) == false)
    #expect(try Data(contentsOf: LogFile.earlier(log)) == Data(repeating: 66, count: 101))

    try Data(repeating: 67, count: 200).write(to: log)
    #expect(LogFile.rotateIfLarge(log, maxByteCount: 100))
    #expect(try Data(contentsOf: LogFile.earlier(log)) == Data(repeating: 67, count: 200))   // the one before is gone

    #expect(LogFile.rotateIfLarge(log, maxByteCount: 100) == false)   // no log, nothing to do
}

@Test func eachLogLevelIncludesTheOnesBeforeIt() {
    #expect(LogLevel.allCases == [.none, .terse, .verbose, .debug])
    #expect(LogLevel.none < .terse && LogLevel.terse < .verbose && LogLevel.verbose < .debug)
    #expect(LogLevel.standard == .terse)
}

@Test func aLogLevelIsNamedByItsWord() {
    #expect(LogLevel(named: "verbose") == .verbose)
    #expect(LogLevel(named: " Debug\n") == .debug)
    #expect(LogLevel(named: "none") == LogLevel.none)
    #expect(LogLevel(named: "chatty") == nil)
    #expect(LogLevel(named: "") == nil)
}

@Test func theAccountsChoiceOfLogLevelIsKeptInAFileAndTheStandardLevelStandsInForNone() throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: home) }
    let file = LogSettings.file(home: home)
    #expect(file.path.hasSuffix("Library/Application Support/Retriever/log-level"))
    #expect(LogSettings.level(in: file) == .terse)             // no file

    for level in LogLevel.allCases {
        try LogSettings.set(level, in: file)
        #expect(LogSettings.level(in: file) == level)
    }
    try Data("nonsense".utf8).write(to: file)
    #expect(LogSettings.level(in: file) == .terse)             // a file that names no level
}
