import CryptoKit
import Foundation
import RetrieverSourceKit
import Network

setvbuf(stdout, nil, _IOLBF, 0)   // flush log lines immediately under launchd

let port: NWEndpoint.Port = 42511
let key = Wire.key(base64: ProcessInfo.processInfo.environment["RETRIEVER_KEY"] ?? "")


// `RetrieverServer status` reports on the modules and exits, serving nothing.
if CommandLine.arguments.dropFirst().first == "status" {
    for service in moduleServices {
        do {
            let module = try RemoteSource(service: service)
            let answered = DispatchSemaphore(value: 0)
            module.fetch { entry in
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
                let data = (try? encoder.encode(entry.data)).map { String(decoding: $0, as: UTF8.self) } ?? "?"
                print("\(service): ok; source \"\(module.name)\"; error \"\(entry.error)\"; data \(data)")
                answered.signal()
            }
            answered.wait()
        } catch {
            print("\(service): \(error)")
        }
    }
    exit(0)
}

let sources = allSources + connectModules()
let config = Config(sources: sources)
let serverInfo = ServerInfo.current(port: port.rawValue)
let sourceTimeout: TimeInterval = 3   // the plugin gives a whole fetch 4 s
var activeListener: NWListener?

func respond(_ conn: NWConnection, _ status: String, _ body: Data = Data()) {
    let head = "HTTP/1.1 \(status)\r\nContent-Type: application/octet-stream\r\n" +
               "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n"
    conn.send(content: Data(head.utf8) + body, completion: .contentProcessed { _ in conn.cancel() })
    log("-> \(status)")
}

// Receives until HTTPRequest.parse has a whole request. Calls `done` with the
// request line and the body, or with nil if no acceptable request arrived.
func readRequest(_ conn: NWConnection, _ buffer: Data = Data(), _ done: @escaping ((line: String, body: Data)?) -> Void) {
    switch HTTPRequest.parse(buffer) {
    case .complete(let line, let body): return done((line, body))
    case .invalid: return done(nil)
    case .incomplete: break
    }
    conn.receive(minimumIncompleteLength: 1, maximumLength: HTTPRequest.maxBytes) { data, _, _, error in
        if let error { log("Receive error from \(conn.endpoint): \(error)"); return done(nil) }
        guard let data, !data.isEmpty else { return done(nil) }
        readRequest(conn, buffer + data, done)
    }
}

// Closes the connection without a response: for anything that has not shown
// the key. The reason goes to the log only.
func drop(_ conn: NWConnection, _ reason: String) {
    conn.cancel()
    log("-> no response (\(reason))")
}

func handle(_ conn: NWConnection) {
    conn.start(queue: .main)
    readRequest(conn) { request in
        guard let request, let key else { return drop(conn, "not a request") }
        log("\(conn.endpoint) \(request.line)")
        let parts = request.line.split(separator: " ")
        guard parts.count >= 2, let path = URLComponents(string: String(parts[1]))?.path, Wire.paths.contains(path) else {
            return drop(conn, "unknown path")
        }
        guard parts[0] == "POST" else {
            return drop(conn, "not POST")
        }
        let id: String
        do {
            id = try Wire.open(request: request.body, path: path, key: key).id
        } catch {
            guard let status = (error as? Wire.Failure)?.status else { return drop(conn, "does not decrypt") }
            return respond(conn, status)
        }
        func send<Body: Codable>(_ data: Body) {
            guard let body = try? Wire.seal(response: data, id: id, seq: config.seq, path: path, key: key) else {
                return respond(conn, "500 Internal Server Error")
            }
            respond(conn, "200 OK", body)
        }
        if path == Wire.serverPath { return send(serverInfo) }
        if path == Wire.configPath { return send(config.schemas) }
        retrieve(from: sources, timeout: sourceTimeout) { send($0) }
    }
}

func startListener() {
    do {
        let listener = try NWListener(using: .tcp, on: port)
        // Registers with mDNSResponder so the HomePod sleep proxy can wake the Mac
        listener.service = NWListener.Service(name: "Retriever", type: "_http._tcp")
        listener.stateUpdateHandler = { log("Listener: \($0)") }
        listener.newConnectionHandler = handle
        listener.start(queue: .main)
        activeListener = listener
    } catch {
        log("Failed to start listener: \(error)")
        exit(1)
    }
}

guard key != nil else {
    log("Set RETRIEVER_KEY (base64 of 32 random bytes) before starting.")
    exit(1)
}

log("Sources: \(sources.map(\.name).joined(separator: ", ")); config \(config.seq)")
startListener()

// Ask every source once now. A source's first fetch may put a permission
// question to the user, as Reminders does after each rebuild, and reports
// "timed out" until it is answered. Better that the question appears at
// startup than on the first request.
retrieve(from: sources, timeout: sourceTimeout) { entries in
    for (name, entry) in entries.sorted(by: { $0.key < $1.key }) where !entry.error.isEmpty {
        log("\(name) at startup: \(entry.error)")
    }
}

dispatchMain()
