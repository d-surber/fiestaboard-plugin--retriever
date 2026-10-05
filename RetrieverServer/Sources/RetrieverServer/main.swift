import CryptoKit
import EventKit
import Foundation
import Network

setvbuf(stdout, nil, _IOLBF, 0)   // flush log lines immediately under launchd

let port: NWEndpoint.Port = 42511
let WIDTH = 15   // board columns (Vestaboard Note)
let ROWS = 3     // board rows (Vestaboard Note)
let key = Wire.key(base64: ProcessInfo.processInfo.environment["RETRIEVER_KEY"] ?? "")
let store = EKEventStore()
var activeListener: NWListener?

struct Item: Codable {
    let title: String
    let list: String
    let due: Date?
    let priority: Int
}

// Top-level object rather than a bare array: many JSON-path consumers expect one.
struct Payload: Codable {
    let count: Int
    let text: String      // board-ready: uppercased titles, one per line, WIDTH chars max, ROWS lines max
    let items: [Item]
}

// One served value. `error` reports a problem getting this value in
// particular and is empty when there was none.
struct Entry<Value: Codable>: Codable {
    let error: String
    let data: Value
}

// Everything the server serves, keyed by name.
struct Values: Codable {
    let reminders: Entry<Payload>
}

func log(_ s: String) { print("\(ISO8601DateFormatter().string(from: Date())) \(s)") }

// Calls `done` with nil if Reminders could not be read.
func fetchReminders(_ done: @escaping ([Item]?) -> Void) {
    let cal = Calendar.current
    store.refreshSourcesIfNecessary()
    // Fetch all incomplete reminders and filter locally: EventKit's date-range
    // predicate can miss date-only ("all-day") reminders. A repeating reminder
    // is one EKReminder whose due date is its next incomplete occurrence.
    let pred = store.predicateForIncompleteReminders(withDueDateStarting: nil, ending: nil, calendars: nil)
    store.fetchReminders(matching: pred) { reminders in
        guard let all = reminders else {
            log("Reminders could not be read")
            return done(nil)
        }
        let items = all.compactMap { r -> Item? in
            guard let comps = r.dueDateComponents,
                  let due = cal.date(from: comps),
                  cal.isDateInToday(due) else { return nil }
            return Item(title: r.title ?? "", list: r.calendar.title, due: due, priority: r.priority)
        }
        log("Fetched \(all.count) incomplete, \(items.count) due today")
        done(items.sorted { ($0.due ?? .distantFuture) < ($1.due ?? .distantFuture) })
    }
}

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

func handle(_ conn: NWConnection) {
    conn.start(queue: .main)
    readRequest(conn) { request in
        guard let request, let key else { return respond(conn, "400 Bad Request") }
        log("\(conn.endpoint) \(request.line)")
        let parts = request.line.split(separator: " ")
        guard parts.count >= 2, URLComponents(string: String(parts[1]))?.path == Wire.path else {
            return respond(conn, "404 Not Found")
        }
        guard parts[0] == "POST" else {
            return respond(conn, "405 Method Not Allowed")
        }
        let id: String
        do {
            id = try Wire.open(request: request.body, key: key)
        } catch Wire.Failure.stale {
            // Authentic but old or from a wrong clock. Said distinctly so that
            // clock skew is not mistaken for a wrong key.
            return respond(conn, "400 Stale Timestamp")
        } catch Wire.Failure.malformed {
            return respond(conn, "400 Bad Request")
        } catch {
            return respond(conn, "401 Unauthorized")
        }
        fetchReminders { fetched in
            let items = fetched ?? []
            let text = items.prefix(ROWS)
                .map { String($0.title.uppercased().prefix(WIDTH)) }
                .joined(separator: "\n")
            let values = Values(reminders: Entry(
                error: fetched == nil ? "Reminders could not be read" : "",
                data: Payload(count: items.count, text: text, items: items)))
            DispatchQueue.main.async {
                guard let body = try? Wire.seal(response: values, id: id, key: key) else {
                    return respond(conn, "500 Internal Server Error")
                }
                respond(conn, "200 OK", body)
            }
        }
    }
}

func startListener() {
    do {
        let listener = try NWListener(using: .tcp, on: port)
        // Registers with mDNSResponder so the HomePod sleep proxy can wake the Mac
        listener.service = NWListener.Service(name: "Reminders", type: "_http._tcp")
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

store.requestFullAccessToReminders { granted, error in
    guard granted else {
        log("Reminders access denied: \(error?.localizedDescription ?? "no error given")")
        exit(1)
    }
    DispatchQueue.main.async { startListener() }
}

dispatchMain()
