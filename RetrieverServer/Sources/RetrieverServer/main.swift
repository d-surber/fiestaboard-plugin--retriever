import EventKit
import Foundation
import Network

setvbuf(stdout, nil, _IOLBF, 0)   // flush log lines immediately under launchd

let port: NWEndpoint.Port = 42511
let WIDTH = 15   // board columns (Vestaboard Note)
let ROWS = 3     // board rows (Vestaboard Note)
let token = ProcessInfo.processInfo.environment["REMINDERS_TOKEN"] ?? ""
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

func log(_ s: String) { print("\(ISO8601DateFormatter().string(from: Date())) \(s)") }

func fetchReminders(_ done: @escaping ([Item]) -> Void) {
    let cal = Calendar.current
    store.refreshSourcesIfNecessary()
    // Fetch all incomplete reminders and filter locally: EventKit's date-range
    // predicate can miss date-only ("all-day") reminders. A repeating reminder
    // is one EKReminder whose due date is its next incomplete occurrence.
    let pred = store.predicateForIncompleteReminders(withDueDateStarting: nil, ending: nil, calendars: nil)
    store.fetchReminders(matching: pred) { reminders in
        let all = reminders ?? []
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

func respond(_ conn: NWConnection, _ status: String, _ body: Data) {
    let head = "HTTP/1.1 \(status)\r\nContent-Type: application/json\r\n" +
               "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n"
    conn.send(content: Data(head.utf8) + body, completion: .contentProcessed { _ in conn.cancel() })
    log("-> \(status)")
}

func handle(_ conn: NWConnection) {
    conn.start(queue: .main)
    conn.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, _, error in
        if let error { log("Receive error from \(conn.endpoint): \(error)"); conn.cancel(); return }
        let request = String(decoding: data ?? Data(), as: UTF8.self)
        let firstLine = String(request.split(separator: "\r\n").first ?? "")
        log("\(conn.endpoint) \(firstLine.replacingOccurrences(of: token, with: "***"))")
        let parts = firstLine.split(separator: " ")
        guard parts.count >= 2, parts[0] == "GET" else {
            return respond(conn, "405 Method Not Allowed", Data("{}".utf8))
        }
        guard let url = URLComponents(string: String(parts[1])), url.path == "/reminders" else {
            return respond(conn, "404 Not Found", Data("{}".utf8))
        }
        let given = url.queryItems?.first { $0.name == "token" }?.value ?? ""
        guard !token.isEmpty, given == token else {
            return respond(conn, "401 Unauthorized", Data("{}".utf8))
        }
        fetchReminders { items in
            let text = items.prefix(ROWS)
                .map { String($0.title.uppercased().prefix(WIDTH)) }
                .joined(separator: "\n")
            let payload = Payload(count: items.count, text: text, items: items)
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let body = (try? encoder.encode(payload)) ?? Data("{}".utf8)
            DispatchQueue.main.async { respond(conn, "200 OK", body) }
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

guard !token.isEmpty else {
    log("Set REMINDERS_TOKEN before starting.")
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
