import Foundation

// A source of data. Sources are independent of one another and of the core
// server, which knows them only through this interface and keeps a list of
// them. Everything particular to a source lives in its own file: what it
// reads, the permissions it needs, and the shape of its data.
//
// A source reports data, never a presentation of it: no truncating, casing
// or laying out. The server does not know the shape of the display, or
// whether there is one.
protocol Source {
    /// The key under which this source's entry and schema are served.
    var name: String { get }

    /// The JSON Schema of this source's data. Its `default` is the data to
    /// show when nothing is known.
    var schema: JSON { get }

    /// Reads the source's current data. Calls `done` exactly once, on any
    /// queue. A source never throws and never takes the server down: a
    /// problem is reported in the entry's `error`.
    func fetch(_ done: @escaping (Entry) -> Void)
}

/// What a source reports. `error` is a problem getting this source's data in
/// particular, and is empty when there was none.
struct Entry: Codable, Equatable {
    let error: String
    let data: JSON
}

extension Source {
    /// The data to show when nothing is known: the schema's `default`.
    var defaultData: JSON {
        if case .object(let schema) = schema, let value = schema["default"] { return value }
        return .null
    }

    func succeeded<Value: Encodable>(_ value: Value) -> Entry {
        guard let data = JSON(encoding: value) else { return failed("could not be encoded") }
        return Entry(error: "", data: data)
    }

    func failed(_ reason: String) -> Entry {
        Entry(error: reason, data: defaultData)
    }
}

extension JSON {
    /// The JSON form of an Encodable value, with dates in ISO 8601.
    init?<Value: Encodable>(encoding value: Value) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(value), let json = try? JSONDecoder().decode(JSON.self, from: data) else { return nil }
        self = json
    }
}

/// Asks every source for its data and calls `done`, on `queue`, with an entry
/// for each. A source that has not answered within `timeout` is reported as
/// such, so one slow source cannot hold up the others.
func retrieve(from sources: [Source], timeout: TimeInterval, on queue: DispatchQueue = .main, _ done: @escaping ([String: Entry]) -> Void) {
    var entries: [String: Entry] = [:]   // only touched on `queue`
    var finished = false
    func finish() {
        guard !finished else { return }
        finished = true
        for source in sources where entries[source.name] == nil {
            log("\(source.name) did not answer in \(timeout) s")
            entries[source.name] = source.failed("timed out")
        }
        done(entries)
    }
    queue.async {
        for source in sources {
            source.fetch { entry in
                queue.async {
                    guard !finished, entries[source.name] == nil else { return }
                    entries[source.name] = entry
                    if entries.count == sources.count { finish() }
                }
            }
        }
        if sources.isEmpty { finish() }
    }
    queue.asyncAfter(deadline: .now() + timeout) { finish() }
}
