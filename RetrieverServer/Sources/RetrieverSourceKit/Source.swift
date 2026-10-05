import Foundation

// A source of data. Sources are independent of one another and of the core
// server, which knows them only through this interface and keeps a list of
// them. Everything particular to a source lives in its own module: what it
// reads, the permissions it needs, and the shape of its data.
//
// This library is what a source module and the server share. A module is a
// separate signed program that hands one Source to SourceHost; the server
// reaches it over XPC and sees it as a Source again.
//
// A source reports data, never a presentation of it: no truncating, casing
// or laying out. The server does not know the shape of the display, or
// whether there is one.
public protocol Source {
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
public struct Entry: Codable, Equatable {
    public let error: String
    public let data: JSON

    public init(error: String, data: JSON) {
        self.error = error
        self.data = data
    }
}

public extension Source {
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

public extension JSON {
    /// The JSON form of an Encodable value, with dates in ISO 8601.
    init?<Value: Encodable>(encoding value: Value) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(value), let json = try? JSONDecoder().decode(JSON.self, from: data) else { return nil }
        self = json
    }
}
