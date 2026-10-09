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

    /// The JSON Schema of the parameters this source takes: an object, each
    /// property a parameter, with its type and, for a person reading it, its
    /// default. A source that takes none need not say so.
    var parametersSchema: JSON { get }

    /// What is wrong with a set of parameters, or nil if this source can be
    /// asked with them. Unless a source has more to say, they are checked
    /// against `parametersSchema`.
    ///
    /// Asked once for each entry in the module config, when the server
    /// starts, so that a mistake in the config is reported then and not
    /// found one fetch at a time. It must not depend on anything that can
    /// change while the server runs.
    func problem(with parameters: SourceParameters) -> String?

    /// Reads the source's current data. Calls `done` exactly once, on any
    /// queue. A source never throws and never takes the server down: a
    /// problem is reported in the entry's `error`.
    /// - Parameter parameters: what this entry in the module config asks of
    ///   the source; the same module may be asked different things under
    ///   different names. They have passed `problem(with:)`.
    func fetch(parameters: SourceParameters, _ done: @escaping (Entry) -> Void)
}

/// What a source is asked, by parameter name.
public typealias SourceParameters = [String: JSON]

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
    /// A source takes no parameters unless it says otherwise.
    var parametersSchema: JSON { ["type": "object", "properties": [:]] }

    func problem(with parameters: SourceParameters) -> String? {
        ParametersSchema.problem(with: parameters, against: parametersSchema)
    }

    /// The data to show when nothing is known: the schema's `default`.
    var defaultData: JSON {
        if case .object(let schema) = schema, let value = schema["default"] { return value }
        return .null
    }

    /// The entry for data that was read.
    func succeeded<Value: Encodable>(_ value: Value) -> Entry {
        guard let data = JSON(encoding: value) else { return failed("could not be encoded") }
        return Entry(error: "", data: data)
    }

    /// The entry for data that could not be read: the reason, and the schema's default in place of the data.
    func failed(_ reason: String) -> Entry {
        Entry(error: reason, data: defaultData)
    }
}

public extension JSON {
    /// The JSON form of an Encodable value. A date is written in ISO 8601 as
    /// the time of day in `timeZone` with its offset from UTC:
    /// "2026-10-08T09:00:00-07:00". It is the same moment however it is
    /// written; written this way it also says what the clock here showed.
    init?<Value: Encodable>(encoding value: Value, in timeZone: TimeZone = .current) {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = timeZone
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(formatter.string(from: date))
        }
        guard let data = try? encoder.encode(value), let json = try? JSONDecoder().decode(JSON.self, from: data) else { return nil }
        self = json
    }
}
