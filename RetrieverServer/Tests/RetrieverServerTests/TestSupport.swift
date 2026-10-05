import Foundation
@testable import RetrieverServer

// Helpers shared by the tests of the Source interface and of each source.

/// The property names a schema gives an object.
func properties(of schema: JSON) -> [String: JSON] {
    guard case .object(let object) = schema, case .object(let properties)? = object["properties"] else { return [:] }
    return properties
}

/// True if `value` has exactly the properties `schema` names, at every level.
func matches(_ value: JSON, _ schema: JSON) -> Bool {
    guard case .object(let object) = value else { return true }
    let expected = properties(of: schema)
    return Set(object.keys) == Set(expected.keys) && object.allSatisfy { matches($0.value, expected[$0.key] ?? .null) }
}

/// A stand-in source that reports a fixed value.
struct FixedSource: Source {
    let name: String
    let schema: JSON
    var value: JSON = .null
    func fetch(_ done: @escaping (Entry) -> Void) { done(Entry(error: "", data: value)) }
}

/// The sources the interop vectors in tests/vectors.json were generated
/// from. They are stand-ins, not the server's own, so that adding or
/// changing a real source never invalidates the vectors.
let vectorSources: [FixedSource] = [
    FixedSource(
        name: "numbers",
        schema: [
            "type": "object",
            "properties": ["count": ["type": "integer"], "items": ["type": "array", "items": ["type": "integer"]]],
            "default": ["count": 0, "items": []],
        ],
        value: ["count": 2, "items": [1, 2]]),
    FixedSource(
        name: "words",
        schema: ["type": "object", "properties": ["text": ["type": "string"]], "default": ["text": ""]],
        value: ["text": "na\u{EF}ve caf\u{E9}"]),
]

/// What `vectorSources` report, as a retrieve response carries it.
var vectorEntries: [String: Entry] {
    Dictionary(uniqueKeysWithValues: vectorSources.map { ($0.name, Entry(error: "", data: $0.value)) })
}
