import CryptoKit
import Foundation

// What the server tells the plugin about itself, so that the plugin need not
// have it built in: the data sources, and for each the shape of its data as
// a JSON Schema. A schema describes only what depends on the source; the
// {"error", "data"} wrapper around every source's data is not part of it.
// Each schema's `default` is the value to show when nothing is known.
enum Config {
    static let sources: [String: JSON] = ["reminders": remindersSchema]

    /// Changes whenever `sources` does; sent with every response so the
    /// plugin knows to read the config again. Only inequality is meaningful.
    static let seq = sequenceNumber(of: sources)

    /// The first four bytes of the SHA-256 of the sources in canonical form:
    /// compact JSON with sorted keys, so that key order and layout do not count.
    static func sequenceNumber(of sources: [String: JSON]) -> UInt32 {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let canonical = (try? encoder.encode(sources)) ?? Data()
        return SHA256.hash(data: canonical).prefix(4).reduce(0) { $0 << 8 | UInt32($1) }
    }
}

/// The shape of `Payload`.
let remindersSchema: JSON = [
    "type": "object",
    "properties": [
        "count": ["type": "integer"],
        "text": ["type": "string"],
        "items": [
            "type": "array",
            "items": [
                "type": "object",
                "properties": [
                    "title": ["type": "string"],
                    "list": ["type": "string"],
                    "due": ["type": "string", "format": "date-time"],
                    "priority": ["type": "integer"],
                ],
            ],
        ],
    ],
    "default": ["count": 0, "text": "", "items": []],
]
