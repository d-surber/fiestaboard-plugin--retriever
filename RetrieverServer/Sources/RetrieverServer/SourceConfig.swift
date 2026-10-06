import CryptoKit
import Foundation
import RetrieverSourceKit

// What the server tells the plugin about itself, so that the plugin need not
// have it built in: the sources, and for each the shape of its data as a
// JSON Schema. A schema describes only what depends on the source; the
// {"error", "data"} wrapper around every source's data is not part of it.
struct SourceConfig {
    let schemas: [String: JSON]

    /// Changes whenever the schemas do; sent with every response so the
    /// plugin knows to read the config again. Only inequality is meaningful.
    let sequenceNumber: UInt32

    init(sources: [Source]) {
        schemas = Dictionary(sources.map { ($0.name, $0.schema) }, uniquingKeysWith: { first, _ in first })
        sequenceNumber = SourceConfig.sequenceNumber(of: schemas)
    }

    /// The first four bytes of the SHA-256 of the schemas in canonical form:
    /// compact JSON with sorted keys, so that key order and layout do not count.
    static func sequenceNumber(of schemas: [String: JSON]) -> UInt32 {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let canonical = (try? encoder.encode(schemas)) ?? Data()
        return SHA256.hash(data: canonical).prefix(4).reduce(0) { $0 << 8 | UInt32($1) }
    }
}
