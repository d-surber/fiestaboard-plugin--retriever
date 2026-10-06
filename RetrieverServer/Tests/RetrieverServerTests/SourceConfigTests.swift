import CryptoKit
import Foundation
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

private let transportKey = SymmetricKey(data: Data(repeating: 7, count: 32))

@Test func configListsEverySourceWithItsSchema() {
    let config = SourceConfig(sources: vectorSources)
    #expect(Set(config.schemas.keys) == Set(vectorSources.map(\.name)))
    #expect(config.schemas.count == vectorSources.count)
    for source in vectorSources {
        #expect(config.schemas[source.name] == source.schema)
    }
    #expect(config.fingerprint == SourceConfig.fingerprint(of: config.schemas))
}

@Test func sequenceNumberIgnoresKeyOrderAndSourceOrder() {
    let a = FixedSource(name: "a", schema: ["type": "object", "default": ["x": 1, "y": "z"]])
    let sameA = FixedSource(name: "a", schema: ["default": ["y": "z", "x": 1], "type": "object"])
    let b = FixedSource(name: "b", schema: ["type": "string"])
    #expect(SourceConfig(sources: [a, b]).fingerprint == SourceConfig(sources: [b, sameA]).fingerprint)
}

@Test func sequenceNumberChangesWithTheContent() {
    let base: [String: JSON] = ["a": ["type": "object", "default": ["x": 1]]]
    #expect(SourceConfig.fingerprint(of: base) != SourceConfig.fingerprint(of: ["a": ["type": "object", "default": ["x": 2]]]))
    #expect(SourceConfig.fingerprint(of: base) != SourceConfig.fingerprint(of: ["a": ["type": "array", "default": ["x": 1]]]))
    #expect(SourceConfig.fingerprint(of: base) != SourceConfig.fingerprint(of: ["b": ["type": "object", "default": ["x": 1]]]))
}

@Test func addingASourceChangesTheSequenceNumber() {
    let first = vectorSources[0], second = vectorSources[1]
    #expect(SourceConfig(sources: [first]).fingerprint != SourceConfig(sources: [first, second]).fingerprint)
}

@Test func aRequestForOneEndpointIsRefusedByTheOther() throws {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let plaintext = Data(#"{"timestamp": 1800000000, "request_id": "abc123"}"#.utf8)
    let body = try ChaChaPoly.seal(plaintext, using: transportKey, authenticating: Wire.requestAuthenticatedData(Wire.retrievePath)).combined
    #expect(try Wire.open(request: body, path: Wire.retrievePath, key: transportKey, now: now).id == "abc123")
    #expect(throws: Wire.Failure.unauthenticated) { try Wire.open(request: body, path: Wire.configPath, key: transportKey, now: now) }
}

@Test func aConfigResponseCarriesTheSequenceNumberAndIsBoundToItsPath() throws {
    let config = SourceConfig(sources: vectorSources)
    let body = try Wire.seal(response: config.schemas, id: "abc123", configFingerprint: config.fingerprint, path: Wire.configPath, key: transportKey)
    let box = try ChaChaPoly.SealedBox(combined: body)
    #expect(throws: (any Error).self) { try ChaChaPoly.open(box, using: transportKey, authenticating: Wire.responseAuthenticatedData(Wire.retrievePath)) }
    let plain = try ChaChaPoly.open(box, using: transportKey, authenticating: Wire.responseAuthenticatedData(Wire.configPath))
    let decoded = try JSONDecoder().decode(Wire.Response<[String: JSON]>.self, from: plain)
    #expect(decoded.id == "abc123")
    #expect(decoded.configFingerprint == config.fingerprint)
    #expect(decoded.data == config.schemas)
}

@Test func jsonValuesSurviveARoundTrip() throws {
    let value: JSON = ["s": "x", "i": 3, "a": [1, "two", .null, .bool(true), .double(1.5)], "o": ["k": []]]
    #expect(try JSONDecoder().decode(JSON.self, from: JSONEncoder().encode(value)) == value)
}
