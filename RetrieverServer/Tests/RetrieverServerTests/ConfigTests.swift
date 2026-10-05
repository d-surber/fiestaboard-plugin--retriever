import CryptoKit
import Foundation
import Testing
@testable import RetrieverServer

private let key = SymmetricKey(data: Data(repeating: 7, count: 32))

private struct FixedSource: Source {
    let name: String
    let schema: JSON
    func fetch(_ done: @escaping (Entry) -> Void) { done(failed("unused")) }
}

@Test func configListsEverySourceWithItsSchema() {
    let config = Config(sources: allSources)
    #expect(Set(config.schemas.keys) == ["reminders", "music"])
    for source in allSources {
        #expect(config.schemas[source.name] == source.schema)
    }
    #expect(config.seq == Config.sequenceNumber(of: config.schemas))
}

@Test func sequenceNumberIgnoresKeyOrderAndSourceOrder() {
    let a = FixedSource(name: "a", schema: ["type": "object", "default": ["x": 1, "y": "z"]])
    let sameA = FixedSource(name: "a", schema: ["default": ["y": "z", "x": 1], "type": "object"])
    let b = FixedSource(name: "b", schema: ["type": "string"])
    #expect(Config(sources: [a, b]).seq == Config(sources: [b, sameA]).seq)
}

@Test func sequenceNumberChangesWithTheContent() {
    let base: [String: JSON] = ["a": ["type": "object", "default": ["x": 1]]]
    #expect(Config.sequenceNumber(of: base) != Config.sequenceNumber(of: ["a": ["type": "object", "default": ["x": 2]]]))
    #expect(Config.sequenceNumber(of: base) != Config.sequenceNumber(of: ["a": ["type": "array", "default": ["x": 1]]]))
    #expect(Config.sequenceNumber(of: base) != Config.sequenceNumber(of: ["b": ["type": "object", "default": ["x": 1]]]))
}

@Test func addingASourceChangesTheSequenceNumber() {
    let reminders = RemindersSource()
    #expect(Config(sources: [reminders]).seq != Config(sources: [reminders, MusicSource()]).seq)
}

@Test func aRequestForOneEndpointIsRefusedByTheOther() throws {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let plaintext = Data(#"{"ts": 1800000000, "id": "abc123"}"#.utf8)
    let body = try ChaChaPoly.seal(plaintext, using: key, authenticating: Wire.requestContext(Wire.retrievePath)).combined
    #expect(try Wire.open(request: body, path: Wire.retrievePath, key: key, now: now) == "abc123")
    #expect(throws: Wire.Failure.unauthenticated) { try Wire.open(request: body, path: Wire.configPath, key: key, now: now) }
}

@Test func aConfigResponseCarriesTheSequenceNumberAndIsBoundToItsPath() throws {
    let config = Config(sources: allSources)
    let body = try Wire.seal(response: config.schemas, id: "abc123", seq: config.seq, path: Wire.configPath, key: key)
    let box = try ChaChaPoly.SealedBox(combined: body)
    #expect(throws: (any Error).self) { try ChaChaPoly.open(box, using: key, authenticating: Wire.responseContext(Wire.retrievePath)) }
    let plain = try ChaChaPoly.open(box, using: key, authenticating: Wire.responseContext(Wire.configPath))
    let decoded = try JSONDecoder().decode(Wire.Response<[String: JSON]>.self, from: plain)
    #expect(decoded.id == "abc123")
    #expect(decoded.seq == config.seq)
    #expect(decoded.data == config.schemas)
}

@Test func jsonValuesSurviveARoundTrip() throws {
    let value: JSON = ["s": "x", "i": 3, "a": [1, "two", .null, .bool(true), .double(1.5)], "o": ["k": []]]
    #expect(try JSONDecoder().decode(JSON.self, from: JSONEncoder().encode(value)) == value)
}
