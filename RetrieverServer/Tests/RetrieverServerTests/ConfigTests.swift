import CryptoKit
import Foundation
import Testing
@testable import RetrieverServer

private let key = SymmetricKey(data: Data(repeating: 7, count: 32))

@Test func configListsRemindersWithItsSchema() {
    #expect(Array(Config.sources.keys) == ["reminders"])
    #expect(Config.sources["reminders"] == remindersSchema)
}

@Test func theSchemaDefaultIsAnEmptyPayload() throws {
    guard case .object(let schema) = remindersSchema, let value = schema["default"] else {
        Issue.record("the reminders schema has no default")
        return
    }
    let payload = try JSONDecoder().decode(Payload.self, from: JSONEncoder().encode(value))
    #expect(payload.count == 0)
    #expect(payload.text == "")
    #expect(payload.items.isEmpty)
}

@Test func theSchemaNamesEveryFieldOfThePayload() throws {
    let item = Item(title: "t", list: "l", due: Date(), priority: 0)
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let encoded = try JSONDecoder().decode(JSON.self, from: encoder.encode(Payload(count: 1, text: "T", items: [item])))
    guard case .object(let payload) = encoded, case .array(let items)? = payload["items"], case .object(let first)? = items.first,
          case .object(let schema) = remindersSchema, case .object(let properties)? = schema["properties"],
          case .object(let itemsSchema)? = properties["items"], case .object(let itemSchema)? = itemsSchema["items"],
          case .object(let itemProperties)? = itemSchema["properties"]
    else {
        Issue.record("payload or schema is not shaped as expected")
        return
    }
    #expect(Set(payload.keys) == Set(properties.keys))
    #expect(Set(first.keys) == Set(itemProperties.keys))
}

@Test func sequenceNumberIgnoresKeyOrder() {
    let one: [String: JSON] = ["a": ["type": "object", "default": ["x": 1, "y": "z"]], "b": ["type": "string"]]
    let other: [String: JSON] = ["b": ["type": "string"], "a": ["default": ["y": "z", "x": 1], "type": "object"]]
    #expect(Config.sequenceNumber(of: one) == Config.sequenceNumber(of: other))
}

@Test func sequenceNumberChangesWithTheContent() {
    let base: [String: JSON] = ["a": ["type": "object", "default": ["x": 1]]]
    #expect(Config.sequenceNumber(of: base) != Config.sequenceNumber(of: ["a": ["type": "object", "default": ["x": 2]]]))
    #expect(Config.sequenceNumber(of: base) != Config.sequenceNumber(of: ["a": ["type": "array", "default": ["x": 1]]]))
    #expect(Config.sequenceNumber(of: base) != Config.sequenceNumber(of: ["b": ["type": "object", "default": ["x": 1]]]))
    #expect(Config.seq == Config.sequenceNumber(of: Config.sources))
}

@Test func aRequestForOneEndpointIsRefusedByTheOther() throws {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let plaintext = Data(#"{"ts": 1800000000, "id": "abc123"}"#.utf8)
    let body = try ChaChaPoly.seal(plaintext, using: key, authenticating: Wire.requestContext(Wire.retrievePath)).combined
    #expect(try Wire.open(request: body, path: Wire.retrievePath, key: key, now: now) == "abc123")
    #expect(throws: Wire.Failure.unauthenticated) { try Wire.open(request: body, path: Wire.configPath, key: key, now: now) }
}

@Test func aConfigResponseCarriesTheSequenceNumberAndIsBoundToItsPath() throws {
    let body = try Wire.seal(response: Config.sources, id: "abc123", seq: Config.seq, path: Wire.configPath, key: key)
    let box = try ChaChaPoly.SealedBox(combined: body)
    #expect(throws: (any Error).self) { try ChaChaPoly.open(box, using: key, authenticating: Wire.responseContext(Wire.retrievePath)) }
    let plain = try ChaChaPoly.open(box, using: key, authenticating: Wire.responseContext(Wire.configPath))
    let decoded = try JSONDecoder().decode(Wire.Response<[String: JSON]>.self, from: plain)
    #expect(decoded.id == "abc123")
    #expect(decoded.seq == Config.seq)
    #expect(decoded.data == Config.sources)
}

@Test func jsonValuesSurviveARoundTrip() throws {
    let value: JSON = ["s": "x", "i": 3, "a": [1, "two", .null, .bool(true), .double(1.5)], "o": ["k": []]]
    #expect(try JSONDecoder().decode(JSON.self, from: JSONEncoder().encode(value)) == value)
}
