import CryptoKit
import Foundation
import Testing
@testable import RetrieverServer

private let key = SymmetricKey(data: Data(repeating: 7, count: 32))
private let now = Date(timeIntervalSince1970: 1_800_000_000)

private func sealed(_ plaintext: String, key: SymmetricKey = key, context: Data = Wire.requestContext) throws -> Data {
    try ChaChaPoly.seal(Data(plaintext.utf8), using: key, authenticating: context).combined
}

private func request(ts: Int, id: String = "abc123") -> String {
    #"{"ts": \#(ts), "id": "\#(id)"}"#
}

@Test func opensAnAuthenticRequest() throws {
    let body = try sealed(request(ts: 1_800_000_000))
    #expect(try Wire.open(request: body, key: key, now: now) == "abc123")
}

@Test(arguments: [-60, 60]) func acceptsTimestampsWithinTheWindow(offset: Int) throws {
    let body = try sealed(request(ts: 1_800_000_000 + offset))
    #expect(try Wire.open(request: body, key: key, now: now) == "abc123")
}

@Test(arguments: [-61, 61, -86_400]) func refusesStaleTimestamps(offset: Int) throws {
    let body = try sealed(request(ts: 1_800_000_000 + offset))
    #expect(throws: Wire.Failure.stale) { try Wire.open(request: body, key: key, now: now) }
}

@Test func refusesAnotherKey() throws {
    let body = try sealed(request(ts: 1_800_000_000), key: SymmetricKey(data: Data(repeating: 8, count: 32)))
    #expect(throws: Wire.Failure.unauthenticated) { try Wire.open(request: body, key: key, now: now) }
}

@Test func refusesAResponseReplayedAsARequest() throws {
    let body = try sealed(request(ts: 1_800_000_000), context: Wire.responseContext)
    #expect(throws: Wire.Failure.unauthenticated) { try Wire.open(request: body, key: key, now: now) }
}

@Test func refusesATamperedRequest() throws {
    var body = try sealed(request(ts: 1_800_000_000))
    body[body.count / 2] ^= 1
    #expect(throws: Wire.Failure.unauthenticated) { try Wire.open(request: body, key: key, now: now) }
}

@Test(arguments: [Data(), Data(repeating: 0, count: 27), Data("GET /reminders".utf8)])
func refusesBodiesThatAreNotMessages(body: Data) {
    #expect(throws: Wire.Failure.unauthenticated) { try Wire.open(request: body, key: key, now: now) }
}

@Test(arguments: [
    "not json",
    #"{"id": "abc123"}"#,
    #"{"ts": 1800000000}"#,
    #"{"ts": 1800000000, "id": ""}"#,
    #"{"ts": 1800000000, "id": "\#(String(repeating: "x", count: 65))"}"#,
])
func refusesAuthenticButMalformedRequests(plaintext: String) throws {
    let body = try sealed(plaintext)
    #expect(throws: Wire.Failure.malformed) { try Wire.open(request: body, key: key, now: now) }
}

@Test func sealsAResponseThatEchoesTheID() throws {
    let values = ["reminders": ["count": 2]]
    let body = try Wire.seal(response: values, id: "abc123", key: key)
    let plain = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: body), using: key, authenticating: Wire.responseContext)
    let decoded = try JSONDecoder().decode([String: AnyDecodable].self, from: plain)
    #expect(decoded["id"] == .string("abc123"))
    #expect(decoded["data"] == .object(["reminders": .object(["count": .int(2)])]))
}

@Test func usesAFreshNonceForEveryResponse() throws {
    let first = try Wire.seal(response: ["a": 1], id: "abc123", key: key)
    let second = try Wire.seal(response: ["a": 1], id: "abc123", key: key)
    #expect(first.prefix(12) != second.prefix(12))
    #expect(first != second)
}

@Test func acceptsOnlyA32ByteBase64Key() {
    #expect(Wire.key(base64: Data(repeating: 7, count: 32).base64EncodedString()) != nil)
    #expect(Wire.key(base64: Data(repeating: 7, count: 16).base64EncodedString()) == nil)
    #expect(Wire.key(base64: "") == nil)
    #expect(Wire.key(base64: "not base64!") == nil)
}

// MARK: Interop
//
// tests/vectors.json holds messages sealed by each side for the other to
// open. The plugin's tests read the same file.

private struct Vectors: Decodable {
    struct RequestVector: Decodable { let ts: Int; let id: String; let body: String }
    struct ResponseVector: Decodable { let id: String; let body: String }
    let key: String
    let request_from_plugin: RequestVector
    let response_from_server: ResponseVector

    static func load() throws -> Vectors {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("tests/vectors.json")
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }
}

private func bytes(hex: String) -> Data {
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        data.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
    }
    return data
}

@Test func opensARequestSealedByThePlugin() throws {
    let vectors = try Vectors.load()
    let request = vectors.request_from_plugin
    let key = try #require(Wire.key(base64: vectors.key))
    let at = Date(timeIntervalSince1970: TimeInterval(request.ts))
    #expect(try Wire.open(request: bytes(hex: request.body), key: key, now: at) == request.id)
}

@Test func responseVectorIsWhatTheServerSeals() throws {
    let vectors = try Vectors.load()
    let response = vectors.response_from_server
    let key = try #require(Wire.key(base64: vectors.key))
    let box = try ChaChaPoly.SealedBox(combined: bytes(hex: response.body))
    let plain = try ChaChaPoly.open(box, using: key, authenticating: Wire.responseContext)
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let decoded = try decoder.decode(Wire.Response<Values>.self, from: plain)
    #expect(decoded.id == response.id)
    #expect(decoded.data.reminders.error == "")
    #expect(decoded.data.reminders.data.count == 1)
}

/// Just enough JSON to compare a decoded response in the tests above.
private enum AnyDecodable: Decodable, Equatable {
    case string(String)
    case int(Int)
    case object([String: AnyDecodable])

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode(Int.self) { self = .int(value) }
        else { self = .object(try container.decode([String: AnyDecodable].self)) }
    }
}
