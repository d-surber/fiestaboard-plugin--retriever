import Foundation
import Testing
@testable import RetrieverServer

/// A source that answers with `value` after `delay`, `answers` times.
private struct FakeSource: Source {
    let name: String
    var value: JSON = ["n": 1]
    var delay: TimeInterval = 0
    var answers = 1
    let schema: JSON = ["type": "object", "default": ["n": 0]]

    func fetch(_ done: @escaping (Entry) -> Void) {
        for _ in 0..<answers {
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) { done(succeeded(value)) }
        }
    }
}

private func retrieved(_ sources: [Source], timeout: TimeInterval = 2) async -> [String: Entry] {
    let queue = DispatchQueue(label: "test")
    return await withCheckedContinuation { continuation in
        retrieve(from: sources, timeout: timeout, on: queue) { continuation.resume(returning: $0) }
    }
}

@Test func everySourceGetsAnEntry() async {
    let entries = await retrieved([FakeSource(name: "a"), FakeSource(name: "b", value: ["n": 2], delay: 0.05)])
    #expect(entries == ["a": Entry(error: "", data: ["n": 1]), "b": Entry(error: "", data: ["n": 2])])
}

@Test func aSlowSourceDoesNotHoldUpTheOthers() async {
    let started = Date()
    let entries = await retrieved([FakeSource(name: "fast"), FakeSource(name: "slow", delay: 5)], timeout: 0.2)
    #expect(Date().timeIntervalSince(started) < 2)
    #expect(entries["fast"] == Entry(error: "", data: ["n": 1]))
    #expect(entries["slow"] == Entry(error: "timed out", data: ["n": 0]))
}

@Test func aSourceThatAnswersTwiceIsCountedOnce() async {
    let entries = await retrieved([FakeSource(name: "twice", answers: 2), FakeSource(name: "b", delay: 0.1)])
    #expect(Set(entries.keys) == ["twice", "b"])
}

@Test func noSourcesGivesNoEntries() async {
    #expect(await retrieved([]).isEmpty)
}

@Test func aFailedEntryCarriesTheSchemasDefault() {
    let source = FakeSource(name: "a")
    #expect(source.failed("broken") == Entry(error: "broken", data: ["n": 0]))
    #expect(source.succeeded(["n": 5]) == Entry(error: "", data: ["n": 5]))
}

// MARK: Every real source

/// The property names a schema gives an object.
private func properties(of schema: JSON) -> [String: JSON] {
    guard case .object(let object) = schema, case .object(let properties)? = object["properties"] else { return [:] }
    return properties
}

/// True if `value` has exactly the properties `schema` names, at every level.
private func matches(_ value: JSON, _ schema: JSON) -> Bool {
    guard case .object(let object) = value else { return true }
    let expected = properties(of: schema)
    return Set(object.keys) == Set(expected.keys) && object.allSatisfy { matches($0.value, expected[$0.key] ?? .null) }
}

@Test func everySourceHasADistinctNameAndADefaultThatFitsItsSchema() {
    #expect(Set(allSources.map(\.name)).count == allSources.count)
    for source in allSources {
        #expect(source.defaultData != .null, "\(source.name) has no default")
        #expect(matches(source.defaultData, source.schema), "\(source.name)'s default does not fit its schema")
    }
}

@Test func remindersPayloadFitsItsSchema() throws {
    let source = RemindersSource()
    let item = RemindersSource.Item(title: "Water plants now please", list: "Home", due: Date(), priority: 0)
    let payload = RemindersSource.Payload(items: [item, item, item, item])
    #expect(payload.count == 4)
    #expect(payload.items.first?.title == "Water plants now please")   // as written: the server does no formatting
    let data = try #require(JSON(encoding: payload))
    #expect(matches(data, source.schema))
    guard case .object(let object) = data, case .array(let items)? = object["items"], let first = items.first,
          case .object(let itemsSchema)? = properties(of: source.schema)["items"], let itemSchema = itemsSchema["items"]
    else {
        Issue.record("payload or schema is not shaped as expected")
        return
    }
    #expect(matches(first, itemSchema))
    #expect(try JSONDecoder().decode(RemindersSource.Payload.self, from: JSONEncoder().encode(source.defaultData)).items.isEmpty)
}

// MARK: Music

private let playing = MusicSource.Payload(state: "playing", title: "So What", artist: "Miles Davis", album: "Kind of Blue")

@Test func musicPayloadAndDefaultFitTheSchema() throws {
    let source = MusicSource()
    #expect(matches(try #require(JSON(encoding: playing)), source.schema))
    let nothing = try JSONDecoder().decode(MusicSource.Payload.self, from: JSONEncoder().encode(source.defaultData))
    #expect(nothing == MusicSource.Payload())
}

@Test func remindersReportsDataNotAPresentationOfIt() {
    let source = RemindersSource()
    #expect(Set(properties(of: source.schema).keys) == ["count", "items"])
    #expect(source.defaultData == ["count": 0, "items": []])
}

@Test func musicReportsOnlyTheCurrentTrack() {
    #expect(Set(properties(of: MusicSource().schema).keys) == ["state", "title", "artist", "album"])
}

@Test func musicReportsWhatTheScriptPrinted() throws {
    let source = MusicSource()
    let output = try JSONEncoder().encode(playing)
    #expect(source.entry(status: 0, terminated: false, output: output, errors: "") == source.succeeded(playing))
}

@Test func musicReportsWhyItCouldNotBeRead() {
    let source = MusicSource()
    let denied = "execution error: Error: Error: Not authorized to send Apple events to Music. (-1743)"
    #expect(source.entry(status: 1, terminated: false, output: Data(), errors: denied) == source.failed("not allowed to control Music"))
    #expect(source.entry(status: 15, terminated: true, output: Data(), errors: "") == source.failed("Music did not answer"))
    #expect(source.entry(status: 1, terminated: false, output: Data(), errors: "syntax error") == source.failed("Music could not be read"))
    #expect(source.entry(status: 0, terminated: false, output: Data("not json".utf8), errors: "") == source.failed("Music could not be read"))
}
