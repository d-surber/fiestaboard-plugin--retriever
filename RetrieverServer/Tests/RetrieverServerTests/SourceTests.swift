import Foundation
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

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
