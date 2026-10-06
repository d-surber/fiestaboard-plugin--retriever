import Foundation
import Testing
@testable import RetrieverSourceMusic
@testable import RetrieverSourceKit

/// What the source reports while a track is playing.
private let playing = MusicSource.Payload(state: "playing", title: "So What", artist: "Miles Davis", album: "Kind of Blue")

@Test func musicPayloadAndDefaultFitTheSchema() throws {
    let source = MusicSource()
    #expect(matches(try #require(JSON(encoding: playing)), source.schema))
    let nothing = try JSONDecoder().decode(MusicSource.Payload.self, from: JSONEncoder().encode(source.defaultData))
    #expect(nothing == MusicSource.Payload())
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

@Test func musicSourceFitsTheSourceContract() {
    #expect(fitsTheSourceContract(MusicSource()))
}
