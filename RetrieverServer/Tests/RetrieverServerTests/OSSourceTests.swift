import Foundation
import Testing
@testable import RetrieverSourceOS
@testable import RetrieverSourceKit

@Test func osReportsTheRunningVersionOfMacOS() async throws {
    let source = OSSource()
    let entry = await withCheckedContinuation { continuation in source.fetch { continuation.resume(returning: $0) } }
    #expect(entry.error == "")
    #expect(matches(entry.data, source.schema))
    let payload = try JSONDecoder().decode(OSSource.Payload.self, from: JSONEncoder().encode(entry.data))
    let running = ProcessInfo.processInfo.operatingSystemVersion
    #expect(payload.version == "\(running.majorVersion).\(running.minorVersion).\(running.patchVersion)")
    #expect(!payload.build.isEmpty)
    #expect(ProcessInfo.processInfo.operatingSystemVersionString.contains(payload.build))
}

@Test func osDefaultIsEmpty() {
    #expect(OSSource().defaultData == ["version": "", "build": ""])
}

@Test func oSSourceFitsTheSourceContract() {
    #expect(fitsTheSourceContract(OSSource()))
}
