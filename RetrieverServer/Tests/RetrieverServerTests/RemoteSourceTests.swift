import Foundation
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

// The server's adapter and the module's host, joined by a real XPC
// connection inside the test process. Signature checks need separately
// signed programs and are tested against the installed ones, not here.

/// A module serving `source` on an anonymous listener.
private final class TestModule {
    let listener = NSXPCListener.anonymous()
    let delegate: SourceHost.ConnectionAcceptor

    init(_ source: Source) {
        delegate = SourceHost.ConnectionAcceptor(SourceHost.ExportedSource(source))
        listener.delegate = delegate
        listener.resume()
    }

    var connect: RemoteSource.Connect { { [listener] _, _ in NSXPCConnection(listenerEndpoint: listener.endpoint) } }

    deinit { listener.invalidate() }
}

private func fetched(_ source: Source) async -> Entry {
    await withCheckedContinuation { continuation in source.fetch { continuation.resume(returning: $0) } }
}

@Test func aModuleIsSeenByTheServerAsItsSource() async throws {
    let source = vectorSources[0]   // "numbers"
    let module = TestModule(source)
    let remote = try RemoteSource(serviceName: Signer.moduleIdentifier(for: "numbers"), connect: module.connect)
    #expect(remote.name == "numbers")
    #expect(remote.schema == source.schema)
    #expect(await fetched(remote) == Entry(error: "", data: source.value))
    #expect(await fetched(remote) == Entry(error: "", data: source.value))   // a new connection each time
}

@Test func aModuleCannotServeUnderAnotherSourcesService() {
    let module = TestModule(vectorSources[0])   // says it is "numbers"
    #expect(throws: RemoteSource.Failure.self) {
        try RemoteSource(serviceName: Signer.moduleIdentifier(for: "words"), connect: module.connect)
    }
}

@Test func aModuleThatCannotBeConnectedToIsLeftOut() {
    struct Refused: Error {}
    #expect(throws: RemoteSource.Failure.self) {
        try RemoteSource(serviceName: Signer.moduleIdentifier(for: "numbers"), connect: { _, _ in throw Refused() })
    }
}

@Test func aModuleThatGoesAwayIsReportedInItsEntry() async throws {
    var module: TestModule? = TestModule(vectorSources[0])
    let remote = try RemoteSource(serviceName: Signer.moduleIdentifier(for: "numbers"), connect: module!.connect)
    module!.listener.invalidate()
    module = nil
    let entry = await fetched(remote)
    #expect(entry.error == "module unavailable")
    #expect(entry.data == remote.defaultData)
}

@Test func aModuleThatDoesNotAnswerIsGivenUpOn() {
    final class Silent: NSObject, NSXPCListenerDelegate, SourceService {
        func describe(reply: @escaping (Data) -> Void) {}
        func fetch(reply: @escaping (Data) -> Void) {}
        func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
            connection.exportedInterface = NSXPCInterface(with: SourceService.self)
            connection.exportedObject = self
            connection.resume()
            return true
        }
    }
    let listener = NSXPCListener.anonymous()
    let silent = Silent()
    listener.delegate = silent
    listener.resume()
    let started = Date()
    #expect(throws: RemoteSource.Failure.self) {
        try RemoteSource(serviceName: Signer.moduleIdentifier(for: "numbers"), timeout: 0.3,
                         connect: { _, _ in NSXPCConnection(listenerEndpoint: listener.endpoint) })
    }
    #expect(Date().timeIntervalSince(started) < 2)
    listener.invalidate()
}
