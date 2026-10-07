import CryptoKit
import Foundation
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

// A module may be listed in the module config more than once, each time
// under its own name and with its own parameters. To the plugin each is
// simply a source.

/// The moment the tests take to be the present.
private let now = Date(timeIntervalSince1970: 1_800_000_000)

/// A stand-in source that takes two parameters and reports what it was asked.
private struct AskedSource: Source {
    let name = "asked"
    let schema: JSON = ["type": "object", "default": [:]]
    let parametersSchema: JSON = [
        "type": "object",
        "properties": ["what": ["type": "string"], "how_many": ["type": "integer", "minimum": 0, "maximum": 9]],
    ]
    func fetch(parameters: SourceParameters, _ done: @escaping (Entry) -> Void) { done(Entry(error: "", data: .object(parameters))) }
}

/// A module serving `source` on a listener of its own, as a signed module would on its service.
private final class TestModule {
    let listener = NSXPCListener.anonymous()
    let acceptor: SourceHost.ConnectionAcceptor

    init(_ source: Source) {
        acceptor = SourceHost.ConnectionAcceptor(SourceHost.ExportedSource(source))
        listener.delegate = acceptor
        listener.resume()
    }

    var connect: RemoteSource.Connect { { [listener] _, _ in NSXPCConnection(listenerEndpoint: listener.endpoint) } }

    deinit { listener.invalidate() }
}

/// What a source reports when asked once.
private func fetched(_ source: Source) async -> Entry {
    await withCheckedContinuation { continuation in source.fetch(parameters: [:]) { continuation.resume(returning: $0) } }
}

private let serviceName = Signer.moduleIdentifier(for: "asked")

// MARK: What a source declares, and the check against it

@Test func aSourceThatDeclaresNothingTakesNoParameters() {
    let source = vectorSources[0]
    #expect(source.problem(with: [:]) == nil)
    #expect(source.problem(with: ["anything": 1]) == "takes no parameter named \"anything\"")
}

@Test(arguments: [
    (["what": "x", "how_many": 3] as SourceParameters, nil as String?),
    ([:], nil),
    (["which": "x"], "takes no parameter named \"which\" (it takes: how_many, what)"),
    (["what": 3], "the parameter \"what\" must be text, not 3"),
    (["how_many": "3"], "the parameter \"how_many\" must be a whole number, not \"3\""),
    (["how_many": .double(1.5)], "the parameter \"how_many\" must be a whole number, not 1.5"),
    (["how_many": true], "the parameter \"how_many\" must be a whole number, not true"),
    (["how_many": -1], "the parameter \"how_many\" must be at least 0, not -1"),
    (["how_many": 10], "the parameter \"how_many\" must be at most 9, not 10"),
])
func parametersAreCheckedAgainstWhatTheSourceDeclares(parameters: SourceParameters, problem: String?) {
    #expect(AskedSource().problem(with: parameters) == problem)
}

@Test func aSchemaMayRequireAParameterOrLimitItToCertainValues() {
    let schema: JSON = ["type": "object", "required": ["zone"], "properties": ["zone": ["type": "string", "enum": ["north", "south"]]]]
    #expect(ParametersSchema.problem(with: [:], against: schema) == "needs the parameter \"zone\"")
    #expect(ParametersSchema.problem(with: ["zone": "east"], against: schema) == "the parameter \"zone\" must be one of \"north\", \"south\", not \"east\"")
    #expect(ParametersSchema.problem(with: ["zone": "north"], against: schema) == nil)
}

@Test func aSchemasParametersAreSummarisedForThePersonWritingAConfig() {
    let schema: JSON = [
        "type": "object", "required": ["zone"],
        "properties": [
            "zone": ["type": "string", "enum": ["north", "south"], "description": "Which half."],
            "limit": ["type": "integer", "minimum": 1, "maximum": 9, "default": 3],
            "label": ["type": "string"],
        ],
    ]
    #expect(ParametersSchema.summary(of: schema) == [
        "label: text",
        "limit: a whole number, at least 1, at most 9, 3 if left out",
        "zone: one of \"north\", \"south\", required. Which half.",
    ])
    #expect(ParametersSchema.summary(of: ["type": "object"]) == [])
}

// MARK: One module, asked through the server

/// These tests wait on a module's answer. They run one at a time so that
/// their waiting does not use up the threads the answers arrive on.
@Suite(.serialized) struct OneModuleAskedThroughTheServer {
    @Test func anEntryCanGiveItsSourceANameAndSayWhatTheModuleIsAsked() async throws {
        let module = TestModule(AskedSource())
        let remote = try RemoteSource(serviceName: serviceName, name: "three_apples", parameters: ["what": "apples", "how_many": 3], connect: module.connect)
        #expect(remote.name == "three_apples")
        #expect(remote.parameterProblem == nil)
        #expect(remote.parametersSchema == AskedSource().parametersSchema)
        #expect(await fetched(remote) == Entry(error: "", data: ["what": "apples", "how_many": 3]))
    }

    @Test func withoutANameOrParametersASourceIsTheModulesOwnAskedNothing() async throws {
        let module = TestModule(AskedSource())
        let remote = try RemoteSource(serviceName: serviceName, connect: module.connect)
        #expect(remote.name == "asked")
        #expect(await fetched(remote) == Entry(error: "", data: [:]))
    }

    @Test func whoeverAsksCannotChangeWhatTheModuleIsAsked() async throws {
        let module = TestModule(AskedSource())
        let remote = try RemoteSource(serviceName: serviceName, parameters: ["what": "apples"], connect: module.connect)
        let entry = await withCheckedContinuation { continuation in
            remote.fetch(parameters: ["what": "something else", "how_many": 9]) { continuation.resume(returning: $0) }
        }
        #expect(entry == Entry(error: "", data: ["what": "apples"]))
    }

    @Test func parametersTheModuleWillNotTakeAreFoundWhenTheSourceIsSetUpAndThenReportedByIt() async throws {
        let module = TestModule(AskedSource())
        let remote = try RemoteSource(serviceName: serviceName, name: "too_many", parameters: ["how_many": 12], connect: module.connect)
        #expect(remote.parameterProblem == "the parameter \"how_many\" must be at most 9, not 12")
        let entry = await fetched(remote)
        #expect(entry.error == "the parameter \"how_many\" must be at most 9, not 12")
        #expect(entry.data == remote.defaultData)
    }

    @Test func aModuleStillAnswersOnlyForTheSourceItsSignatureNames() {
        let module = TestModule(AskedSource())
        #expect(throws: RemoteSource.Failure.self) {
            try RemoteSource(serviceName: Signer.moduleIdentifier(for: "another"), name: "asked", connect: module.connect)
        }
    }
}

// MARK: The module config

/// A module config whose entries are these, signed and checked as the server checks one.
private func verdict(_ entries: [ModuleConfig.Module]) throws -> ModuleConfigVerdict {
    let key = P256.Signing.PrivateKey()
    let bytes = ModuleConfig(version: 1, expires: now.addingTimeInterval(86400), modules: entries).encoded()
    return ModuleConfigStore.verify(config: bytes, signature: try key.signature(for: bytes).derRepresentation,
                                    publicKeyPEM: key.publicKey.pemRepresentation, now: now)
}

private func calendarEntry(_ name: String?, _ parameters: SourceParameters? = nil) -> ModuleConfig.Module {
    ModuleConfig.Module(identifier: "local.retriever-source.calendar", name: name, parameters: parameters)
}

@Test func aModuleMayBeListedMoreThanOnceUnderDifferentNames() throws {
    let entries = [calendarEntry(nil), calendarEntry("tomorrow", ["days_from_today": 1]), calendarEntry("work_today", ["calendar": "Work"])]
    guard case .valid(let config) = try verdict(entries) else { Issue.record("refused"); return }
    #expect(config.modules == entries)
    #expect(config.modules.map(\.sourceName) == ["calendar", "tomorrow", "work_today"])
}

@Test func twoEntriesCannotHaveOneName() throws {
    #expect(try verdict([calendarEntry("soon", ["days_from_today": 1]), calendarEntry("soon", ["days_from_today": 2])])
            == .invalid("module config lists two sources named \"soon\""))
    #expect(try verdict([calendarEntry(nil), calendarEntry("calendar")]) == .invalid("module config lists two sources named \"calendar\""))
    let os = ModuleConfig.Module(identifier: "local.retriever-source.os")
    #expect(try verdict([os, calendarEntry("os")]) == .invalid("module config lists two sources named \"os\""))
}

@Test(arguments: ["Tomorrow", "two-days", "2day", "", "a b", "caf\u{E9}", "a.b"])
func aSourcesNameIsLowerCaseLettersDigitsAndUnderscores(name: String) throws {
    #expect(ModuleConfig.Module.isSourceName(name) == false)
    #expect(try verdict([calendarEntry(name)]) == .invalid("module config names a source \"\(name)\", which is not a name a source can have"))
}

@Test(arguments: ["error", "server", "module_config"])
func aSourceCannotBeGivenANameThatIsTaken(name: String) throws {
    guard case .invalid(let reason) = try verdict([calendarEntry(name)]) else { Issue.record("\(name) was accepted"); return }
    #expect(reason.contains("a name that is already taken"))
}

@Test func aConfigWrittenBeforeEntriesHadNamesIsReadAsBefore() throws {
    let earlier = Data(#"{"version": 2, "expires": "2027-01-03T00:00:00Z", "modules": [{"identifier": "local.retriever-source.os"}]}"#.utf8)
    let config = try #require(ModuleConfig.decode(earlier))
    #expect(config.modules == [ModuleConfig.Module(identifier: "local.retriever-source.os")])
    #expect(config.modules[0].sourceName == "os")
}

@Test func anEntrysNameAndParametersAreInWhatIsSigned() throws {
    let entry = calendarEntry("tomorrow", ["days_from_today": 1, "calendar": "Work"])
    let written = ModuleConfig(version: 1, expires: now, modules: [entry]).encoded()
    #expect(ModuleConfig.decode(written)?.modules == [entry])
    #expect(String(decoding: written, as: UTF8.self).contains(#""days_from_today" : 1"#))
}

// MARK: What the server serves

@Test func eachEntryOfOneModuleIsServedAsItsOwnSource() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let key = P256.Signing.PrivateKey()
    let entries = [calendarEntry(nil), calendarEntry("tomorrow", ["days_from_today": 1])]
    let bytes = ModuleConfig(version: 1, expires: Date().addingTimeInterval(86400), modules: entries).encoded()
    try bytes.write(to: directory.appendingPathComponent(ModuleConfigStore.configFile))
    try key.signature(for: bytes).derRepresentation.write(to: directory.appendingPathComponent(ModuleConfigStore.signatureFile))
    try Data(key.publicKey.pemRepresentation.utf8).write(to: directory.appendingPathComponent(ModuleConfigStore.publicKeyFile))

    let state = ServerState(builtIn: [], directory: directory, builtInKey: nil) { asked in
        asked.map { FixedSource(name: $0.sourceName, schema: ["type": "object"], value: .object($0.parameters ?? [:])) }
    }
    state.refresh()
    #expect(state.sources.map(\.name) == ["module_config", "calendar", "tomorrow"])
    #expect(state.hasUnreachedModules == false)
    #expect(Set(state.sourceConfig.schemas.keys) == ["module_config", "calendar", "tomorrow"])
}

// MARK: The commands

@Test func aSourceIsNamedAndItsParametersSetOnTheCommandLine() throws {
    let options = try ModuleConfigCommand.Options(["local.retriever-source.calendar", "--name", "tomorrow", "--set", "days_from_today=1", "--set", "calendar=Work"])
    #expect(options.names == ["local.retriever-source.calendar"])
    #expect(options.sourceName == "tomorrow")
    #expect(options.parameters == ["days_from_today": 1, "calendar": "Work"])
    #expect(throws: ModuleConfigCommand.Problem.self) { try ModuleConfigCommand.Options(["--set", "no-equals-sign"]) }
    #expect(throws: ModuleConfigCommand.Problem.self) { try ModuleConfigCommand.Options(["--set", "=value"]) }
    #expect(throws: ModuleConfigCommand.Problem.self) { try ModuleConfigCommand.Options(["--name"]) }
}

@Test(arguments: [
    ("1", JSON.int(1)), ("-3", .int(-3)), ("1.5", .double(1.5)), ("true", .bool(true)), ("false", .bool(false)), ("Work", .string("Work")),
    ("\"1\"", .string("1")), ("\"true\"", .string("true")), ("", .string("")), ("a=b", .string("a=b")), ("nan", .string("nan")), ("True", .string("True")),
])
func aValueTypedOnTheCommandLineIsANumberOrATruthValueIfItReadsAsOne(written: String, value: JSON) {
    #expect(ModuleConfigCommand.parameterValue(written) == value)
}

@Test func aValueMayHaveAnEqualsSignInIt() throws {
    #expect(try ModuleConfigCommand.Options(["--set", "note=a=b"]).parameters == ["note": "a=b"])
}

@Test func allowingASourceReplacesTheEntryOfThatNameAndNoOther() {
    let own = calendarEntry(nil), tomorrow = calendarEntry("tomorrow", ["days_from_today": 1])
    let later = calendarEntry("tomorrow", ["days_from_today": 2])
    #expect(ModuleConfigCommand.allowing([tomorrow], in: [own]) == [own, tomorrow])
    #expect(ModuleConfigCommand.allowing([later], in: [own, tomorrow]) == [own, later])
}

@Test func whatAnEntryAsksIsShownAsItWasTyped() {
    #expect(ModuleConfigCommand.asked(of: calendarEntry(nil)) == "")
    #expect(ModuleConfigCommand.asked(of: calendarEntry("x", ["days_from_today": 1, "calendar": "Work"])) == ", asked calendar=\"Work\" days_from_today=1")
}
