import Foundation
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

// MARK: Where things go

@Test func everythingThatDecidesWhatRunsIsInRootOwnedPlaces() {
    #expect(Installation.programs.path == "/Library/Application Support/Retriever/bin")
    #expect(Installation.agentFile("local.retriever-server").path == "/Library/LaunchAgents/local.retriever-server.plist")
    #expect(ConfigStore.installed.path == "/Library/Application Support/Retriever")
}

@Test func theTransportKeyIsInTheAccountsOwnFolder() {
    let home = URL(fileURLWithPath: "/Users/someone", isDirectory: true)
    #expect(Installation.transportKeyFile(home: home).path == "/Users/someone/Library/Application Support/Retriever/transport.key")
}

@Test func aNewTransportKeyIsOneTheServerAccepts() {
    let first = Installation.newTransportKey(), second = Installation.newTransportKey()
    #expect(Wire.key(base64: first) != nil)
    #expect(first != second)
}

@Test func theTransportKeyIsReadWithoutItsTrailingNewline() throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: home) }
    #expect(Installation.transportKey(home: home) == nil)
    let file = Installation.transportKeyFile(home: home)
    try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
    let key = Installation.newTransportKey()
    try Data((key + "\n").utf8).write(to: file)
    #expect(Installation.transportKey(home: home) == key)
}

// MARK: Launchd agents

@Test func theServerAgentStartsAtLoginAndCarriesNoSecrets() throws {
    let agent = Installation.serverAgent(program: "/x/RetrieverServer")
    #expect(agent["Label"] as? String == "local.retriever-server")
    #expect(agent["ProgramArguments"] as? [String] == ["/x/RetrieverServer"])
    #expect(agent["RunAtLoad"] as? Bool == true)
    #expect((agent["KeepAlive"] as? [String: Bool]) == ["SuccessfulExit": false])   // an account with no key is left alone
    #expect(agent["EnvironmentVariables"] == nil)
    _ = try PropertyListSerialization.data(fromPropertyList: agent, format: .xml, options: 0)
}

@Test func aModuleAgentIsStartedOnDemandUnderItsIdentifier() throws {
    let agent = Installation.moduleAgent(identifier: "local.retriever-source.os", program: "/x/RetrieverSourceOS")
    #expect(agent["Label"] as? String == "local.retriever-source.os")
    #expect((agent["MachServices"] as? [String: Bool]) == ["local.retriever-source.os": true])
    #expect(agent["RunAtLoad"] == nil)
    _ = try PropertyListSerialization.data(fromPropertyList: agent, format: .xml, options: 0)
}

// MARK: Which programs are modules

@Test func moduleCandidatesAreChosenByNameAndTheSignatureDecides() throws {
    #expect(Installation.moduleCandidates(in: ["RetrieverServer", "RetrieverSourceOS", "RetrieverSourceKit.build", "RetrieverSourceOS.dSYM",
                                               "RetrieverSourceMusic", "notes.txt"]) == ["RetrieverSourceMusic", "RetrieverSourceOS"])

    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    for name in ["RetrieverSourceGood", "RetrieverSourceForeign", "RetrieverSourceNotAModule", "RetrieverSourceData"] {
        let path = directory.appendingPathComponent(name).path
        FileManager.default.createFile(atPath: path, contents: Data("x".utf8),
                                       attributes: [.posixPermissions: name == "RetrieverSourceData" ? 0o644 : 0o755])
    }
    try FileManager.default.createDirectory(at: directory.appendingPathComponent("RetrieverSourceFolder"), withIntermediateDirectories: true)

    let found = Installation.modules(in: directory) { path in
        switch URL(fileURLWithPath: path).lastPathComponent {
        case "RetrieverSourceGood": return Signer.Program(path: path, identifier: "local.retriever-source.good", cdhash: "aa")
        case "RetrieverSourceNotAModule": return Signer.Program(path: path, identifier: "local.retriever-server", cdhash: "bb")
        default: throw Signer.Failure.notOurs(path)
        }
    }
    #expect(found.accepted.map(\.identifier) == ["local.retriever-source.good"])
    #expect(found.refused == ["RetrieverSourceForeign", "RetrieverSourceNotAModule"])   // not executable or a folder: not even candidates
}

@Test func aFileThatIsNotASignedProgramIsNotOurs() throws {
    let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try Data("not a program".utf8).write(to: file)
    defer { try? FileManager.default.removeItem(at: file) }
    #expect(throws: (any Error).self) { try Signer.inspect(file.path) }
    #expect(throws: (any Error).self) { try Signer.inspect("/nonexistent/program") }
}

// MARK: Config commands

@Test func configOptionsAreReadFromTheArguments() throws {
    let plain = try ConfigCommand.Options(["a", "b"])
    #expect(plain.names == ["a", "b"])
    #expect(plain.days == 90)
    #expect(!plain.pin)
    let full = try ConfigCommand.Options(["--pin", "a", "--days", "30"])
    #expect(full.names == ["a"])
    #expect(full.days == 30)
    #expect(full.pin)
    #expect(throws: ConfigCommand.Problem.self) { try ConfigCommand.Options(["--days"]) }
    #expect(throws: ConfigCommand.Problem.self) { try ConfigCommand.Options(["--days", "0"]) }
}

@Test func allowingAModuleAddsItOrReplacesItsEntry() {
    let os = ModuleConfig.Module(identifier: "local.retriever-source.os")
    let music = ModuleConfig.Module(identifier: "local.retriever-source.music")
    let pinned = ModuleConfig.Module(identifier: "local.retriever-source.os", cdhash: "abc")
    #expect(ConfigCommand.allowing([music], in: [os]) == [os, music])
    #expect(ConfigCommand.allowing([pinned], in: [os, music]) == [music, pinned])
    #expect(ConfigCommand.allowing([os], in: [pinned]) == [os])   // unpinning is adding again without --pin
}

// MARK: Help

@Test func helpDescribesEveryCommand() {
    let help = Help.text(program: "/x/RetrieverServer")
    for command in ["install", "config sign", "config install", "config add", "config remove", "status", "help", "--pin", "--days"] {
        #expect(help.contains(command), "help does not mention \(command)")
    }
    for place in [Installation.programs.path, ConfigStore.installed.path, Installation.launchAgents.path, "transport.key", "RetrieverServer.log"] {
        #expect(help.contains(place), "help does not mention \(place)")
    }
    #expect(help.contains("sudo"))
    #expect(help.contains("\(ModuleConfig.warningDays) days"))
}
