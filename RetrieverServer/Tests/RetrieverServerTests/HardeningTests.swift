import CryptoKit
import Foundation
import Security
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

/// The moment the tests take to be the present.
private let now = Date(timeIntervalSince1970: 1_800_000_000)
/// A signer's part of a requirement, naming a certificate that signed nothing here.
private let someSigner = "certificate leaf = H\"00112233445566778899aabbccddeeff00112233\""

// MARK: Nothing unchecked goes into a code-signing requirement

/// An identifier that closes its own quote and adds a clause. In a
/// requirement "and" binds tighter than "or", so the someSigner's part would
/// apply to the second clause only and the first would stand alone.
private let rewriting = "local.retriever-source.os\" or identifier \"local.retriever-source.os"

@Test func theHazardIsReal() throws {
    // /bin/ls is signed by Apple, not by the made-up certificate below, and
    // still satisfies a requirement written the way an unchecked identifier
    // would have had it written.
    var code: SecStaticCode?
    try #require(SecStaticCodeCreateWithPath(URL(fileURLWithPath: "/bin/ls") as CFURL, [], &code) == errSecSuccess)
    func satisfies(_ text: String) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement, let code else { return false }
        return SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
    #expect(satisfies("identifier \"com.apple.ls\" and \(someSigner)") == false)
    #expect(satisfies("identifier \"com.apple.ls\" or identifier \"com.apple.ls\" and \(someSigner)"))
}

@Test(arguments: [rewriting, "a\"b", "a b", "", "a\\b", "caf\u{E9}"])
func aRequirementIsNotWrittenForTextThatIsNotAnIdentifier(identifier: String) {
    #expect(throws: Signer.Failure.notAnIdentifier(identifier)) {
        try Signer.requirement(identifier: identifier, cdhash: nil, signer: someSigner)
    }
}

@Test(arguments: ["abc", "aabbccddeeff00112233445566778899aabbccdd\" or anchor apple", "aabbccddeeff00112233445566778899aabbccd", "zzbbccddeeff00112233445566778899aabbccdd"])
func aRequirementIsNotWrittenForTextThatIsNotACodeHash(cdhash: String) {
    #expect(throws: Signer.Failure.notACodeHash(cdhash)) {
        try Signer.requirement(identifier: "local.retriever-source.os", cdhash: cdhash, signer: someSigner)
    }
}

@Test func moduleIdentifiersHaveOneForm() {
    for good in ["local.retriever-source.os", "local.retriever-source.air-quality", "local.retriever-source.zone2"] {
        #expect(Signer.isModuleIdentifier(good), "\(good)")
    }
    for bad in ["local.retriever-source.", "local.retriever-server", "local.retriever-source.OS", "local.retriever-source.a.b",
                "local.retriever-source.a b", "com.example.thing", rewriting] {
        #expect(Signer.isModuleIdentifier(bad) == false, "\(bad)")
    }
}

@Test func aSignedConfigListingSomethingThatIsNotAModuleIsRefused() throws {
    let key = P256.Signing.PrivateKey()
    func verdict(_ modules: [ModuleConfig.Module]) throws -> ModuleConfigVerdict {
        let bytes = ModuleConfig(version: 1, expires: now.addingTimeInterval(86400), modules: modules).encoded()
        return ModuleConfigStore.verify(config: bytes, signature: try key.signature(for: bytes).derRepresentation,
                                  publicKeyPEM: key.publicKey.pemRepresentation, now: now)
    }
    let os = ModuleConfig.Module(identifier: "local.retriever-source.os")
    #expect(try verdict([os, ModuleConfig.Module(identifier: rewriting)])
            == .invalid("module config lists \"\(rewriting)\", which is not a module's identifier"))
    #expect(try verdict([ModuleConfig.Module(identifier: "local.retriever-source.os", cdhash: "abc")])
            == .invalid("module config pins local.retriever-source.os to \"abc\", which is not a code hash"))
    let pinned = ModuleConfig.Module(identifier: "local.retriever-source.os", cdhash: "AABBCCDDEEFF00112233445566778899AABBCCDD")
    #expect(try verdict([pinned]) == .valid(ModuleConfig(version: 1, expires: now.addingTimeInterval(86400), modules: [pinned])))
}

// MARK: Which config key an install trusts

/// Two config keys, as PEM: the one taken to be installed, and a different one.
private let installedKey = P256.Signing.PrivateKey().publicKey.pemRepresentation
private let otherKey = P256.Signing.PrivateKey().publicKey.pemRepresentation

@Test func aConfigNeverBringsADifferentKeyWithItUnasked() throws {
    #expect(throws: ModuleConfigStore.KeyRefusal.differentKey) {
        try ModuleConfigStore.keyToTrust(builtIn: nil, installed: installedKey, waiting: otherKey, replacingKey: false)
    }
    #expect(try ModuleConfigStore.keyToTrust(builtIn: nil, installed: installedKey, waiting: otherKey, replacingKey: true) == .replacement(otherKey))
}

@Test func theInstalledKeyIsKeptWhenTheConfigComesWithTheSameOneOrNone() throws {
    #expect(try ModuleConfigStore.keyToTrust(builtIn: nil, installed: installedKey, waiting: installedKey, replacingKey: false) == .installed(installedKey))
    #expect(try ModuleConfigStore.keyToTrust(builtIn: nil, installed: installedKey, waiting: installedKey + "\n", replacingKey: false) == .installed(installedKey))
    #expect(try ModuleConfigStore.keyToTrust(builtIn: nil, installed: installedKey, waiting: nil, replacingKey: false) == .installed(installedKey))
    #expect(try ModuleConfigStore.keyToTrust(builtIn: nil, installed: installedKey, waiting: installedKey, replacingKey: true) == .installed(installedKey))
}

@Test func theFirstKeyComesWithTheFirstConfig() throws {
    #expect(try ModuleConfigStore.keyToTrust(builtIn: nil, installed: nil, waiting: otherKey, replacingKey: false) == .first(otherKey))
    #expect(throws: ModuleConfigStore.KeyRefusal.noKey) { try ModuleConfigStore.keyToTrust(builtIn: nil, installed: nil, waiting: nil, replacingKey: false) }
}

@Test func aKeyBuiltIntoTheServerIsTheOnlyOne() throws {
    #expect(try ModuleConfigStore.keyToTrust(builtIn: installedKey, installed: otherKey, waiting: otherKey, replacingKey: true) == .builtIn(installedKey))
}

@Test func onlyANewKeyIsInstalledWithAConfig() {
    #expect(ModuleConfigStore.KeyToTrust.first(otherKey).isInstalledWithTheConfig)
    #expect(ModuleConfigStore.KeyToTrust.replacement(otherKey).isInstalledWithTheConfig)
    #expect(ModuleConfigStore.KeyToTrust.installed(otherKey).isInstalledWithTheConfig == false)
    #expect(ModuleConfigStore.KeyToTrust.builtIn(otherKey).isInstalledWithTheConfig == false)
}

@Test func aKeysFingerprintIsShortStableAndItsOwn() throws {
    let fingerprint = try #require(ModuleConfigStore.keyFingerprint(pem: installedKey))
    #expect(fingerprint.count == 19)   // sixteen digits in fours
    #expect(fingerprint == ModuleConfigStore.keyFingerprint(pem: installedKey + "\n"))
    #expect(fingerprint != ModuleConfigStore.keyFingerprint(pem: otherKey))
    #expect(ModuleConfigStore.keyFingerprint(pem: "not a key") == nil)
}

@Test func replacingTheKeyHasToBeAskedForByName() throws {
    #expect(try ModuleConfigCommand.Options([]).replaceKey == false)
    #expect(try ModuleConfigCommand.Options(["--replace-key"]).replaceKey)
}

// MARK: The installer checks the copy, not the original

/// A folder standing in for the root-owned programs folder, and one for the
/// folder the programs come from, which its owner can still change.
private final class Folders {
    let programs = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    let source = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)

    init() throws {
        for folder in [programs, source] { try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true) }
    }

    deinit { for folder in [programs, source] { try? FileManager.default.removeItem(at: folder) } }

    /// What is in the programs folder now, in order.
    func installedNames() -> [String] { ((try? FileManager.default.contentsOfDirectory(atPath: programs.path)) ?? []).sorted() }
}

/// The contents of the one program the stand-in signature check accepts.
private let genuineProgram = Data("genuine program".utf8)

/// Stands in for reading a signature: only the genuineProgram bytes are "signed".
private func inspectingBytes(as identifier: String) -> (String) throws -> Signer.Program {
    { path in
        guard try Data(contentsOf: URL(fileURLWithPath: path)) == genuineProgram else { throw Signer.Failure.notOurs(path) }
        return Signer.Program(path: path, identifier: identifier, cdhash: "00")
    }
}

@Test func whatIsCheckedIsTheCopyInThePlaceOnlyRootCanChange() throws {
    let folders = try Folders()
    let original = folders.source.appendingPathComponent("RetrieverSourceOS")
    try genuineProgram.write(to: original)
    var inspected: [String] = []
    let installed = try Installation.installProgram(from: original.path, into: folders.programs, as: "RetrieverSourceOS",
                                                    expecting: "local.retriever-source.os", owner: nil) { path in
        inspected.append(path)
        return try inspectingBytes(as: "local.retriever-source.os")(path)
    }
    #expect(inspected.count == 1)
    #expect(inspected[0].hasPrefix(folders.programs.path))
    #expect(installed == folders.programs.appendingPathComponent("RetrieverSourceOS").path)
    #expect(try Data(contentsOf: URL(fileURLWithPath: installed)) == genuineProgram)
    #expect(FileManager.default.isExecutableFile(atPath: installed))
    #expect(folders.installedNames() == ["RetrieverSourceOS"])
}

@Test func aProgramSwappedAfterItWasLookedAtIsNotInstalled() throws {
    let folders = try Folders()
    let earlier = folders.programs.appendingPathComponent("RetrieverSourceOS")
    try genuineProgram.write(to: earlier)                       // an earlier, good install
    let original = folders.source.appendingPathComponent("RetrieverSourceOS")
    try Data("something else".utf8).write(to: original)  // what is there by the time it is copied

    #expect(throws: Installation.ProgramRefusal.notSignedByThisSigner("RetrieverSourceOS")) {
        try Installation.installProgram(from: original.path, into: folders.programs, as: "RetrieverSourceOS",
                                        expecting: "local.retriever-source.os", owner: nil,
                                        inspect: inspectingBytes(as: "local.retriever-source.os"))
    }
    #expect(try Data(contentsOf: earlier) == genuineProgram)    // the earlier install stands
    #expect(folders.installedNames() == ["RetrieverSourceOS"])    // and nothing is left lying beside it
}

@Test func aProgramSignedAsSomethingElseIsNotInstalledInItsPlace() throws {
    let folders = try Folders()
    let original = folders.source.appendingPathComponent("RetrieverServer")
    try genuineProgram.write(to: original)
    #expect(throws: Installation.ProgramRefusal.signedAs("local.retriever-source.os", expected: "local.retriever-server")) {
        try Installation.installProgram(from: original.path, into: folders.programs, as: "RetrieverServer",
                                        expecting: "local.retriever-server", owner: nil,
                                        inspect: inspectingBytes(as: "local.retriever-source.os"))
    }
    #expect(folders.installedNames().isEmpty)
}

@Test func aLinkIsInstalledAsTheProgramItPointsToNotAsALink() throws {
    let folders = try Folders()
    let target = folders.source.appendingPathComponent("the real file")
    try genuineProgram.write(to: target)
    let link = folders.source.appendingPathComponent("RetrieverSourceOS")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

    let installed = try Installation.installProgram(from: link.path, into: folders.programs, as: "RetrieverSourceOS",
                                                    expecting: "local.retriever-source.os", owner: nil,
                                                    inspect: inspectingBytes(as: "local.retriever-source.os"))
    let type = try FileManager.default.attributesOfItem(atPath: installed)[.type] as? FileAttributeType
    #expect(type == .typeRegular)
    try Data("changed afterwards".utf8).write(to: target)
    #expect(try Data(contentsOf: URL(fileURLWithPath: installed)) == genuineProgram)
}

// MARK: Acting in the account's folder with the account's access

@Test func theAccountThatRanSudoIsFoundFromTheEnvironment() throws {
    let name = NSUserName()
    let account = try #require(InvokingAccount.fromSudo(environment: ["SUDO_USER": name]))
    #expect(account.uid == getuid())
    #expect(account.home.path == NSHomeDirectory())
    #expect(InvokingAccount.fromSudo(environment: [:]) == nil)
    #expect(InvokingAccount.fromSudo(environment: ["SUDO_USER": "no-such-account-\(UUID().uuidString)"]) == nil)
}

@Test func aProgramThatIsNotRootHasNothingToGiveUp() throws {
    let account = try #require(InvokingAccount.fromSudo(environment: ["SUDO_USER": NSUserName()]))
    #expect(try account.withItsAccess { geteuid() } == getuid())
    #expect(throws: CocoaError.self) { try account.withItsAccess { throw CocoaError(.fileNoSuchFile) } }
}

@Test func aNewTransportKeyIsWrittenForItsOwnerOnly() throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    defer { try? FileManager.default.removeItem(at: home) }
    let note = try InstallCommand.ensureTransportKey(home: home)
    let key = try #require(Installation.transportKey(home: home))
    #expect(Wire.transportKey(base64: key) != nil)
    #expect(note.contains(key))
    let file = Installation.transportKeyFile(home: home)
    #expect(try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? Int == 0o600)
    #expect(try FileManager.default.attributesOfItem(atPath: file.deletingLastPathComponent().path)[.posixPermissions] as? Int == 0o700)
    #expect(try InstallCommand.ensureTransportKey(home: home) == "The transport key is unchanged.")
    #expect(Installation.transportKey(home: home) == key)
}

// MARK: A request is answered once

@Test func aRequestIDIsRememberedForAsLongAsACopyCouldBeSentAgain() {
    var answered = AnsweredRequests()
    let period = answered.remembersFor
    #expect(period > 2 * Wire.maxClockDifference)
    let admitted = [
        answered.admit("a", now: now),
        answered.admit("b", now: now),
        answered.admit("a", now: now.addingTimeInterval(1)),
        answered.admit("a", now: now.addingTimeInterval(period - 1)),
        answered.admit("a", now: now.addingTimeInterval(period + 1)),
    ]
    #expect(admitted == [true, true, false, false, true])
}

@Test func theMemoryOfRequestsIsBounded() {
    var answered = AnsweredRequests(remembersFor: 100, capacity: 8)
    var everyNewOneWasAdmitted = true
    for number in 0..<1000 where !answered.admit("id-\(number)", now: now.addingTimeInterval(Double(number) / 1000)) {
        everyNewOneWasAdmitted = false
    }
    #expect(everyNewOneWasAdmitted)
    let theLatestAgain = answered.admit("id-999", now: now.addingTimeInterval(1))
    #expect(theLatestAgain == false)   // the latest are still remembered
    let aNewOneLater = answered.admit("a-new-one", now: now.addingTimeInterval(200))
    #expect(aNewOneLater)
}

// MARK: Source names

@Test func aConfigListingAModuleTwiceOrUnderAReservedNameIsRefused() throws {
    let key = P256.Signing.PrivateKey()
    func verdict(_ identifiers: [String]) throws -> ModuleConfigVerdict {
        let modules = identifiers.map { ModuleConfig.Module(identifier: $0) }
        let bytes = ModuleConfig(version: 1, expires: now.addingTimeInterval(86400), modules: modules).encoded()
        return ModuleConfigStore.verify(config: bytes, signature: try key.signature(for: bytes).derRepresentation,
                                  publicKeyPEM: key.publicKey.pemRepresentation, now: now)
    }
    #expect(try verdict(["local.retriever-source.os", "local.retriever-source.music", "local.retriever-source.os"])
            == .invalid("module config lists local.retriever-source.os twice"))
    for reserved in Wire.reservedSourceNames {
        guard case .invalid(let reason) = try verdict(["local.retriever-source.\(reserved)"]) else { Issue.record("\(reserved) was accepted"); continue }
        #expect(reason.contains("a name the plugin keeps for itself"))
    }
    #expect(Wire.reservedSourceNames == ["error", "server"])
}

@Test func twoSourcesOfOneNameDoNotMakeARetrieveWaitOutItsTime() async {
    let sources = [FixedSource(name: "same", schema: ["type": "string"], value: "first"),
                   FixedSource(name: "same", schema: ["type": "string"], value: "second"),
                   FixedSource(name: "other", schema: ["type": "string"], value: "x")]
    let started = Date()
    let queue = DispatchQueue(label: "duplicate names")
    let entries = await withCheckedContinuation { continuation in
        retrieve(from: sources, timeout: 5, on: queue) { continuation.resume(returning: $0) }
    }
    #expect(Date().timeIntervalSince(started) < 2)
    #expect(Set(entries.keys) == ["same", "other"])
}

// MARK: A module that does not answer delays nothing but itself

/// A folder holding a signed module config, as the server reads one.
private final class ConfigFolder {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    private let key = P256.Signing.PrivateKey()

    init(allowing names: [String]) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let modules = names.map { ModuleConfig.Module(identifier: Signer.moduleIdentifier(for: $0)) }
        let bytes = ModuleConfig(version: 1, expires: Date().addingTimeInterval(86400), modules: modules).encoded()
        try bytes.write(to: directory.appendingPathComponent(ModuleConfigStore.configFile))
        try key.signature(for: bytes).derRepresentation.write(to: directory.appendingPathComponent(ModuleConfigStore.signatureFile))
        try Data(key.publicKey.pemRepresentation.utf8).write(to: directory.appendingPathComponent(ModuleConfigStore.publicKeyFile))
    }

    deinit { try? FileManager.default.removeItem(at: directory) }
}

/// A stand-in for the source a module would provide, named as its identifier says.
private func source(for module: ModuleConfig.Module) -> Source {
    FixedSource(name: String(module.identifier.dropFirst(Signer.moduleIdentifierPrefix.count)), schema: ["type": "string"])
}

/// The names of the modules among what a state serves; the config's own source is not one.
private func moduleNames(_ state: ServerState) -> [String] {
    state.sources.map(\.name).filter { $0 != "module_config" }
}

/// Waits, off the server's queue, until `condition` holds there or `seconds` pass.
private func eventually(on queue: DispatchQueue, within seconds: Double = 5, _ condition: @escaping () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if queue.sync(execute: condition) { return true }
        Thread.sleep(forTimeInterval: 0.02)
    }
    return false
}

@Test func theServersQueueIsNotHeldWhileAModuleIsWaitedFor() throws {
    let folder = try ConfigFolder(allowing: ["quick", "stuck"])
    let serverQueue = DispatchQueue(label: "server"), elsewhere = DispatchQueue(label: "elsewhere")
    let release = DispatchSemaphore(value: 0)
    let state = ServerState(builtIn: [], directory: folder.directory, builtInKey: nil, background: (elsewhere, returningTo: serverQueue)) { modules in
        release.wait()   // a module that is not answering
        return modules.map(source(for:))
    }

    let started = Date()
    serverQueue.sync { _ = state.refresh() }
    #expect(Date().timeIntervalSince(started) < 1)
    #expect(serverQueue.sync { moduleNames(state) } == [])
    #expect(serverQueue.sync { state.hasUnreachedModules })

    release.signal()
    #expect(eventually(on: serverQueue) { moduleNames(state) == ["quick", "stuck"] })
    #expect(serverQueue.sync { state.hasUnreachedModules } == false)
}

@Test func onlyTheModulesNotYetReachedAreAskedAgainAndOneAskingAtATime() throws {
    let folder = try ConfigFolder(allowing: ["os", "words"])
    let serverQueue = DispatchQueue(label: "server"), elsewhere = DispatchQueue(label: "elsewhere")
    let lock = NSLock()
    var asked: [[String]] = []
    var reachable = ["os"]
    let state = ServerState(builtIn: [], directory: folder.directory, builtInKey: nil, background: (elsewhere, returningTo: serverQueue)) { modules in
        let names = modules.map { String($0.identifier.dropFirst(Signer.moduleIdentifierPrefix.count)) }
        let canReach = lock.withLock { asked.append(names); return reachable }
        Thread.sleep(forTimeInterval: 0.2)
        return modules.map(source(for:)).filter { canReach.contains($0.name) }
    }

    serverQueue.sync { _ = state.refresh() }
    #expect(eventually(on: serverQueue) { moduleNames(state) == ["os"] })
    #expect(serverQueue.sync { state.hasUnreachedModules })

    lock.withLock { reachable = ["os", "words"] }
    // Three requests in a row, as one fetch by the plugin makes.
    serverQueue.sync { for _ in 0..<3 { state.refresh(retryingModules: true) } }
    #expect(eventually(on: serverQueue) { moduleNames(state) == ["os", "words"] })
    #expect(lock.withLock { asked } == [["os", "words"], ["words"]])
}

@Test func atStartupTheModulesAreWaitedFor() throws {
    let folder = try ConfigFolder(allowing: ["os"])
    let serverQueue = DispatchQueue(label: "server"), elsewhere = DispatchQueue(label: "elsewhere")
    let state = ServerState(builtIn: [], directory: folder.directory, builtInKey: nil, background: (elsewhere, returningTo: serverQueue)) { modules in
        Thread.sleep(forTimeInterval: 0.2)
        return modules.map(source(for:))
    }
    #expect(serverQueue.sync { state.refresh(waiting: true) })
    #expect(serverQueue.sync { moduleNames(state) } == ["os"])
}

@Test func aSecondSourceOfANameAlreadyServedIsLeftOut() throws {
    let folder = try ConfigFolder(allowing: ["numbers"])
    let state = ServerState(builtIn: [vectorSources[0]], directory: folder.directory, builtInKey: nil) { $0.map(source(for:)) }
    state.refresh()
    #expect(state.sources.map(\.name) == ["numbers", "module_config"])
    #expect(state.sources[0].schema == vectorSources[0].schema)   // the first of the name is the one kept
}
