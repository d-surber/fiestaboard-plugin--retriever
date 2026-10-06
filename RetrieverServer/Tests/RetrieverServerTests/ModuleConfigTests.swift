import CryptoKit
import Foundation
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

private let now = Date(timeIntervalSince1970: 1_800_000_000)
private let day: TimeInterval = 86400
private let key = P256.Signing.PrivateKey()
private let pem = key.publicKey.pemRepresentation

private func config(expiresIn days: Double = 90, modules: [String] = ["local.retriever-source.numbers"]) -> ModuleConfig {
    ModuleConfig(version: 3, expires: now.addingTimeInterval(days * day), modules: modules.map { ModuleConfig.Module(identifier: $0) })
}

private func signature(_ data: Data, with signer: P256.Signing.PrivateKey = key) throws -> Data {
    try signer.signature(for: data).derRepresentation
}

// MARK: Verification

@Test func aSignedUnexpiredConfigIsValid() throws {
    let bytes = config().encoded()
    #expect(ConfigStore.verify(config: bytes, signature: try signature(bytes), publicKeyPEM: pem, now: now) == .valid(config()))
}

@Test func aConfigChangedAfterSigningIsRefused() throws {
    let bytes = config().encoded()
    let altered = config(modules: ["local.retriever-source.numbers", "local.retriever-source.intruder"]).encoded()
    #expect(ConfigStore.verify(config: altered, signature: try signature(bytes), publicKeyPEM: pem, now: now)
            == .invalid("module config signature is not valid"))
}

@Test func aConfigSignedWithAnotherKeyIsRefused() throws {
    let bytes = config().encoded()
    let other = try signature(bytes, with: P256.Signing.PrivateKey())
    #expect(ConfigStore.verify(config: bytes, signature: other, publicKeyPEM: pem, now: now) == .invalid("module config signature is not valid"))
}

@Test func anExpiredConfigIsRefusedEvenThoughItsSignatureIsGood() throws {
    let bytes = config(expiresIn: 90).encoded()
    let later = now.addingTimeInterval(90 * day)
    #expect(ConfigStore.verify(config: bytes, signature: try signature(bytes), publicKeyPEM: pem, now: later) == .invalid("module config expired"))
    #expect(ConfigStore.verify(config: bytes, signature: try signature(bytes), publicKeyPEM: pem, now: later.addingTimeInterval(-1)) == .valid(config()))
}

@Test func thereIsNoUnsignedMode() throws {
    let bytes = config().encoded()
    #expect(ConfigStore.verify(config: bytes, signature: nil, publicKeyPEM: pem, now: now) == .invalid("module config is not signed"))
    #expect(ConfigStore.verify(config: bytes, signature: Data(), publicKeyPEM: pem, now: now) == .invalid("module config signature is not valid"))
    #expect(ConfigStore.verify(config: bytes, signature: try signature(bytes), publicKeyPEM: nil, now: now) == .invalid("no config key"))
    #expect(ConfigStore.verify(config: nil, signature: nil, publicKeyPEM: pem, now: now) == .invalid("no module config"))
    #expect(ConfigStore.verify(config: bytes, signature: try signature(bytes), publicKeyPEM: "not a key", now: now) == .invalid("config key is unreadable"))
}

@Test func aSignedFileThatIsNotAConfigIsRefused() throws {
    let bytes = Data("{\"modules\": \"all of them\"}".utf8)
    #expect(ConfigStore.verify(config: bytes, signature: try signature(bytes), publicKeyPEM: pem, now: now) == .invalid("module config is unreadable"))
}

/// A config signed with `openssl dgst -sha256 -sign`, the way one would be
/// signed away from this Mac. Its key was discarded.
@Test func aConfigSignedWithOpenSSLIsAccepted() throws {
    let bytes = Data("{\"version\": 1, \"expires\": \"2999-01-01T00:00:00Z\", \"modules\": [{\"identifier\": \"local.retriever-source.numbers\"}, {\"identifier\": \"local.retriever-source.words\", \"cdhash\": \"00112233445566778899aabbccddeeff00112233\"}]}".utf8)
    let signed = try #require(Data(base64Encoded: "MEQCIDAG4Hz8yeSaA1HCXHqFbcys6G9B8j88PIQR6d0HDFn0AiABimjaZK5ki8fJlYdey5s2G10fsRt+7eg8wKu6KI1tJQ=="))
    let verdict = ConfigStore.verify(config: bytes, signature: signed, publicKeyPEM: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3q/vzo4mxxnds3LxbyqjRQHmjdg0\nW30nQhGzKYP2zXmKxDFynV75U++K16eNfLPvG0+vpLFdLJ2SnRcrEs+QRw==\n-----END PUBLIC KEY-----\n", now: now)
    guard case .valid(let decoded) = verdict else {
        Issue.record("\(verdict)")
        return
    }
    #expect(decoded.modules == [
        ModuleConfig.Module(identifier: "local.retriever-source.numbers"),
        ModuleConfig.Module(identifier: "local.retriever-source.words", cdhash: "00112233445566778899aabbccddeeff00112233"),
    ])
}

// MARK: Expiry

@Test func theConfigIsValidFor90DaysByDefault() {
    #expect(ModuleConfig.validity == 90 * day)
    #expect(ModuleConfig.warningDays == 14)
}

@Test(arguments: [(90.0, 90, ""), (15.0, 15, ""), (14.9, 14, "module config expires in 14 days"), (14.0, 14, "module config expires in 14 days"),
                  (1.5, 1, "module config expires in 1 day"), (0.5, 0, "module config expires in 0 days")])
func warnsFromFourteenDaysBeforeExpiry(days: Double, remaining: Int, warning: String) {
    let config = config(expiresIn: days)
    #expect(config.daysRemaining(now: now) == remaining)
    #expect(config.warning(now: now) == warning)
}

@Test func configSurvivesEncoding() {
    var original = config(modules: ["a", "b"])
    original.modules[1].cdhash = "abcdef"
    #expect(ModuleConfig.decode(original.encoded()) == original)
}

// MARK: The module_config source

@Test func theConfigSourceReportsExpiryAndStaysQuietUntilTheWarningPeriod() throws {
    let source = ConfigSource()
    source.verdict = .valid(config(expiresIn: 90))
    #expect(source.entry(now: now) == source.succeeded(ConfigSource.Payload(
        expires: ISO8601DateFormatter().string(from: now.addingTimeInterval(90 * day)), days_remaining: 90, warning: "", version: 3)))
    let later = source.entry(now: now.addingTimeInterval(80 * day))
    #expect(later.error == "")
    #expect(later.data == source.succeeded(ConfigSource.Payload(
        expires: ISO8601DateFormatter().string(from: now.addingTimeInterval(90 * day)), days_remaining: 10,
        warning: "module config expires in 10 days", version: 3)).data)
}

@Test func theConfigSourceSaysWhyThereIsNoValidConfig() {
    let source = ConfigSource()
    source.verdict = .invalid("module config signature is not valid")
    #expect(source.entry(now: now) == source.failed("module config signature is not valid"))
    source.verdict = .valid(config(expiresIn: 1))
    #expect(source.entry(now: now.addingTimeInterval(2 * day)) == source.failed("module config expired"))
    #expect(matches(source.defaultData, source.schema))
}

// MARK: Which key is trusted

@Test func aKeyBuiltIntoTheServerIsTheOnlyOneTrusted() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    #expect(ConfigStore.trustedKey(in: directory, builtIn: nil) == nil)
    try Data("FILE KEY".utf8).write(to: directory.appendingPathComponent(ConfigStore.publicKeyFile))
    #expect(ConfigStore.trustedKey(in: directory, builtIn: nil)?.pem == "FILE KEY")
    #expect(ConfigStore.trustedKey(in: directory, builtIn: "BUILT IN")?.pem == "BUILT IN")
    #expect(ConfigStore.builtInKey() == nil)   // the test build has none
}

// MARK: Pinning a build

@Test func aModuleCanBePinnedToOneBuild() throws {
    let signer = "certificate leaf = H\"00112233445566778899aabbccddeeff00112233\""
    #expect(try Signer.requirement(identifier: "local.retriever-source.os", cdhash: nil, signer: signer)
            == "identifier \"local.retriever-source.os\" and \(signer)")
    let pinned = try Signer.requirement(identifier: "local.retriever-source.os", cdhash: "AABBCCDDEEFF00112233445566778899AABBCCDD", signer: signer)
    #expect(pinned == "identifier \"local.retriever-source.os\" and \(signer) and cdhash H\"aabbccddeeff00112233445566778899aabbccdd\"")
    var requirement: SecRequirement?
    #expect(SecRequirementCreateWithString(pinned as CFString, [], &requirement) == errSecSuccess)
}

// MARK: What the server serves

private final class Installation {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    var connected: [[String]] = []
    lazy var state = ServerState(builtIn: [vectorSources[0]], directory: directory, builtInKey: nil) { [unowned self] modules in
        self.connected.append(modules.map(\.identifier))
        return modules.map { FixedSource(name: String($0.identifier.split(separator: ".").last!), schema: ["type": "string"]) }
    }

    init() throws { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true) }
    deinit { try? FileManager.default.removeItem(at: directory) }

    func install(_ config: ModuleConfig, signedWith signer: P256.Signing.PrivateKey = key) throws {
        let bytes = config.encoded()
        try bytes.write(to: directory.appendingPathComponent(ConfigStore.configFile))
        try signer.signature(for: bytes).derRepresentation.write(to: directory.appendingPathComponent(ConfigStore.signatureFile))
        try Data(pem.utf8).write(to: directory.appendingPathComponent(ConfigStore.publicKeyFile))
    }

    var names: [String] { state.sources.map(\.name) }
}

@Test func withoutAConfigOnlyTheBuiltInSourcesAreServed() throws {
    let installation = try Installation()
    #expect(installation.state.refresh(now: now))
    #expect(installation.names == ["numbers", "module_config"])
    #expect(installation.state.verdict == .invalid("no config key"))
    #expect(installation.connected == [[]])
    #expect(!installation.state.refresh(now: now))   // nothing changed
}

@Test func aValidConfigLoadsExactlyTheModulesItLists() throws {
    let installation = try Installation()
    try installation.install(config(modules: ["local.retriever-source.os", "local.retriever-source.words"]))
    installation.state.refresh(now: now)
    #expect(installation.names == ["numbers", "module_config", "os", "words"])
    #expect(installation.connected == [["local.retriever-source.os", "local.retriever-source.words"]])
}

@Test func aNewlyInstalledConfigIsPickedUpAndChangesTheSequenceNumber() throws {
    let installation = try Installation()
    try installation.install(config(modules: ["local.retriever-source.os"]))
    installation.state.refresh(now: now)
    let before = installation.state.config.seq
    try installation.install(config(modules: ["local.retriever-source.os", "local.retriever-source.words"]))
    #expect(installation.state.refresh(now: now))
    #expect(installation.names == ["numbers", "module_config", "os", "words"])
    #expect(installation.state.config.seq != before)
}

@Test func aConfigSignedWithTheWrongKeyLoadsNothing() throws {
    let installation = try Installation()
    try installation.install(config(modules: ["local.retriever-source.os"]), signedWith: P256.Signing.PrivateKey())
    installation.state.refresh(now: now)
    #expect(installation.names == ["numbers", "module_config"])
    #expect(installation.state.verdict == .invalid("module config signature is not valid"))
}

@Test func aModuleThatCouldNotBeReachedIsTriedAgainOnlyWhenARequestArrives() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    var reachable = ["os"]
    var attempts = 0
    let state = ServerState(builtIn: [], directory: directory, builtInKey: nil) { modules in
        attempts += 1
        return modules.map { String($0.identifier.split(separator: ".").last!) }.filter(reachable.contains)
            .map { FixedSource(name: $0, schema: ["type": "string"]) }
    }
    let bytes = config(modules: ["local.retriever-source.os", "local.retriever-source.words"]).encoded()
    try bytes.write(to: directory.appendingPathComponent(ConfigStore.configFile))
    try key.signature(for: bytes).derRepresentation.write(to: directory.appendingPathComponent(ConfigStore.signatureFile))
    try Data(pem.utf8).write(to: directory.appendingPathComponent(ConfigStore.publicKeyFile))

    #expect(state.refresh(now: now))
    #expect(state.sources.map(\.name) == ["module_config", "os"])
    #expect(state.incomplete)
    #expect(!state.refresh(now: now))                    // the minute timer: no retry
    #expect(attempts == 1)
    #expect(!state.refresh(now: now, retryingModules: true))   // a request: tried, still missing, nothing changed
    #expect(attempts == 2)
    reachable.append("words")
    #expect(!state.refresh(now: now))                    // the timer still does not retry
    #expect(attempts == 2)
    #expect(state.refresh(now: now, retryingModules: true))    // a request: now it answers
    #expect(state.sources.map(\.name) == ["module_config", "os", "words"])
    #expect(!state.incomplete)
    #expect(!state.refresh(now: now, retryingModules: true))
    #expect(attempts == 3)                               // all present: nothing left to retry
}

@Test func theServerHasNoSourcesOfItsOwn() {
    #expect(builtInSources.isEmpty)
}

@Test func modulesAreDroppedWhenTheConfigExpires() throws {
    let installation = try Installation()
    try installation.install(config(expiresIn: 5, modules: ["local.retriever-source.os"]))
    installation.state.refresh(now: now)
    #expect(installation.names == ["numbers", "module_config", "os"])
    #expect(!installation.state.refresh(now: now.addingTimeInterval(4 * day)))   // still valid: nothing changes
    #expect(installation.state.refresh(now: now.addingTimeInterval(6 * day)))
    #expect(installation.names == ["numbers", "module_config"])
    #expect(installation.state.verdict == .invalid("module config expired"))
}
