import CryptoKit
import Foundation
import Testing
@testable import RetrieverServer
@testable import RetrieverSourceKit

private let key = SymmetricKey(data: Data(repeating: 7, count: 32))
private let now = Date(timeIntervalSince1970: 1_800_000_000)

private func request(_ path: String, protocol requested: Int? = nil) throws -> Data {
    let field = requested.map { #", "required_protocol_version": \#($0)"# } ?? ""
    let plaintext = Data(#"{"timestamp": 1800000000, "request_id": "abc123"\#(field)}"#.utf8)
    return try ChaChaPoly.seal(plaintext, using: key, authenticating: Wire.requestAuthenticatedData(path)).combined
}

@Test func serverInfoHasTheKeysEveryServerMustReport() {
    let info = ServerInfo.current(port: 42511)
    #expect(info["name"] == "RetrieverServer")
    #expect(info["version"] == .string(ServerInfo.version))
    #expect(info["supported_protocol_version_range"] == ["min": .int(Wire.protocolVersions.lowerBound), "max": .int(Wire.protocolVersions.upperBound)])
}

@Test func serverInfoHasTheWellKnownOptionalKeys() {
    let info = ServerInfo.current(port: 42511)
    #expect(info["port"] == 42511)
    guard case .string(let os)? = info["os"], case .string(let host)? = info["host"] else {
        Issue.record("os and host should be strings")
        return
    }
    #expect(os.hasPrefix("macOS "))
    #expect(!host.isEmpty)
}

@Test(arguments: [Wire.configPath, Wire.retrievePath])
func aRequestThatNamesNoProtocolMeansProtocolOne(path: String) throws {
    #expect(try Wire.open(request: request(path), path: path, key: key, now: now) == Wire.Accepted(id: "abc123", protocolVersion: 1))
}

@Test(arguments: [Wire.configPath, Wire.retrievePath])
func aRequestMayNameAProtocolInTheServersRange(path: String) throws {
    for supported in Wire.protocolVersions {
        let accepted = try Wire.open(request: request(path, protocol: supported), path: path, key: key, now: now)
        #expect(accepted == Wire.Accepted(id: "abc123", protocolVersion: supported))
    }
}

@Test(arguments: [Wire.configPath, Wire.retrievePath])
func aProtocolOutsideTheRangeIsRefused(path: String) throws {
    for unsupported in [Wire.protocolVersions.lowerBound - 1, Wire.protocolVersions.upperBound + 1, 99] {
        #expect(throws: Wire.Failure.unsupportedProtocol) {
            try Wire.open(request: request(path, protocol: unsupported), path: path, key: key, now: now)
        }
    }
}

@Test func serverInfoIsAnswerableWhateverProtocolIsNamed() throws {
    // /server is how a client learns the range, so it cannot depend on one.
    for requested in [nil, 1, 99] as [Int?] {
        let accepted = try Wire.open(request: request(Wire.serverInfoPath, protocol: requested), path: Wire.serverInfoPath, key: key, now: now)
        #expect(accepted.id == "abc123")
    }
}

@Test func onlyARequestThatDecryptsIsToldAnything() {
    #expect(Wire.Failure.unauthenticated.status == nil)   // the connection is closed without a response
    #expect(Wire.Failure.stale.status == "400 Stale Timestamp")
    #expect(Wire.Failure.unsupportedProtocol.status == "400 Unsupported Protocol")
    #expect(Wire.Failure.malformed.status == "400 Bad Request")
}

@Test func serverInfoIsSealedForItsOwnPath() throws {
    let body = try Wire.seal(response: ServerInfo.current(port: 42511), id: "abc123", configFingerprint: 7, path: Wire.serverInfoPath, key: key)
    let box = try ChaChaPoly.SealedBox(combined: body)
    #expect(throws: (any Error).self) { try ChaChaPoly.open(box, using: key, authenticating: Wire.responseAuthenticatedData(Wire.configPath)) }
    let plain = try ChaChaPoly.open(box, using: key, authenticating: Wire.responseAuthenticatedData(Wire.serverInfoPath))
    let decoded = try JSONDecoder().decode(Wire.Response<[String: JSON]>.self, from: plain)
    #expect(decoded.data == ServerInfo.current(port: 42511))
}
