import Foundation
import Security
import Testing
@testable import RetrieverSourceKit

/// A throwaway self-signed certificate, DER in base64. Its key was discarded.
private let certificateBase64 =
    "MIIBtTCCAR4CCQDAUxzlfCa9XzANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDDBNSZXRyaWV2ZXIgVW5pdCBUZXN0MCAXDTI2MTAw" +
    "NTIwMTc1MloYDzIxMjYwOTExMjAxNzUyWjAeMRwwGgYDVQQDDBNSZXRyaWV2ZXIgVW5pdCBUZXN0MIGfMA0GCSqGSIb3DQEBAQUA" +
    "A4GNADCBiQKBgQCg6COAv6xmkt1iCrEkvbm8FJcY+Zc0W1ZVh7vyEnLQ2nMjWGBVyk2B2+YhPpS4IqvArNYwdvRThV2JeeE7+FGz" +
    "sLMDeNkM8+3V/GhpVjxDzLe5ktwEpoTDV/S0PWm4w87mQ23/p+4NAqR4GgbEJApIW6h1Io/3ZrpBKY+zFwvjtQIDAQABMA0GCSqG" +
    "SIb3DQEBCwUAA4GBADBALLfeuQdxNXXWLwYE6hUHdKkyKuE/lz/mMvrTGzxYBxNvg7ETbfl904b6FPTHHZZKSzYPdofWmabv9kKV" +
    "Vm/uGKfaTR3EXk+XsLPEq5o8Uhk2NHE2CacYxjdRBgEJ8yVXEVOY9GviP9wmq4X6NkXe1rzeSGLx/6I46BZs+nIm"
private let certificateSHA1 = "67b70cf96f15db69b87d365a45683b3543914910"

@Test func aSelfSignedSignerIsRecognisedAsThatExactCertificate() throws {
    let der = try #require(Data(base64Encoded: certificateBase64))
    let certificate = try #require(SecCertificateCreateWithData(nil, der as CFData))
    #expect(try Signer.sameSigner(team: nil, certificates: [certificate]) == "certificate leaf = H\"\(certificateSHA1)\"")
    #expect(try Signer.sameSigner(team: "", certificates: [certificate]) == "certificate leaf = H\"\(certificateSHA1)\"")
}

@Test func aDeveloperIDSignerIsRecognisedByItsTeam() throws {
    let der = try #require(Data(base64Encoded: certificateBase64))
    let certificate = try #require(SecCertificateCreateWithData(nil, der as CFData))
    let expected = "anchor apple generic and certificate leaf[subject.OU] = \"ABCDE12345\""
    #expect(try Signer.sameSigner(team: "ABCDE12345", certificates: [certificate]) == expected)
}

@Test func aProgramWithNoSignerHasNoRequirementToOffer() {
    #expect(throws: Signer.Failure.self) { try Signer.sameSigner(team: nil, certificates: []) }
}

@Test func moduleIdentifiersAreDerivedFromTheSourceName() {
    #expect(Signer.moduleIdentifier(for: "os") == "local.retriever-source.os")
    #expect(Signer.serverIdentifier == "local.retriever-server")
}

@Test func theSignersRequirementsCompile() throws {
    // The requirement strings must be ones the system accepts.
    let der = try #require(Data(base64Encoded: certificateBase64))
    let certificate = try #require(SecCertificateCreateWithData(nil, der as CFData))
    for signer in [try Signer.sameSigner(team: nil, certificates: [certificate]), try Signer.sameSigner(team: "ABCDE12345", certificates: [])] {
        var requirement: SecRequirement?
        let text = "identifier \"\(Signer.moduleIdentifier(for: "os"))\" and \(signer)"
        #expect(SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, "\(text)")
    }
}
