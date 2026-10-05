import CryptoKit
import Foundation
import Security

/// Who signed this program, as a requirement another program can be held to.
///
/// The server and its source modules only talk to programs signed by the
/// same signer as themselves. Nothing is configured: each derives the
/// requirement from its own code signature, so it works unchanged with a
/// self-signed certificate or a Developer ID. A program that is not signed
/// by an identity (ad-hoc, or unsigned) has no signer, and refuses everyone.
public enum Signer {
    /// The signing identifier of the server.
    public static let serverIdentifier = "local.retriever-server"

    /// The signing identifier, and XPC service name, of the module for a source.
    public static func moduleIdentifier(for name: String) -> String { "local.retriever-source.\(name)" }

    public enum Failure: Error, CustomStringConvertible {
        case notSigned

        public var description: String { "this program is not signed with an identity" }
    }

    /// The requirement "signed by my signer, with this identifier".
    public static func requirement(identifier: String) throws -> String {
        "identifier \"\(identifier)\" and \(try sameSigner())"
    }

    /// The part of a requirement that says "signed by whoever signed me".
    static func sameSigner() throws -> String {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any]
        else { throw Failure.notSigned }
        return try sameSigner(team: info[kSecCodeInfoTeamIdentifier as String] as? String,
                              certificates: info[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? [])
    }

    /// A Developer ID is recognised by its team, on a certificate Apple
    /// issued. A self-signed certificate is recognised as that exact certificate.
    static func sameSigner(team: String?, certificates: [SecCertificate]) throws -> String {
        if let team, !team.isEmpty {
            return "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        }
        guard let leaf = certificates.first else { throw Failure.notSigned }
        let hash = Insecure.SHA1.hash(data: SecCertificateCopyData(leaf) as Data)   // the form requirements use
        return "certificate leaf = H\"\(hash.map { String(format: "%02x", $0) }.joined())\""
    }
}
