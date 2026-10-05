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
        case notOurs(String)   // a program that is unsigned, or signed by someone else

        public var description: String {
            switch self {
            case .notSigned: return "this program is not signed with an identity"
            case .notOurs(let path): return "\(path) is not signed by this program's signer"
            }
        }
    }

    /// A program on disk that is signed by this program's signer.
    public struct Program: Equatable {
        public let path: String
        public let identifier: String
        public let cdhash: String   // identifies the exact build
    }

    /// Reads a program's signature. Throws unless it is signed by this
    /// program's signer; its identifier is whatever it was signed with.
    public static func inspect(_ path: String) throws -> Program {
        var code: SecStaticCode?
        var information: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let identifier = info[kSecCodeInfoIdentifier as String] as? String,
              let unique = info[kSecCodeInfoUnique as String] as? Data
        else { throw Failure.notOurs(path) }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(try Signer.requirement(identifier: identifier) as CFString, [], &requirement) == errSecSuccess,
              let requirement, SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
        else { throw Failure.notOurs(path) }
        return Program(path: path, identifier: identifier, cdhash: unique.map { String(format: "%02x", $0) }.joined())
    }

    /// The requirement "signed by my signer, with this identifier", and
    /// optionally "and is exactly the build with this code hash".
    public static func requirement(identifier: String, cdhash: String? = nil) throws -> String {
        requirement(identifier: identifier, cdhash: cdhash, signer: try sameSigner())
    }

    static func requirement(identifier: String, cdhash: String?, signer: String) -> String {
        let build = cdhash.map { " and cdhash H\"\($0.lowercased())\"" } ?? ""
        return "identifier \"\(identifier)\" and \(signer)\(build)"
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
