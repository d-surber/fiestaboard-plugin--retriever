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
    public static func moduleIdentifier(for name: String) -> String { moduleIdentifierPrefix + name }

    /// The start of every module's signing identifier.
    public static let moduleIdentifierPrefix = "local.retriever-source."

    /// Whether `text` is a module's signing identifier: the prefix, then a
    /// source name in lower-case letters, digits and hyphens.
    public static func isModuleIdentifier(_ text: String) -> Bool {
        guard text.hasPrefix(moduleIdentifierPrefix) else { return false }
        let name = text.dropFirst(moduleIdentifierPrefix.count)
        return !name.isEmpty && name.allSatisfy { $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "-") }
    }

    /// Whether `text` can be an identifier in a requirement. A requirement is
    /// written as text with the identifier between quotes, so one holding a
    /// quote could rewrite the rest of it, the signer's part included.
    static func isIdentifier(_ text: String) -> Bool {
        !text.isEmpty && text.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-") }
    }

    /// Whether `text` is a code hash as a requirement writes one: 40 hexadecimal digits.
    public static func isCodeHash(_ text: String) -> Bool {
        text.count == 40 && text.allSatisfy { $0.isASCII && $0.isHexDigit }
    }

    /// Why a requirement cannot be written, or a program does not meet one.
    public enum Failure: Error, CustomStringConvertible, Equatable {
        case notSigned
        case notOurs(String)   // a program that is unsigned, or signed by someone else
        case notAnIdentifier(String)
        case notACodeHash(String)

        public var description: String {
            switch self {
            case .notSigned: return "this program is not signed with an identity"
            case .notOurs(let path): return "\(path) is not signed by this program's signer"
            case .notAnIdentifier(let text): return "\"\(text)\" cannot be a signing identifier"
            case .notACodeHash(let text): return "\"\(text)\" is not a code hash"
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
              let signingInformation = information as? [String: Any],
              let identifier = signingInformation[kSecCodeInfoIdentifier as String] as? String,
              let unique = signingInformation[kSecCodeInfoUnique as String] as? Data
        else { throw Failure.notOurs(path) }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(try Signer.requirement(identifier: identifier) as CFString, [], &requirement) == errSecSuccess,
              let requirement, SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
        else { throw Failure.notOurs(path) }
        return Program(path: path, identifier: identifier, cdhash: unique.map { String(format: "%02x", $0) }.joined())
    }

    /// The requirement "signed by my signer, with this identifier", and
    /// optionally "and is exactly the build with this code hash".
    /// - Throws: `notAnIdentifier` or `notACodeHash` for text that could
    ///   change what the requirement means; `notSigned` if this program has no signer.
    public static func requirement(identifier: String, cdhash: String? = nil) throws -> String {
        try requirement(identifier: identifier, cdhash: cdhash, signer: try sameSigner())
    }

    static func requirement(identifier: String, cdhash: String?, signer: String) throws -> String {
        guard isIdentifier(identifier) else { throw Failure.notAnIdentifier(identifier) }
        if let cdhash, !isCodeHash(cdhash) { throw Failure.notACodeHash(cdhash) }
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
              let signingInformation = information as? [String: Any]
        else { throw Failure.notSigned }
        return try sameSigner(team: signingInformation[kSecCodeInfoTeamIdentifier as String] as? String,
                              certificates: signingInformation[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? [])
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
