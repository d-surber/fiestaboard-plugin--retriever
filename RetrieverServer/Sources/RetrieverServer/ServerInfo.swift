import Foundation
import RetrieverSourceKit

/// What /server reports about this server. `name`, `version` and `protocol`
/// are required of every server; `os`, `host` and `port` are well known but
/// optional; a server may add anything else.
enum ServerInfo {
    static let name = "RetrieverServer"
    static let version = "0.1.0"

    static func current(port: UInt16) -> [String: JSON] {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return [
            "name": .string(name),
            "version": .string(version),
            "protocol": ["min": .int(Wire.protocols.lowerBound), "max": .int(Wire.protocols.upperBound)],
            "os": .string("macOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"),
            "host": .string(hostName()),
            "port": .int(Int(port)),
        ]
    }

    /// The name the machine gives itself. Asked of the kernel, which answers at once.
    static func hostName() -> String {
        var buffer = [CChar](repeating: 0, count: 256)
        guard gethostname(&buffer, buffer.count) == 0 else { return "" }
        return String(cString: buffer)
    }
}
