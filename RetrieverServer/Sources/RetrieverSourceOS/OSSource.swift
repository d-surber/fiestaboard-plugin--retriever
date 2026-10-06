import Foundation
import RetrieverSourceKit

/// The version of macOS this Mac is running.
final class OSSource: Source {
    /// The version, as the system reports it.
    struct Payload: Codable, Equatable {
        let version: String   // "26.6.2"
        let build: String     // "25G78"
    }

    let name = "os"

    /// The shape of `Payload`.
    let schema: JSON = [
        "type": "object",
        "properties": [
            "version": ["type": "string"],
            "build": ["type": "string"],
        ],
        "default": ["version": "", "build": ""],
    ]

    func fetch(_ done: @escaping (Entry) -> Void) {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        done(succeeded(Payload(version: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)", build: Self.build())))
    }

    /// The build number, from the kernel: `kern.osversion`.
    static func build() -> String {
        var size = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else { return "" }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &buffer, &size, nil, 0) == 0 else { return "" }
        return String(cString: buffer)
    }
}
