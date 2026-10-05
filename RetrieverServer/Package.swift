// swift-tools-version:5.9
import Foundation
import PackageDescription

// Embedded in the server so macOS accepts its permission requests.
var serverSections = ["__info_plist": "Info.plist"]

// Optional: a config key built into the server. If config-key.pub (a PEM
// public key) is present here, the server trusts only that key for module
// configs, and it is covered by the server's code signature.
if FileManager.default.fileExists(atPath: "\(Context.packageDirectory)/config-key.pub") {
    serverSections["__config_key"] = "config-key.pub"
}

let package = Package(
    name: "RetrieverServer",
    platforms: [.macOS(.v14)],
    targets: [
        // What the server and every source module share: the Source
        // interface, and the XPC plumbing with its signature checks.
        .target(name: "RetrieverSourceKit"),
        .executableTarget(
            name: "RetrieverServer",
            dependencies: ["RetrieverSourceKit"],
            linkerSettings: [
                .unsafeFlags(serverSections.sorted { $0.key < $1.key }.flatMap { section, file in
                    ["-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", section,
                     "-Xlinker", "\(Context.packageDirectory)/\(file)"]
                })
            ]
        ),
        // Source modules: one separately signed program per source.
        .executableTarget(name: "RetrieverSourceOS", dependencies: ["RetrieverSourceKit"]),
        .testTarget(
            name: "RetrieverServerTests",
            dependencies: ["RetrieverServer", "RetrieverSourceKit", "RetrieverSourceOS"]),
    ]
)
