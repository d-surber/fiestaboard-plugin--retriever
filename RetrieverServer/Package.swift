// swift-tools-version:5.9
import Foundation
import PackageDescription

/// Linker flags that embed a file in a program as a section of `__TEXT`.
func embedding(_ sections: [String: String]) -> LinkerSetting {
    .unsafeFlags(sections.sorted { $0.key < $1.key }.flatMap { section, file in
        ["-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", section,
         "-Xlinker", "\(Context.packageDirectory)/\(file)"]
    })
}

/// A source module: one separately signed program per source. Its Info.plist
/// is embedded so macOS has a name and a reason to show when the module asks
/// for the permission its source needs; a module that needs none has no file.
func module(_ name: String, infoPlist: Bool = false) -> Target {
    .executableTarget(
        name: name,
        dependencies: ["RetrieverSourceKit"],
        exclude: infoPlist ? ["Info.plist"] : [],
        linkerSettings: infoPlist ? [embedding(["__info_plist": "Sources/\(name)/Info.plist"])] : [])
}

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
            linkerSettings: [embedding(serverSections)]
        ),
        module("RetrieverSourceOS"),
        module("RetrieverSourceReminders", infoPlist: true),
        module("RetrieverSourceMusic", infoPlist: true),
        module("RetrieverSourceCalendar", infoPlist: true),
        .testTarget(
            name: "RetrieverServerTests",
            dependencies: ["RetrieverServer", "RetrieverSourceKit", "RetrieverSourceOS",
                           "RetrieverSourceReminders", "RetrieverSourceMusic", "RetrieverSourceCalendar"]),
    ]
)
