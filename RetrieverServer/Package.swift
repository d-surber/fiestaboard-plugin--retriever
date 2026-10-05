// swift-tools-version:5.9
import PackageDescription

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
                // Embed Info.plist so macOS accepts the Reminders permission request
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "\(Context.packageDirectory)/Info.plist",
                ])
            ]
        ),
        // Source modules: one separately signed program per source.
        .executableTarget(name: "RetrieverSourceOS", dependencies: ["RetrieverSourceKit"]),
        .testTarget(
            name: "RetrieverServerTests",
            dependencies: ["RetrieverServer", "RetrieverSourceKit", "RetrieverSourceOS"]),
    ]
)
