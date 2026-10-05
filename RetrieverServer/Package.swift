// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "RetrieverServer",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "RetrieverServer",
            linkerSettings: [
                // Embed Info.plist so macOS accepts the Reminders permission request
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "\(Context.packageDirectory)/Info.plist",
                ])
            ]
        )
    ]
)
