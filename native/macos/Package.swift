// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "AegisMac",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "AegisMac", targets: ["AegisMac"])
    ],
    targets: [
        .executableTarget(
            name: "AegisMac",
            path: "Sources/AegisMac"
        ),
        .testTarget(
            name: "AegisMacTests",
            dependencies: ["AegisMac"],
            path: "Tests/AegisMacTests"
        )
    ]
)
