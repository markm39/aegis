// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "AegisIOS",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .executable(name: "AegisIOS", targets: ["AegisIOS"])
    ],
    targets: [
        .executableTarget(
            name: "AegisIOS",
            path: "Sources/AegisIOS"
        ),
        .testTarget(
            name: "AegisIOSTests",
            dependencies: ["AegisIOS"],
            path: "Tests/AegisIOSTests"
        )
    ]
)
