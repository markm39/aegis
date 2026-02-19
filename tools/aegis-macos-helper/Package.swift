// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AegisMacosHelper",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "aegis-macos-helper", targets: ["AegisMacosHelper"])
    ],
    targets: [
        .executableTarget(
            name: "AegisMacosHelper",
            path: "Sources/AegisMacosHelper"
        )
    ]
)
