// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EnigmaM10",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "EnigmaM10", targets: ["EnigmaM10"]),
        .library(name: "EnigmaM10Core", targets: ["EnigmaM10Core"])
    ],
    targets: [
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            publicHeadersPath: "include"
        ),
        .target(
            name: "EnigmaM10Core",
            dependencies: ["CArgon2"],
            path: "Sources/EnigmaM10Core"
        ),
        .executableTarget(
            name: "EnigmaM10",
            dependencies: ["EnigmaM10Core"],
            path: "Sources/EnigmaM10"
        ),
        .executableTarget(
            name: "EnigmaM10TestRunner",
            dependencies: ["EnigmaM10Core"],
            path: "Tests/EnigmaM10TestRunner"
        )
    ]
)
