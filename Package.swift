// swift-tools-version: 6.0
// This is a Skip (https://skip.tools) package.
import PackageDescription

let package = Package(
    name: "skip-auth0",
    defaultLocalization: "en",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SkipAuth0", targets: ["SkipAuth0"]),
    ],
    dependencies: [
        .package(url: "https://github.com/skiptools/skip.git", from: "1.0.0"),
        .package(url: "https://github.com/skiptools/skip-foundation.git", from: "1.0.0"),
        .package(url: "https://github.com/auth0/Auth0.swift", from: "2.18.0"),
    ],
    targets: [
        .target(name: "SkipAuth0", dependencies: [
            .product(name: "SkipFoundation", package: "skip-foundation"),
            .product(name: "Auth0", package: "Auth0.swift", condition: .when(platforms: [.macOS, .iOS, .tvOS, .watchOS, .macCatalyst]))
        ], resources: [.process("Resources")], plugins: [.plugin(name: "skipstone", package: "skip")]),
        .testTarget(name: "SkipAuth0Tests", dependencies: [
            "SkipAuth0",
            .product(name: "SkipTest", package: "skip")
        ], resources: [.process("Resources")], plugins: [.plugin(name: "skipstone", package: "skip")]),
    ]
)

// SKIP_DYNAMIC_LIBRARIES and SKIP_BRIDGE both enforce building as dynamic
// libraries; SKIP_BRIDGE additionally puts the skipstone plugin in bridge mode
let bridgeMode = (Context.environment["SKIP_BRIDGE"] ?? "0") != "0"
let forceDylib = bridgeMode || (Context.environment["SKIP_DYNAMIC_LIBRARIES"] ?? "0") != "0"

if bridgeMode {
    package.dependencies += [.package(url: "https://github.com/skiptools/skip-bridge.git", "0.0.0"..<"2.0.0")]
    package.targets.forEach({ target in
        target.dependencies += [.product(name: "SkipBridge", package: "skip-bridge")]
    })
}

if forceDylib {
    // all library types must be dynamic to support bridging
    package.products = package.products.map({ product in
        guard let libraryProduct = product as? Product.Library else { return product }
        return .library(name: libraryProduct.name, type: .dynamic, targets: libraryProduct.targets)
    })
}
