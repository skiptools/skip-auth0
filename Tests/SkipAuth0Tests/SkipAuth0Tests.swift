// Copyright 2025–2026 Skip
// SPDX-License-Identifier: MPL-2.0

import XCTest
import OSLog
import Foundation
@testable import SkipAuth0

let logger: Logger = Logger(subsystem: "SkipAuth0", category: "Tests")

@available(macOS 13, *)
final class SkipAuth0Tests: XCTestCase {

    func testSkipAuth0() throws {
        Auth0SDK.shared.configure(Auth0Config(domain: "https://skip.tools", clientId: "", scheme: ""))
        if false { // testing compile of API surface only
            Auth0SDK.shared.login { result in
                logger.log("login result")
            }
            Auth0SDK.shared.logout { result in
                logger.log("logout result")
            }
        }
    }
}

struct TestData : Codable, Hashable {
    var testModuleName: String
}
