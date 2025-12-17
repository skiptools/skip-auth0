// Licensed under the GNU General Public License v3.0 with Linking Exception
// SPDX-License-Identifier: LGPL-3.0-only WITH LGPL-3.0-linking-exception

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
