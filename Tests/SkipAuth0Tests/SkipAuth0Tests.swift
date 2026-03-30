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

    func testAuth0Config() throws {
        let config = Auth0Config(
            domain: "example.us.auth0.com",
            clientId: "test-client-id",
            scheme: "myapp",
            logoutReturnTo: "myapp://logout"
        )
        XCTAssertEqual(config.domain, "example.us.auth0.com")
        XCTAssertEqual(config.clientId, "test-client-id")
        XCTAssertEqual(config.scheme, "myapp")
        XCTAssertEqual(config.logoutReturnTo, "myapp://logout")

        // Config without logoutReturnTo
        let config2 = Auth0Config(domain: "test.auth0.com", clientId: "cid", scheme: "app")
        XCTAssertNil(config2.logoutReturnTo)
    }

    func testAuth0Credentials() throws {
        let now = Date()
        let creds = Auth0Credentials(
            accessToken: "access-token-123",
            idToken: "id-token-456",
            refreshToken: "refresh-token-789",
            tokenType: "Bearer",
            expiresAt: now,
            scope: "openid profile email"
        )
        XCTAssertEqual(creds.accessToken, "access-token-123")
        XCTAssertEqual(creds.idToken, "id-token-456")
        XCTAssertEqual(creds.refreshToken, "refresh-token-789")
        XCTAssertEqual(creds.tokenType, "Bearer")
        XCTAssertNotNil(creds.expiresAt)
        XCTAssertEqual(creds.scope, "openid profile email")

        // Default credentials (all nil)
        let emptyCreds = Auth0Credentials()
        XCTAssertNil(emptyCreds.accessToken)
        XCTAssertNil(emptyCreds.idToken)
        XCTAssertNil(emptyCreds.refreshToken)
        XCTAssertNil(emptyCreds.scope)
    }

    func testAuth0ErrorCases() throws {
        let errors: [Auth0Error] = [
            .notConfigured,
            .missingPresenter,
            .webAuthFailed("test failure")
        ]
        XCTAssertEqual(errors.count, 3)
        for err in errors {
            XCTAssertNotNil(err.errorDescription)
            XCTAssertFalse(err.errorDescription!.isEmpty)
        }
        // Verify specific messages
        XCTAssertTrue(Auth0Error.notConfigured.errorDescription!.contains("configure"))
        XCTAssertTrue(Auth0Error.missingPresenter.errorDescription!.contains("presenter"))
        XCTAssertTrue(Auth0Error.webAuthFailed("xyz").errorDescription!.contains("xyz"))
    }

    func testAuth0SDKConfiguration() throws {
        let sdk = Auth0SDK.shared
        let config = Auth0Config(domain: "test.auth0.com", clientId: "cid", scheme: "testscheme")
        sdk.configure(config)
        XCTAssertTrue(sdk.isConfigured)
        XCTAssertNotNil(sdk.config)
        XCTAssertEqual(sdk.config?.domain, "test.auth0.com")
        XCTAssertEqual(sdk.config?.clientId, "cid")
        XCTAssertEqual(sdk.config?.scheme, "testscheme")
    }

    func testAuth0APICompilation() throws {
        Auth0SDK.shared.configure(Auth0Config(domain: "test.auth0.com", clientId: "cid", scheme: "test"))

        // Validate all API methods compile without actually calling them
        if false {
            Auth0SDK.shared.login { _ in }
            Auth0SDK.shared.login(scope: "openid", audience: "https://api.example.com") { _ in }
            Auth0SDK.shared.loginWithCredentials(email: "a@b.com", password: "p") { _ in }
            Auth0SDK.shared.loginWithCredentials(email: "a@b.com", password: "p", scope: "openid", audience: "https://api.example.com") { _ in }
            Auth0SDK.shared.logout { _ in }
            Auth0SDK.shared.logout(federated: true) { _ in }
            Auth0SDK.shared.renewCredentials(refreshToken: "rt") { _ in }
            let _ = Auth0SDK.shared.hasValidCredentials
            Auth0SDK.shared.clearCredentials()
        }
    }

    func testAuth0CredentialsManager() throws {
        Auth0SDK.shared.configure(Auth0Config(domain: "test.auth0.com", clientId: "cid", scheme: "test"))
        Auth0SDK.shared.clearCredentials()
        XCTAssertFalse(Auth0SDK.shared.hasValidCredentials)
    }
}

struct TestData : Codable, Hashable {
    var testModuleName: String
}
