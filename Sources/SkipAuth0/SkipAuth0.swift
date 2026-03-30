// Copyright 2025–2026 Skip
// SPDX-License-Identifier: MPL-2.0

#if !SKIP_BRIDGE
import Foundation
#if SKIP
import android.app.Activity
import android.content.Context
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationAPIClient
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.authentication.storage.SharedPreferencesStorage
import com.auth0.android.callback.Callback
import com.auth0.android.provider.WebAuthProvider
import com.auth0.android.result.Credentials
#else
import Auth0
#endif

// MARK: - Auth0SDK

/// Cross-platform facade over the Auth0 authentication SDK for iOS and Android.
///
/// On iOS this wraps the [Auth0.swift](https://github.com/auth0/Auth0.swift) SDK.
/// On Android this wraps the [Auth0.Android](https://github.com/auth0/Auth0.Android) SDK.
public final class Auth0SDK {
    nonisolated(unsafe) public static let shared = Auth0SDK()

    private var configuration: Auth0Config?

    #if SKIP
    private var account: com.auth0.android.Auth0?
    private var authClient: AuthenticationAPIClient?
    private var credentialsMgr: com.auth0.android.authentication.storage.CredentialsManager?
    #endif

    private init() { }

    /// Configure the Auth0 domain, client ID, and redirect scheme.
    ///
    /// Must be called before any other method. Typically called in your `App.init()`.
    public func configure(_ config: Auth0Config) {
        self.configuration = config
        #if SKIP
        let auth0Account = com.auth0.android.Auth0.getInstance(clientId: config.clientId, domain: config.domain)
        self.account = auth0Account
        self.authClient = AuthenticationAPIClient(auth0Account)
        let context = ProcessInfo.processInfo.androidContext
        let storage = SharedPreferencesStorage(context)
        self.credentialsMgr = com.auth0.android.authentication.storage.CredentialsManager(authClient!, storage)
        #endif
    }

    /// Returns whether `configure` has been called.
    public var isConfigured: Bool {
        configuration != nil
    }

    /// The current Auth0 configuration, or `nil` if not configured.
    public var config: Auth0Config? {
        configuration
    }

    // MARK: Web Auth

    /// Start an interactive login flow using the system browser (Universal Login).
    public func login(scope: String = "openid profile email offline_access",
                      audience: String? = nil,
                      presenting: Any? = nil,
                      completion: @escaping (Result<Auth0Credentials, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let context = presentingContext(presenting) else {
            completion(.failure(Auth0Error.missingPresenter))
            return
        }

        let account = com.auth0.android.Auth0.getInstance(clientId: config.clientId, domain: config.domain)
        var builder = WebAuthProvider.login(account)
            .withScheme(config.scheme)
            .withScope(scope)
        if let audience {
            builder = builder.withAudience(audience)
        }

        let loginCallback = Auth0LoginCallback(completion)
        builder.start(context, callback: loginCallback)
        #else
        var webAuth = Auth0.webAuth(clientId: config.clientId, domain: config.domain)
            .scope(scope)
        if let audience {
            webAuth = webAuth.audience(audience)
        }

        webAuth.start { (result: Result<Credentials, WebAuthError>) in
            switch result {
            case .success(let credentials):
                completion(.success(Auth0Credentials(credentials)))
            case .failure(let error):
                completion(.failure(error))
            }
        }
        #endif
    }

    /// Clear the current session (logout).
    public func logout(federated: Bool = false, presenting: Any? = nil, completion: @escaping (Result<Void, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let context = presentingContext(presenting) else {
            completion(.failure(Auth0Error.missingPresenter))
            return
        }

        let account = com.auth0.android.Auth0.getInstance(clientId: config.clientId, domain: config.domain)
        var builder = WebAuthProvider.logout(account)
            .withScheme(config.scheme)
        let returnTo = config.logoutReturnTo ?? config.defaultReturnToURL.absoluteString
        builder = builder.withReturnToUrl(returnTo)
        if federated {
            builder = builder.withFederated()
        }

        let logoutCallback = Auth0LogoutCallback(completion)
        builder.start(context, callback: logoutCallback)
        #else
        let webAuth = Auth0.webAuth(clientId: config.clientId, domain: config.domain)

        webAuth.clearSession(federated: federated) { (result: Result<Void, WebAuthError>) in
            switch result {
            case .success:
                completion(.success(()))
            case .failure(let error):
                completion(.failure(error))
            }
        }
        #endif
    }

    // MARK: Authentication API

    /// Log in with email and password (Resource Owner Password Grant).
    ///
    /// Requires the "Password" grant type to be enabled in your Auth0 application settings.
    public func loginWithCredentials(email: String, password: String, scope: String = "openid profile email offline_access", audience: String? = nil, completion: @escaping (Result<Auth0Credentials, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let loginClient = authClient else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        var request = loginClient.login(email, password, "Username-Password-Authentication")
            .setScope(scope)
        if let audience {
            request = request.setAudience(audience)
        }
        let loginCallback = Auth0LoginCallback(completion)
        request.start(loginCallback)
        #else
        Auth0.authentication(clientId: config.clientId, domain: config.domain)
            .login(usernameOrEmail: email, password: password, realmOrConnection: "Username-Password-Authentication", audience: audience, scope: scope)
            .start { result in
                switch result {
                case .success(let credentials):
                    completion(.success(Auth0Credentials(credentials)))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        #endif
    }

    /// Renew (refresh) credentials using a refresh token.
    public func renewCredentials(refreshToken: String, completion: @escaping (Result<Auth0Credentials, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let renewClient = authClient else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        let request = renewClient.renewAuth(refreshToken)
        let loginCallback = Auth0LoginCallback(completion)
        request.start(loginCallback)
        #else
        Auth0.authentication(clientId: config.clientId, domain: config.domain)
            .renew(withRefreshToken: refreshToken)
            .start { result in
                switch result {
                case .success(let credentials):
                    completion(.success(Auth0Credentials(credentials)))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        #endif
    }

    // MARK: Credentials Manager

    /// Whether stored credentials exist and have not expired (or can be renewed).
    public var hasValidCredentials: Bool {
        #if SKIP
        return credentialsMgr?.hasValidCredentials() ?? false
        #else
        guard let config = configuration else { return false }
        let credentialsManager = Auth0.CredentialsManager(authentication: Auth0.authentication(clientId: config.clientId, domain: config.domain))
        return credentialsManager.hasValid()
        #endif
    }

    /// Clear stored credentials.
    public func clearCredentials() {
        #if SKIP
        credentialsMgr?.clearCredentials()
        #else
        guard let config = configuration else { return }
        let credentialsManager = Auth0.CredentialsManager(authentication: Auth0.authentication(clientId: config.clientId, domain: config.domain))
        _ = credentialsManager.clear()
        #endif
    }

    #if SKIP
    func presentingContext(presenting: Any?) -> Context? {
        if let activity = presenting as? Activity {
            return activity
        } else if let presentingContext = presenting as? Context {
            return presentingContext
        } else if let processContext = ProcessInfo.processInfo.androidContext {
            return processContext
        } else {
            return nil
        }
    }
    #endif
}

// MARK: - Auth0Config

/// Configuration for the Auth0 SDK.
public struct Auth0Config: Sendable {
    /// Your Auth0 tenant domain (e.g. `"yourapp.us.auth0.com"`).
    public let domain: String
    /// The OAuth client ID from your Auth0 application.
    public let clientId: String
    /// The URL scheme used for Auth0 callbacks (e.g. `"myapp"`).
    public let scheme: String
    /// Optional custom return-to URL for logout.
    public var logoutReturnTo: String?

    public init(domain: String, clientId: String, scheme: String, logoutReturnTo: String? = nil) {
        self.domain = domain
        self.clientId = clientId
        self.scheme = scheme
        self.logoutReturnTo = logoutReturnTo
    }

    var defaultReturnToURL: URL {
        URL(string: "\(scheme)://\(domain)/ios/callback") ?? URL(string: "\(scheme)://\(domain)/callback")!
    }
}

// MARK: - Auth0Credentials

/// Cross-platform credentials from an Auth0 authentication flow.
public struct Auth0Credentials: Sendable {
    /// The OAuth2 access token.
    public let accessToken: String?
    /// The OpenID Connect ID token (JWT).
    public let idToken: String?
    /// The refresh token for obtaining new credentials.
    public let refreshToken: String?
    /// The token type (typically `"Bearer"`).
    public let tokenType: String?
    /// When the access token expires.
    public let expiresAt: Date?
    /// The granted OAuth scopes.
    public let scope: String?

    /// Create credentials with explicit values.
    public init(accessToken: String? = nil, idToken: String? = nil, refreshToken: String? = nil, tokenType: String? = nil, expiresAt: Date? = nil, scope: String? = nil) {
        self.accessToken = accessToken
        self.idToken = idToken
        self.refreshToken = refreshToken
        self.tokenType = tokenType
        self.expiresAt = expiresAt
        self.scope = scope
    }

    #if SKIP
    init(_ credentials: Credentials) {
        accessToken = credentials.accessToken
        idToken = credentials.idToken
        refreshToken = credentials.refreshToken
        tokenType = credentials.type
        expiresAt = skip.foundation.Date(platformValue: credentials.expiresAt)
        scope = credentials.scope
    }
    #else
    init(_ credentials: Credentials) {
        accessToken = credentials.accessToken
        idToken = credentials.idToken
        refreshToken = credentials.refreshToken
        tokenType = credentials.tokenType
        expiresAt = credentials.expiresIn
        scope = credentials.scope
    }
    #endif
}

// MARK: - Auth0Error

/// Errors that can occur during Auth0 operations.
public enum Auth0Error: LocalizedError {
    /// The SDK has not been configured. Call `Auth0SDK.shared.configure(_:)` first.
    case notConfigured
    /// A platform presenter is required (Activity/Context on Android, UIViewController on iOS).
    case missingPresenter
    /// The web authentication flow failed with the given message.
    case webAuthFailed(String)

    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "Auth0SDK.configure(_) must be called before login/logout."
        case .missingPresenter:
            return "A platform presenter (Activity/Context on Android or UIViewController on iOS) is required to start Auth0 WebAuth."
        case .webAuthFailed(let message):
            return message
        }
    }
}


// MARK: - Kotlin Callbacks

#if SKIP
class Auth0LoginCallback: Callback<Credentials, AuthenticationException> {
    private let completion: (Result<Auth0Credentials, Error>) -> Void

    init(_ completion: @escaping (Result<Auth0Credentials, Error>) -> Void) {
        self.completion = completion
    }

    override func onSuccess(result: Credentials) {
        completion(.success(Auth0Credentials(result)))
    }

    override func onFailure(error: AuthenticationException) {
        completion(.failure(Auth0Error.webAuthFailed(error.description)))
    }
}

typealias JavaVoid = java.lang.Void

class Auth0LogoutCallback: Callback<JavaVoid?, AuthenticationException> {
    private let completion: (Result<Void, Error>) -> Void

    init(_ completion: @escaping (Result<Void, Error>) -> Void) {
        self.completion = completion
    }

    override func onSuccess(result: JavaVoid?) {
        completion(.success(()))
    }

    override func onFailure(error: AuthenticationException) {
        completion(.failure(Auth0Error.webAuthFailed(error.description)))
    }
}
#endif


#endif
