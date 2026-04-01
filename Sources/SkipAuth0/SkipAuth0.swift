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
import com.auth0.android.authentication.storage.CredentialsManagerException
import com.auth0.android.authentication.storage.SharedPreferencesStorage
import com.auth0.android.callback.Callback
import com.auth0.android.provider.WebAuthProvider
import com.auth0.android.result.Credentials
import com.auth0.android.result.DatabaseUser
import com.auth0.android.result.UserProfile
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

        webAuth.start { (result: Result<Auth0.Credentials, WebAuthError>) in
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

    /// Sign up a new user and log in, returning credentials.
    ///
    /// Creates the user in the specified database connection and then performs
    /// a login to obtain tokens. Requires the "Password" grant type to be enabled.
    ///
    /// - Parameters:
    ///   - email: The user's email address.
    ///   - password: The desired password.
    ///   - username: Optional username (if the connection requires it).
    ///   - connection: The Auth0 database connection name.
    ///   - scope: OAuth scopes to request.
    ///   - audience: Optional API audience identifier.
    ///   - completion: Called with credentials on success or an error on failure.
    public func signUp(email: String,
                       password: String,
                       username: String? = nil,
                       connection: String = "Username-Password-Authentication",
                       scope: String = "openid profile email offline_access",
                       audience: String? = nil,
                       completion: @escaping (Result<Auth0Credentials, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let signUpClient = authClient else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        var request = signUpClient.signUp(email, password, username, connection)
            .setScope(scope)
        if let audience {
            request = request.setAudience(audience)
        }
        let callback = Auth0LoginCallback(completion)
        request.start(callback)
        #else
        // iOS: create user then log in to obtain tokens
        Auth0.authentication(clientId: config.clientId, domain: config.domain)
            .signup(email: email, username: username, password: password, connection: connection)
            .start { signupResult in
                switch signupResult {
                case .success:
                    Auth0.authentication(clientId: config.clientId, domain: config.domain)
                        .login(usernameOrEmail: email, password: password, realmOrConnection: connection, audience: audience, scope: scope)
                        .start { loginResult in
                            switch loginResult {
                            case .success(let credentials):
                                completion(.success(Auth0Credentials(credentials)))
                            case .failure(let error):
                                completion(.failure(error))
                            }
                        }
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        #endif
    }

    /// Create a new user without logging in.
    ///
    /// Registers the user in the specified database connection and returns
    /// basic user information. No tokens are issued.
    ///
    /// - Parameters:
    ///   - email: The user's email address.
    ///   - password: The desired password.
    ///   - username: Optional username (if the connection requires it).
    ///   - connection: The Auth0 database connection name.
    ///   - completion: Called with user info on success or an error on failure.
    public func createUser(email: String,
                           password: String,
                           username: String? = nil,
                           connection: String = "Username-Password-Authentication",
                           completion: @escaping (Result<Auth0DatabaseUser, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let createClient = authClient else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        let request = createClient.createUser(email, password, username, connection)
        let callback = Auth0DatabaseUserCallback(completion)
        request.start(callback)
        #else
        Auth0.authentication(clientId: config.clientId, domain: config.domain)
            .signup(email: email, username: username, password: password, connection: connection)
            .start { result in
                switch result {
                case .success(let user):
                    completion(.success(Auth0DatabaseUser(user)))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        #endif
    }

    /// Send a password reset email.
    ///
    /// Triggers Auth0 to send a password reset link to the given email address.
    /// For security reasons, this will not fail if the email does not exist.
    ///
    /// - Parameters:
    ///   - email: The email address of the user.
    ///   - connection: The Auth0 database connection name.
    ///   - completion: Called with success or an error.
    public func resetPassword(email: String,
                              connection: String = "Username-Password-Authentication",
                              completion: @escaping (Result<Void, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let resetClient = authClient else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        let request = resetClient.resetPassword(email, connection)
        let callback = Auth0VoidCallback(completion)
        request.start(callback)
        #else
        Auth0.authentication(clientId: config.clientId, domain: config.domain)
            .resetPassword(email: email, connection: connection)
            .start { result in
                switch result {
                case .success:
                    completion(.success(()))
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

    /// Fetch the user profile from the `/userinfo` endpoint.
    ///
    /// Requires a valid access token obtained from a login flow.
    ///
    /// - Parameters:
    ///   - accessToken: A valid OAuth2 access token.
    ///   - completion: Called with the user profile on success or an error on failure.
    public func userInfo(accessToken: String,
                         completion: @escaping (Result<Auth0UserProfile, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let infoClient = authClient else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        let request = infoClient.userInfo(accessToken)
        let callback = Auth0UserProfileCallback(completion)
        request.start(callback)
        #else
        Auth0.authentication(clientId: config.clientId, domain: config.domain)
            .userInfo(withAccessToken: accessToken)
            .start { result in
                switch result {
                case .success(let info):
                    completion(.success(Auth0UserProfile(info)))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        #endif
    }

    /// Revoke a refresh token.
    ///
    /// After revocation the refresh token can no longer be used to obtain
    /// new access tokens. Call this when logging out to invalidate stored tokens.
    ///
    /// - Parameters:
    ///   - refreshToken: The refresh token to revoke.
    ///   - completion: Called with success or an error.
    public func revokeToken(refreshToken: String,
                            completion: @escaping (Result<Void, Error>) -> Void) {
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let revokeClient = authClient else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        let request = revokeClient.revokeToken(refreshToken)
        let callback = Auth0VoidCallback(completion)
        request.start(callback)
        #else
        Auth0.authentication(clientId: config.clientId, domain: config.domain)
            .revoke(refreshToken: refreshToken)
            .start { result in
                switch result {
                case .success:
                    completion(.success(()))
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

    /// Store credentials in the platform's secure storage.
    ///
    /// On iOS, credentials are saved in the Keychain via the Auth0 CredentialsManager.
    /// On Android, credentials are saved in SharedPreferences via the Auth0 CredentialsManager.
    ///
    /// - Parameter credentials: The credentials to store.
    /// - Returns: `true` if the credentials were stored successfully.
    @discardableResult
    public func saveCredentials(_ credentials: Auth0Credentials) -> Bool {
        #if SKIP
        guard let mgr = credentialsMgr else { return false }
        let epochMs = Int64((credentials.expiresAt ?? Date()).timeIntervalSince1970 * 1000.0)
        let platformCreds = Credentials(
            credentials.idToken ?? "",
            credentials.accessToken ?? "",
            credentials.tokenType ?? "Bearer",
            credentials.refreshToken,
            java.util.Date(epochMs),
            credentials.scope
        )
        mgr.saveCredentials(platformCreds)
        return true
        #else
        guard let config = configuration else { return false }
        let platformCreds = Auth0.Credentials(
            accessToken: credentials.accessToken ?? "",
            tokenType: credentials.tokenType ?? "Bearer",
            idToken: credentials.idToken ?? "",
            refreshToken: credentials.refreshToken,
            expiresIn: credentials.expiresAt ?? Date(),
            scope: credentials.scope
        )
        let credentialsManager = Auth0.CredentialsManager(authentication: Auth0.authentication(clientId: config.clientId, domain: config.domain))
        return credentialsManager.store(credentials: platformCreds)
        #endif
    }

    /// Retrieve stored credentials, automatically renewing if expired.
    ///
    /// If stored credentials have expired but a refresh token is available,
    /// the credentials will be renewed automatically before returning.
    ///
    /// - Parameter completion: Called with credentials on success or an error on failure.
    public func getCredentials(completion: @escaping (Result<Auth0Credentials, Error>) -> Void) {
        guard configuration != nil else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }

        #if SKIP
        guard let mgr = credentialsMgr else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        let callback = Auth0CredentialsManagerCallback(completion)
        mgr.getCredentials(callback)
        #else
        guard let config = configuration else {
            completion(.failure(Auth0Error.notConfigured))
            return
        }
        let credentialsManager = Auth0.CredentialsManager(authentication: Auth0.authentication(clientId: config.clientId, domain: config.domain))
        credentialsManager.credentials { result in
            switch result {
            case .success(let creds):
                completion(.success(Auth0Credentials(creds)))
            case .failure(let error):
                completion(.failure(error))
            }
        }
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
    init(_ credentials: Auth0.Credentials) {
        accessToken = credentials.accessToken
        idToken = credentials.idToken
        refreshToken = credentials.refreshToken
        tokenType = credentials.tokenType
        expiresAt = credentials.expiresIn
        scope = credentials.scope
    }
    #endif
}

// MARK: - Auth0UserProfile

/// Cross-platform user profile from the Auth0 `/userinfo` endpoint.
public struct Auth0UserProfile: Sendable {
    /// The user's unique identifier (the `sub` claim).
    public let sub: String
    /// The user's full name.
    public let name: String?
    /// The user's given (first) name.
    public let givenName: String?
    /// The user's family (last) name.
    public let familyName: String?
    /// The user's nickname.
    public let nickname: String?
    /// The user's email address.
    public let email: String?
    /// Whether the user's email address has been verified.
    public let emailVerified: Bool
    /// URL string of the user's profile picture.
    public let picture: String?

    /// Create a user profile with explicit values.
    public init(sub: String, name: String? = nil, givenName: String? = nil, familyName: String? = nil, nickname: String? = nil, email: String? = nil, emailVerified: Bool = false, picture: String? = nil) {
        self.sub = sub
        self.name = name
        self.givenName = givenName
        self.familyName = familyName
        self.nickname = nickname
        self.email = email
        self.emailVerified = emailVerified
        self.picture = picture
    }

    #if SKIP
    init(_ profile: UserProfile) {
        sub = profile.getId() ?? ""
        name = profile.name
        givenName = profile.givenName
        familyName = profile.familyName
        nickname = profile.nickname
        email = profile.email
        // SKIP REPLACE: emailVerified = profile.isEmailVerified ?: false
        emailVerified = false
        picture = profile.pictureURL
    }
    #else
    init(_ info: UserInfo) {
        sub = info.sub
        name = info.name
        givenName = info.givenName
        familyName = info.familyName
        nickname = info.nickname
        email = info.email
        emailVerified = info.emailVerified ?? false
        picture = info.picture?.absoluteString
    }
    #endif
}

// MARK: - Auth0DatabaseUser

/// Cross-platform representation of a newly created Auth0 database user.
public struct Auth0DatabaseUser: Sendable {
    /// The user's email address.
    public let email: String
    /// The user's username (if the connection uses usernames).
    public let username: String?
    /// Whether the user's email has been verified.
    public let emailVerified: Bool

    /// Create a database user with explicit values.
    public init(email: String, username: String? = nil, emailVerified: Bool = false) {
        self.email = email
        self.username = username
        self.emailVerified = emailVerified
    }

    #if SKIP
    init(_ user: DatabaseUser) {
        email = user.email
        username = user.username
        emailVerified = user.isEmailVerified
    }
    #else
    init(_ user: Auth0.DatabaseUser) {
        email = user.email
        username = user.username
        emailVerified = user.verified
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
    /// An authentication API call failed with the given message.
    case authenticationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "Auth0SDK.configure(_) must be called before login/logout."
        case .missingPresenter:
            return "A platform presenter (Activity/Context on Android or UIViewController on iOS) is required to start Auth0 WebAuth."
        case .webAuthFailed(let message):
            return message
        case .authenticationFailed(let message):
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

class Auth0VoidCallback: Callback<JavaVoid?, AuthenticationException> {
    private let completion: (Result<Void, Error>) -> Void

    init(_ completion: @escaping (Result<Void, Error>) -> Void) {
        self.completion = completion
    }

    override func onSuccess(result: JavaVoid?) {
        completion(.success(()))
    }

    override func onFailure(error: AuthenticationException) {
        completion(.failure(Auth0Error.authenticationFailed(error.description)))
    }
}

class Auth0DatabaseUserCallback: Callback<DatabaseUser, AuthenticationException> {
    private let completion: (Result<Auth0DatabaseUser, Error>) -> Void

    init(_ completion: @escaping (Result<Auth0DatabaseUser, Error>) -> Void) {
        self.completion = completion
    }

    override func onSuccess(result: DatabaseUser) {
        completion(.success(Auth0DatabaseUser(result)))
    }

    override func onFailure(error: AuthenticationException) {
        completion(.failure(Auth0Error.authenticationFailed(error.description)))
    }
}

class Auth0UserProfileCallback: Callback<UserProfile, AuthenticationException> {
    private let completion: (Result<Auth0UserProfile, Error>) -> Void

    init(_ completion: @escaping (Result<Auth0UserProfile, Error>) -> Void) {
        self.completion = completion
    }

    override func onSuccess(result: UserProfile) {
        completion(.success(Auth0UserProfile(result)))
    }

    override func onFailure(error: AuthenticationException) {
        completion(.failure(Auth0Error.authenticationFailed(error.description)))
    }
}

class Auth0CredentialsManagerCallback: Callback<Credentials, CredentialsManagerException> {
    private let completion: (Result<Auth0Credentials, Error>) -> Void

    init(_ completion: @escaping (Result<Auth0Credentials, Error>) -> Void) {
        self.completion = completion
    }

    override func onSuccess(result: Credentials) {
        completion(.success(Auth0Credentials(result)))
    }

    override func onFailure(error: CredentialsManagerException) {
        completion(.failure(Auth0Error.authenticationFailed(error.description)))
    }
}
#endif


#endif
