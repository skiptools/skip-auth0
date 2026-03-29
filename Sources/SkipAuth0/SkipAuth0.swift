// Copyright 2023–2026 Skip
// SPDX-License-Identifier: MPL-2.0
#if !SKIP_BRIDGE
import Foundation
#if SKIP
import android.app.Activity
import android.content.Context
import com.auth0.android.Auth0
import com.auth0.android.authentication.AuthenticationException
import com.auth0.android.callback.Callback
import com.auth0.android.provider.WebAuthProvider
import com.auth0.android.result.Credentials
#else
import Auth0
#endif

/// Simple cross-platform facade over the Auth0 web auth flow for iOS and Android.
///
/// This mirrors the Auth0 quickstarts:
/// - iOS/macOS: https://auth0.com/docs/quickstart/native/ios-swift
/// - Android: https://auth0.com/docs/quickstart/native/android
public final class Auth0SDK {
    nonisolated(unsafe) public static let shared = Auth0SDK()

    private var configuration: Auth0Config?

    private init() { }

    /// Configure the Auth0 domain, client id, and redirect scheme.
    public func configure(_ config: Auth0Config) {
        self.configuration = config
    }

    /// Returns whether `configure` has been called.
    public var isConfigured: Bool {
        configuration != nil
    }

    /// Start an interactive login flow.
    /// - Parameters:
    ///   - scope: default `openid profile email offline_access`.
    ///   - audience: optional API audience.
    ///   - presenting: platform presenter (UIViewController for iOS, Activity/Context for Android). If omitted on Android we fall back to the process context when available.
    ///   - completion: receives Auth0 credentials or an error.
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

        let account = Auth0.getInstance(clientId: config.clientId, domain: config.domain)
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

    /// Clear the current session.
    /// - Parameters:
    ///   - federated: also log out of the identity provider when supported.
    ///   - presenting: platform presenter (UIViewController for iOS, Activity/Context for Android). If omitted on Android we fall back to the process context when available.
    ///   - completion: called when the session has been cleared or an error occurs.
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

        let account = Auth0.getInstance(clientId: config.clientId, domain: config.domain)
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

/// Auth0 configuration shared between platforms.
public struct Auth0Config: Sendable {
    public let domain: String
    public let clientId: String
    public let scheme: String
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

/// Normalized credentials container to keep the surface area aligned across platforms.
public struct Auth0Credentials: Sendable {
    public let accessToken: String?
    public let idToken: String?
    public let refreshToken: String?
    public let tokenType: String?
    public let expiresAt: Date?
    public let scope: String?

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


public enum Auth0Error: LocalizedError {
    case notConfigured
    case missingPresenter
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


#if SKIP
/// Forward declarations for callback classes
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
