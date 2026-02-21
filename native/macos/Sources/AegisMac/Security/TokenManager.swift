import Foundation

/// Manages API token lifecycle: storage, retrieval, and validation.
///
/// The token is stored exclusively in the macOS Keychain via `KeychainHelper`.
/// This class provides a higher-level interface for token operations used
/// by the `DaemonClient`.
///
/// Security guarantees:
/// - Tokens are never stored in memory longer than necessary
/// - Tokens are never logged or included in error messages
/// - Keychain access is gated by the user's login session
/// - Token validation is performed locally (format check only)
final class TokenManager {
    /// Keychain account name for the daemon API token.
    private static let tokenAccount = "aegis-daemon-api-key"

    /// Minimum acceptable token length to prevent empty/trivial tokens.
    private static let minimumTokenLength = 8

    /// Retrieve the current API token from the Keychain.
    ///
    /// Returns nil if no token is stored or the stored token is invalid.
    func getToken() -> String? {
        guard let token = KeychainHelper.load(forAccount: Self.tokenAccount) else {
            return nil
        }
        // Validate the token format before returning
        guard isValidFormat(token) else {
            return nil
        }
        return token
    }

    /// Store a new API token in the Keychain.
    ///
    /// - Parameter token: The API token to store.
    /// - Returns: True if the token was stored successfully.
    @discardableResult
    func setToken(_ token: String) -> Bool {
        guard isValidFormat(token) else {
            return false
        }
        let status = KeychainHelper.save(value: token, forAccount: Self.tokenAccount)
        return status == errSecSuccess
    }

    /// Remove the stored API token from the Keychain.
    ///
    /// - Returns: True if the token was removed (or didn't exist).
    @discardableResult
    func clearToken() -> Bool {
        let status = KeychainHelper.delete(forAccount: Self.tokenAccount)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// Check whether a token is currently stored.
    func hasToken() -> Bool {
        return KeychainHelper.exists(forAccount: Self.tokenAccount)
    }

    // MARK: - Validation

    /// Validate the token format.
    ///
    /// This is a local format check only -- it does not verify the token
    /// against the daemon. Checks:
    /// - Non-empty
    /// - Minimum length
    /// - No whitespace or control characters (injection prevention)
    private func isValidFormat(_ token: String) -> Bool {
        guard token.count >= Self.minimumTokenLength else {
            return false
        }
        // Reject tokens with whitespace or control characters
        let forbidden = CharacterSet.whitespacesAndNewlines.union(.controlCharacters)
        guard token.rangeOfCharacter(from: forbidden) == nil else {
            return false
        }
        return true
    }
}
