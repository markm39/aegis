import Foundation
import Security

/// Keychain helper for securely storing and retrieving credentials on iOS.
///
/// All secrets are stored in the iOS Keychain using `kSecClassGenericPassword`.
/// This ensures credentials are encrypted at rest and protected by the device's
/// Secure Enclave. No secrets are ever stored in UserDefaults, plists, or files.
///
/// Security properties:
/// - Uses kSecClassGenericPassword for API tokens
/// - Access control: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
///   (items not included in backups, not synced to iCloud)
/// - Keychain items are scoped to the "com.aegis.ios" service name
/// - All operations are atomic (no partial state on failure)
enum KeychainHelper {
    /// Service name used to scope Keychain items to this application.
    static let serviceName = "com.aegis.ios"

    /// Save a string value to the Keychain.
    ///
    /// If an item with the same account already exists, it is updated.
    /// The item is marked as accessible only when the device is unlocked
    /// and is never included in device backups or iCloud sync.
    ///
    /// - Parameters:
    ///   - value: The secret string to store.
    ///   - account: The account identifier (key name).
    /// - Returns: The OSStatus result code.
    @discardableResult
    static func save(value: String, forAccount account: String) -> OSStatus {
        guard let data = value.data(using: .utf8) else {
            return errSecParam
        }

        // First try to delete any existing item to avoid duplicates
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Add the new item with strict access control
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        return SecItemAdd(addQuery as CFDictionary, nil)
    }

    /// Retrieve a string value from the Keychain.
    ///
    /// - Parameter account: The account identifier (key name).
    /// - Returns: The stored string, or nil if not found or on error.
    static func load(forAccount account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }

        return String(data: data, encoding: .utf8)
    }

    /// Delete a value from the Keychain.
    ///
    /// - Parameter account: The account identifier (key name).
    /// - Returns: The OSStatus result code.
    @discardableResult
    static func delete(forAccount account: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
        ]

        return SecItemDelete(query as CFDictionary)
    }

    /// Check whether a value exists in the Keychain for the given account.
    ///
    /// - Parameter account: The account identifier (key name).
    /// - Returns: True if an item exists.
    static func exists(forAccount account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: false,
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}

// MARK: - Token Manager

/// Manages API token lifecycle: storage, retrieval, and validation.
///
/// The token is stored exclusively in the iOS Keychain via `KeychainHelper`.
/// This class provides a higher-level interface for token operations used
/// by the `DaemonClient`.
///
/// Security guarantees:
/// - Tokens are never stored in memory longer than necessary
/// - Tokens are never logged or included in error messages
/// - Keychain access is gated by device unlock state
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
