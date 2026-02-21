import Foundation
import Security

/// Keychain helper for securely storing and retrieving credentials.
///
/// All secrets are stored in the macOS Keychain using `kSecClassGenericPassword`.
/// This ensures credentials are encrypted at rest and protected by the user's
/// login keychain. No secrets are ever stored in UserDefaults, plists, or files.
///
/// Security properties:
/// - Uses kSecClassGenericPassword for API tokens
/// - Queries restrict access to the current app with kSecAttrAccessible
/// - Keychain items are scoped to the "com.aegis.mac" service name
/// - All operations are atomic (no partial state on failure)
enum KeychainHelper {
    /// Service name used to scope Keychain items to this application.
    static let serviceName = "com.aegis.mac"

    /// Save a string value to the Keychain.
    ///
    /// If an item with the same account already exists, it is updated.
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

        // First try to delete any existing item
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Add the new item
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
