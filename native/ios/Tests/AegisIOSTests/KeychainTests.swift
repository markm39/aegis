import XCTest
@testable import AegisIOS

final class KeychainTests: XCTestCase {

    private let testAccount = "aegis-ios-test-keychain-\(UUID().uuidString)"

    override func tearDown() {
        // Clean up any test items from the Keychain
        KeychainHelper.delete(forAccount: testAccount)
        super.tearDown()
    }

    // MARK: - Save and Read Token

    func test_save_and_read_token() {
        let secret = "test-api-key-ios-12345678"
        let status = KeychainHelper.save(value: secret, forAccount: testAccount)
        XCTAssertEqual(status, errSecSuccess, "Save should succeed")

        let loaded = KeychainHelper.load(forAccount: testAccount)
        XCTAssertEqual(loaded, secret, "Loaded value should match saved value")
    }

    func testLoadNonexistentReturnsNil() {
        let loaded = KeychainHelper.load(forAccount: "aegis-ios-nonexistent-\(UUID().uuidString)")
        XCTAssertNil(loaded, "Loading a nonexistent key should return nil")
    }

    func testSaveOverwritesExistingValue() {
        let original = "original-value-ios-12345678"
        let updated = "updated-value-ios-87654321"

        KeychainHelper.save(value: original, forAccount: testAccount)
        KeychainHelper.save(value: updated, forAccount: testAccount)

        let loaded = KeychainHelper.load(forAccount: testAccount)
        XCTAssertEqual(loaded, updated, "Second save should overwrite the first")
    }

    // MARK: - Delete Token

    func test_delete_token() {
        let secret = "to-be-deleted-ios-12345678"
        KeychainHelper.save(value: secret, forAccount: testAccount)

        // Verify it exists
        let beforeDelete = KeychainHelper.load(forAccount: testAccount)
        XCTAssertNotNil(beforeDelete, "Value should exist before deletion")

        // Delete it
        let deleteStatus = KeychainHelper.delete(forAccount: testAccount)
        XCTAssertEqual(deleteStatus, errSecSuccess, "Delete should succeed")

        // Verify it's gone
        let afterDelete = KeychainHelper.load(forAccount: testAccount)
        XCTAssertNil(afterDelete, "Value should be nil after deletion")
    }

    func testDeleteNonexistentReturnsItemNotFound() {
        let status = KeychainHelper.delete(forAccount: "aegis-ios-nonexistent-\(UUID().uuidString)")
        XCTAssertEqual(status, errSecItemNotFound, "Deleting nonexistent item should return errSecItemNotFound")
    }

    // MARK: - Exists Check

    func testExistsReturnsTrueForStoredItem() {
        KeychainHelper.save(value: "exists-test-ios-12345678", forAccount: testAccount)
        XCTAssertTrue(KeychainHelper.exists(forAccount: testAccount))
    }

    func testExistsReturnsFalseForMissingItem() {
        XCTAssertFalse(KeychainHelper.exists(forAccount: "aegis-ios-nonexistent-\(UUID().uuidString)"))
    }

    // MARK: - TokenManager Integration

    func testTokenManagerSetAndGet() {
        let manager = TokenManager()
        let testToken = "test-token-ios-abcdefgh-12345678"
        XCTAssertTrue(manager.setToken(testToken))

        let retrieved = manager.getToken()
        XCTAssertEqual(retrieved, testToken)

        // Clean up
        manager.clearToken()
    }

    func testTokenManagerRejectsTooShortToken() {
        let manager = TokenManager()
        XCTAssertFalse(manager.setToken("short"))
        XCTAssertFalse(manager.setToken(""))
        XCTAssertFalse(manager.setToken("1234567")) // 7 chars, minimum is 8
    }

    func testTokenManagerRejectsWhitespaceTokens() {
        let manager = TokenManager()
        XCTAssertFalse(manager.setToken("has space here"))
        XCTAssertFalse(manager.setToken("has\nnewline"))
        XCTAssertFalse(manager.setToken("has\ttab1234"))
    }

    func testTokenManagerClear() {
        let manager = TokenManager()
        manager.setToken("token-to-clear-ios-12345")
        XCTAssertTrue(manager.hasToken())

        XCTAssertTrue(manager.clearToken())
        XCTAssertFalse(manager.hasToken())
    }

    // MARK: - Service Name

    func testServiceNameIsIOS() {
        XCTAssertEqual(KeychainHelper.serviceName, "com.aegis.ios",
                       "iOS Keychain service name should be com.aegis.ios")
    }
}
