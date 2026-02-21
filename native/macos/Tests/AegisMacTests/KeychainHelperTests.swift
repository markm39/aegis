import XCTest
@testable import AegisMac

final class KeychainHelperTests: XCTestCase {

    private let testAccount = "aegis-test-keychain-\(UUID().uuidString)"

    override func tearDown() {
        // Clean up any test items from the Keychain
        KeychainHelper.delete(forAccount: testAccount)
        super.tearDown()
    }

    // MARK: - Save and Load

    func testSaveAndLoadRoundtrip() {
        let secret = "test-api-key-12345678"
        let status = KeychainHelper.save(value: secret, forAccount: testAccount)
        XCTAssertEqual(status, errSecSuccess)

        let loaded = KeychainHelper.load(forAccount: testAccount)
        XCTAssertEqual(loaded, secret)
    }

    func testLoadNonexistentReturnsNil() {
        let loaded = KeychainHelper.load(forAccount: "aegis-nonexistent-\(UUID().uuidString)")
        XCTAssertNil(loaded)
    }

    func testSaveOverwritesExistingValue() {
        let original = "original-value-12345678"
        let updated = "updated-value-87654321"

        KeychainHelper.save(value: original, forAccount: testAccount)
        KeychainHelper.save(value: updated, forAccount: testAccount)

        let loaded = KeychainHelper.load(forAccount: testAccount)
        XCTAssertEqual(loaded, updated)
    }

    // MARK: - Delete

    func testDeleteRemovesItem() {
        let secret = "to-be-deleted-12345678"
        KeychainHelper.save(value: secret, forAccount: testAccount)

        let deleteStatus = KeychainHelper.delete(forAccount: testAccount)
        XCTAssertEqual(deleteStatus, errSecSuccess)

        let loaded = KeychainHelper.load(forAccount: testAccount)
        XCTAssertNil(loaded)
    }

    func testDeleteNonexistentReturnsItemNotFound() {
        let status = KeychainHelper.delete(forAccount: "aegis-nonexistent-\(UUID().uuidString)")
        XCTAssertEqual(status, errSecItemNotFound)
    }

    // MARK: - Exists

    func testExistsReturnsTrueForStoredItem() {
        KeychainHelper.save(value: "exists-test-12345678", forAccount: testAccount)
        XCTAssertTrue(KeychainHelper.exists(forAccount: testAccount))
    }

    func testExistsReturnsFalseForMissingItem() {
        XCTAssertFalse(KeychainHelper.exists(forAccount: "aegis-nonexistent-\(UUID().uuidString)"))
    }

    // MARK: - TokenManager Integration

    func testTokenManagerSetAndGet() {
        let manager = TokenManager()

        // Set a token
        let testToken = "test-token-abcdefgh-12345678"
        XCTAssertTrue(manager.setToken(testToken))

        // Get it back
        let retrieved = manager.getToken()
        XCTAssertEqual(retrieved, testToken)

        // Clean up
        manager.clearToken()
    }

    func testTokenManagerRejectsTooShortToken() {
        let manager = TokenManager()

        // Tokens shorter than 8 characters should be rejected
        XCTAssertFalse(manager.setToken("short"))
        XCTAssertFalse(manager.setToken(""))
    }

    func testTokenManagerRejectsWhitespaceTokens() {
        let manager = TokenManager()

        XCTAssertFalse(manager.setToken("has space here"))
        XCTAssertFalse(manager.setToken("has\nnewline"))
        XCTAssertFalse(manager.setToken("has\ttab1234"))
    }

    func testTokenManagerClear() {
        let manager = TokenManager()
        manager.setToken("token-to-clear-12345")
        XCTAssertTrue(manager.hasToken())

        XCTAssertTrue(manager.clearToken())
        XCTAssertFalse(manager.hasToken())
    }
}
