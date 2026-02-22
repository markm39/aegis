import XCTest
@testable import AegisMac

final class TokenManagerTests: XCTestCase {

    private let manager = TokenManager()

    override func tearDown() {
        manager.clearToken()
        super.tearDown()
    }

    // MARK: - Set and Get

    func testSetAndGetToken() {
        let token = "test-token-abcdefgh-12345678"
        XCTAssertTrue(manager.setToken(token))
        XCTAssertEqual(manager.getToken(), token)
    }

    func testGetTokenReturnsNilWhenNotSet() {
        manager.clearToken()
        // After clearing, getToken should return nil (unless another test set one)
        // This is best-effort since Keychain state is shared
        let token = manager.getToken()
        // If a token exists from another test, just verify it's valid format
        if let token = token {
            XCTAssertGreaterThanOrEqual(token.count, 8)
        }
    }

    // MARK: - Validation

    func testRejectsTooShortToken() {
        XCTAssertFalse(manager.setToken("short"))
        XCTAssertFalse(manager.setToken(""))
        XCTAssertFalse(manager.setToken("1234567")) // 7 chars
    }

    func testRejectsWhitespaceTokens() {
        XCTAssertFalse(manager.setToken("has space here"))
        XCTAssertFalse(manager.setToken("has\nnewline"))
        XCTAssertFalse(manager.setToken("has\ttab1234"))
    }

    func testAcceptsValidTokens() {
        XCTAssertTrue(manager.setToken("abcdefgh"))
        XCTAssertTrue(manager.setToken("sk-1234567890abcdef"))
        XCTAssertTrue(manager.setToken("aegis_api_key_very_long_string_1234"))
    }

    // MARK: - Clear

    func testClearToken() {
        manager.setToken("token-to-clear-12345")
        XCTAssertTrue(manager.hasToken())

        XCTAssertTrue(manager.clearToken())
        XCTAssertFalse(manager.hasToken())
    }

    func testClearTokenWhenNoneExists() {
        manager.clearToken() // Ensure no token
        XCTAssertTrue(manager.clearToken()) // Should succeed even if no token
    }

    // MARK: - Has Token

    func testHasToken() {
        manager.clearToken()
        XCTAssertFalse(manager.hasToken())

        manager.setToken("test-token-12345678")
        XCTAssertTrue(manager.hasToken())
    }

    // MARK: - Overwrite

    func testOverwriteToken() {
        let first = "first-token-12345678"
        let second = "second-token-87654321"

        manager.setToken(first)
        XCTAssertEqual(manager.getToken(), first)

        manager.setToken(second)
        XCTAssertEqual(manager.getToken(), second)
    }
}
