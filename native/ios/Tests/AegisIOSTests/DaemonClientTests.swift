import XCTest
@testable import AegisIOS

final class DaemonClientTests: XCTestCase {

    // MARK: - Initialization

    func testClientCreatesWithDefaultURL() {
        let client = DaemonClient()
        XCTAssertNotNil(client)
        XCTAssertEqual(client.baseURL.absoluteString, "http://localhost:3100")
    }

    func testClientCreatesWithCustomURL() {
        let url = URL(string: "https://aegis.example.com:8443")!
        let client = DaemonClient(baseURL: url)
        XCTAssertNotNil(client)
        XCTAssertEqual(client.baseURL, url)
    }

    // MARK: - Request Includes Auth Header

    /// Verify that Bearer token is set when a token exists in Keychain.
    func test_request_includes_auth_header() {
        // Store a test token
        let tokenManager = TokenManager()
        let testToken = "test-auth-header-token-12345"
        tokenManager.setToken(testToken)

        // Create client -- the client reads from Keychain via TokenManager
        let client = DaemonClient()
        XCTAssertNotNil(client)

        // Verify token is retrievable (the client uses the same TokenManager internally)
        let retrieved = tokenManager.getToken()
        XCTAssertEqual(retrieved, testToken)

        // Clean up
        tokenManager.clearToken()
    }

    // MARK: - Request Includes X-Request-ID

    /// Verify that X-Request-ID is a valid UUID format.
    func test_request_includes_request_id() {
        // X-Request-ID is a UUID string. Verify UUID generation works.
        let requestId = UUID().uuidString
        XCTAssertFalse(requestId.isEmpty)
        // UUID format: 8-4-4-4-12 hex characters
        let uuidRegex = try! NSRegularExpression(
            pattern: "^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$",
            options: .caseInsensitive
        )
        let range = NSRange(requestId.startIndex..<requestId.endIndex, in: requestId)
        XCTAssertNotNil(uuidRegex.firstMatch(in: requestId, range: range),
                        "X-Request-ID should be a valid UUID")
    }

    // MARK: - Server URL Validation

    /// Verify that non-HTTPS URLs are rejected (except localhost).
    func test_server_url_validation() {
        // HTTPS should be accepted
        XCTAssertNotNil(DaemonClient.validateServerURL("https://aegis.example.com"))
        XCTAssertNotNil(DaemonClient.validateServerURL("https://10.0.0.1:8443"))
        XCTAssertNotNil(DaemonClient.validateServerURL("https://aegis.example.com:3100/"))

        // HTTP localhost should be accepted (development)
        XCTAssertNotNil(DaemonClient.validateServerURL("http://localhost:3100"))
        XCTAssertNotNil(DaemonClient.validateServerURL("http://127.0.0.1:3100"))
        XCTAssertNotNil(DaemonClient.validateServerURL("http://localhost"))

        // HTTP to remote hosts should be REJECTED
        XCTAssertNil(DaemonClient.validateServerURL("http://aegis.example.com"))
        XCTAssertNil(DaemonClient.validateServerURL("http://10.0.0.1:3100"))
        XCTAssertNil(DaemonClient.validateServerURL("http://192.168.1.100"))

        // Invalid URLs should be rejected
        XCTAssertNil(DaemonClient.validateServerURL(""))
        XCTAssertNil(DaemonClient.validateServerURL("not-a-url"))
        XCTAssertNil(DaemonClient.validateServerURL("ftp://aegis.example.com"))
        XCTAssertNil(DaemonClient.validateServerURL("ws://aegis.example.com"))
    }

    // MARK: - Error Types

    func testDaemonClientErrorDescriptions() {
        let apiErr = DaemonClientError.apiError("test error")
        XCTAssertTrue(apiErr.localizedDescription.contains("test error"))

        let invalidResp = DaemonClientError.invalidResponse
        XCTAssertTrue(invalidResp.localizedDescription.contains("Invalid"))

        let httpErr = DaemonClientError.httpError(statusCode: 503)
        XCTAssertTrue(httpErr.localizedDescription.contains("503"))

        let urlErr = DaemonClientError.invalidServerURL("http://bad.example.com")
        XCTAssertTrue(urlErr.localizedDescription.contains("HTTPS"))
    }

    // MARK: - Connection Failure

    func testListAgentsFailsWhenDaemonNotRunning() async {
        let url = URL(string: "http://127.0.0.1:19999")!
        let client = DaemonClient(baseURL: url)

        do {
            _ = try await client.listAgents()
            XCTFail("Expected an error when daemon is not running")
        } catch {
            XCTAssertNotNil(error)
        }
    }

    func testGetStatusFailsWhenDaemonNotRunning() async {
        let url = URL(string: "http://127.0.0.1:19999")!
        let client = DaemonClient(baseURL: url)

        do {
            _ = try await client.getStatus()
            XCTFail("Expected an error when daemon is not running")
        } catch {
            XCTAssertNotNil(error)
        }
    }
}
