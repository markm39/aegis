import XCTest
@testable import AegisMac

final class DaemonClientTests: XCTestCase {

    // MARK: - DaemonClient Initialization

    func testClientCreatesWithDefaultURL() {
        let client = DaemonClient()
        // Should not crash; default URL is localhost:3100
        XCTAssertNotNil(client)
    }

    func testClientCreatesWithCustomURL() {
        let url = URL(string: "http://127.0.0.1:9999")!
        let client = DaemonClient(baseURL: url)
        XCTAssertNotNil(client)
    }

    // MARK: - Error Types

    func testDaemonClientErrorDescriptions() {
        let apiErr = DaemonClientError.apiError("test error")
        XCTAssertTrue(apiErr.localizedDescription.contains("test error"))

        let invalidResp = DaemonClientError.invalidResponse
        XCTAssertTrue(invalidResp.localizedDescription.contains("Invalid"))

        let httpErr = DaemonClientError.httpError(statusCode: 503)
        XCTAssertTrue(httpErr.localizedDescription.contains("503"))
    }

    // MARK: - Request Construction

    func testListAgentsFailsWhenDaemonNotRunning() async {
        // Use a port that nothing is listening on
        let url = URL(string: "http://127.0.0.1:19999")!
        let client = DaemonClient(baseURL: url)

        do {
            _ = try await client.listAgents()
            XCTFail("Expected an error when daemon is not running")
        } catch {
            // Expected: connection refused or timeout
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
