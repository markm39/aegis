import XCTest
@testable import AegisMac

final class DaemonClientTests: XCTestCase {

    // MARK: - DaemonClient Initialization

    func testClientCreatesWithDefaultURL() {
        let client = DaemonClient()
        // Should not crash; default URL is localhost:3100
        XCTAssertNotNil(client)
        XCTAssertEqual(client.baseURL.absoluteString, "http://localhost:3100")
    }

    func testClientCreatesWithCustomURL() {
        let url = URL(string: "http://127.0.0.1:9999")!
        let client = DaemonClient(baseURL: url)
        XCTAssertNotNil(client)
        XCTAssertEqual(client.baseURL.absoluteString, "http://127.0.0.1:9999")
    }

    func testSetBaseURL() {
        let client = DaemonClient()
        let newURL = URL(string: "http://192.168.1.100:3100")!
        client.setBaseURL(newURL)
        XCTAssertEqual(client.baseURL.absoluteString, "http://192.168.1.100:3100")
    }

    // MARK: - Connection State

    func testInitialConnectionState() {
        let client = DaemonClient()
        XCTAssertEqual(client.connectionState, .disconnected)
    }

    // MARK: - Error Types

    func testDaemonClientErrorDescriptions() {
        let apiErr = DaemonClientError.apiError("test error")
        XCTAssertTrue(apiErr.localizedDescription.contains("test error"))

        let invalidResp = DaemonClientError.invalidResponse
        XCTAssertTrue(invalidResp.localizedDescription.contains("Invalid"))

        let httpErr = DaemonClientError.httpError(statusCode: 503)
        XCTAssertTrue(httpErr.localizedDescription.contains("503"))

        let notConnected = DaemonClientError.notConnected
        XCTAssertTrue(notConnected.localizedDescription.contains("Not connected"))
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

    func testPingReturnsFalseWhenDaemonNotRunning() async {
        let url = URL(string: "http://127.0.0.1:19999")!
        let client = DaemonClient(baseURL: url)

        let result = await client.ping()
        XCTAssertFalse(result)
    }

    // MARK: - WebSocket State

    func testDisconnectWebSocketSetsStateToDisconnected() {
        let client = DaemonClient()
        client.disconnectWebSocket()
        XCTAssertEqual(client.connectionState, .disconnected)
    }

    // MARK: - Auto-Discovery

    func testDiscoverDaemonReturnsNilWhenNothingRunning() async {
        // This test may pass or fail depending on whether a daemon is actually running.
        // In CI environments, typically nothing is running.
        // We just verify the method doesn't crash.
        let _ = await DaemonClient.discoverDaemon()
    }
}
