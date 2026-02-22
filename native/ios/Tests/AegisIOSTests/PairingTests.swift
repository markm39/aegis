import XCTest
@testable import AegisIOS

final class PairingTests: XCTestCase {

    // MARK: - Pairing Error Descriptions

    func testPairingErrorDescriptions() {
        let invalidCode = PairingError.invalidCode
        XCTAssertTrue(invalidCode.localizedDescription.contains("Invalid pairing code"))

        let invalidURL = PairingError.invalidURL("http://bad.com")
        XCTAssertTrue(invalidURL.localizedDescription.contains("Invalid server URL"))
        XCTAssertTrue(invalidURL.localizedDescription.contains("bad.com"))

        let keychainErr = PairingError.keychainError
        XCTAssertTrue(keychainErr.localizedDescription.contains("Keychain"))

        let connFailed = PairingError.connectionFailed("timeout")
        XCTAssertTrue(connFailed.localizedDescription.contains("timeout"))
    }

    // MARK: - Notification Category

    func testNotificationCategoryProperties() {
        XCTAssertEqual(NotificationCategory.approval.iconName, "bell.badge")
        XCTAssertEqual(NotificationCategory.crash.iconName, "exclamationmark.triangle.fill")
        XCTAssertEqual(NotificationCategory.statusChange.iconName, "arrow.left.arrow.right")
    }

    func testNotificationCategoryRawValues() {
        XCTAssertEqual(NotificationCategory.approval.rawValue, "Approval")
        XCTAssertEqual(NotificationCategory.crash.rawValue, "Crash")
        XCTAssertEqual(NotificationCategory.statusChange.rawValue, "Status Change")
    }

    // MARK: - Notification Record

    func testNotificationRecordTimeAgo() {
        let record = NotificationRecord(
            title: "Test",
            subtitle: "agent-1",
            body: "test body",
            category: .approval,
            agentName: "agent-1",
            timestamp: Date()
        )

        // Just created, should say seconds ago
        XCTAssertTrue(record.timeAgo.contains("s ago"))
        XCTAssertFalse(record.id.uuidString.isEmpty)
    }

    func testNotificationRecordOlderTimestamp() {
        let fiveMinutesAgo = Date().addingTimeInterval(-300)
        let record = NotificationRecord(
            title: "Test",
            subtitle: "agent-1",
            body: "test body",
            category: .crash,
            agentName: "agent-1",
            timestamp: fiveMinutesAgo
        )

        XCTAssertTrue(record.timeAgo.contains("m ago"))
    }

    func testNotificationRecordHoursAgo() {
        let twoHoursAgo = Date().addingTimeInterval(-7200)
        let record = NotificationRecord(
            title: "Test",
            subtitle: "agent-1",
            body: "test body",
            category: .statusChange,
            agentName: "agent-1",
            timestamp: twoHoursAgo
        )

        XCTAssertTrue(record.timeAgo.contains("h ago"))
    }
}
