import Foundation
import UserNotifications
import SwiftUI

/// Manages local notifications for agent events on iOS.
///
/// Provides notification categories with actionable buttons:
/// - Pending approval: Approve/Deny inline actions (both require authentication)
/// - Agent crash: Restart/View actions
///
/// Notifications require user permission. The manager requests
/// authorization on init and degrades gracefully if denied.
///
/// Security notes:
/// - Approve and Deny actions require device authentication (.authenticationRequired)
/// - Deny is marked as destructive for visual distinction
/// - Notification content is truncated to prevent sensitive data overflow
/// - Request IDs and agent names are passed via userInfo for action handling
@MainActor
final class PushManager: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    /// Whether notifications are authorized by the user.
    @Published var isAuthorized: Bool = false

    // MARK: - Category and Action Identifiers

    /// Notification category for pending approval requests.
    static let approvalRequestCategory = "APPROVAL_REQUEST"

    /// Notification category for agent crash events.
    static let agentCrashCategory = "AEGIS_AGENT_CRASH"

    // Action identifiers
    static let approveAction = "AEGIS_APPROVE"
    static let denyAction = "AEGIS_DENY"
    static let restartAction = "AEGIS_RESTART"
    static let viewAction = "AEGIS_VIEW"

    override init() {
        super.init()
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        registerCategories()
        requestAuthorization()
    }

    // MARK: - Setup

    /// Request notification authorization from the user.
    func requestAuthorization() {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, error in
            Task { @MainActor in
                self?.isAuthorized = granted
                if let error = error {
                    print("[Aegis] Notification authorization error: \(error.localizedDescription)")
                }
            }
        }
    }

    /// Register notification categories with action buttons.
    ///
    /// Categories:
    /// - APPROVAL_REQUEST: Approve (auth required) / Deny (auth required, destructive)
    /// - AEGIS_AGENT_CRASH: Restart (auth required) / View (foreground)
    private func registerCategories() {
        let center = UNUserNotificationCenter.current()

        // Pending approval: Approve / Deny (both require authentication)
        let approveAction = UNNotificationAction(
            identifier: Self.approveAction,
            title: "Approve",
            options: [.authenticationRequired]
        )
        let denyAction = UNNotificationAction(
            identifier: Self.denyAction,
            title: "Deny",
            options: [.authenticationRequired, .destructive]
        )
        let approvalCategory = UNNotificationCategory(
            identifier: Self.approvalRequestCategory,
            actions: [approveAction, denyAction],
            intentIdentifiers: [],
            options: []
        )

        // Agent crash: Restart / View
        let restartAction = UNNotificationAction(
            identifier: Self.restartAction,
            title: "Restart",
            options: [.authenticationRequired]
        )
        let viewAction = UNNotificationAction(
            identifier: Self.viewAction,
            title: "View Dashboard",
            options: [.foreground]
        )
        let crashCategory = UNNotificationCategory(
            identifier: Self.agentCrashCategory,
            actions: [restartAction, viewAction],
            intentIdentifiers: [],
            options: []
        )

        center.setNotificationCategories([approvalCategory, crashCategory])
    }

    // MARK: - Schedule Notifications

    /// Post a notification for a new pending approval request.
    ///
    /// - Parameters:
    ///   - agentName: Name of the agent with the pending prompt.
    ///   - requestId: The unique pending request ID.
    ///   - prompt: The raw prompt text (truncated in the notification body).
    func notifyPendingApproval(agentName: String, requestId: String, prompt: String) {
        guard isAuthorized else { return }

        let content = UNMutableNotificationContent()
        content.title = "Aegis: Approval Needed"
        content.subtitle = agentName
        // Truncate long prompts to prevent notification overflow
        let truncated = prompt.count > 200 ? String(prompt.prefix(200)) + "..." : prompt
        content.body = truncated
        content.sound = .default
        content.categoryIdentifier = Self.approvalRequestCategory
        content.userInfo = [
            "agentName": agentName,
            "requestId": requestId,
        ]
        // Set badge to indicate pending items
        content.badge = 1

        let request = UNNotificationRequest(
            identifier: "pending-\(requestId)",
            content: content,
            trigger: nil // deliver immediately
        )

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[Aegis] Failed to deliver notification: \(error.localizedDescription)")
            }
        }
    }

    /// Post a notification for an agent crash.
    ///
    /// - Parameters:
    ///   - agentName: Name of the crashed agent.
    ///   - exitCode: The exit code of the crashed process.
    func notifyAgentCrash(agentName: String, exitCode: Int32) {
        guard isAuthorized else { return }

        let content = UNMutableNotificationContent()
        content.title = "Aegis: Agent Crashed"
        content.subtitle = agentName
        content.body = "Agent '\(agentName)' exited with code \(exitCode)"
        content.sound = .defaultCritical
        content.categoryIdentifier = Self.agentCrashCategory
        content.userInfo = [
            "agentName": agentName,
            "exitCode": exitCode,
        ]

        let request = UNNotificationRequest(
            identifier: "crash-\(agentName)-\(Date().timeIntervalSince1970)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[Aegis] Failed to deliver notification: \(error.localizedDescription)")
            }
        }
    }

    /// Clear the app badge count.
    func clearBadge() {
        UNUserNotificationCenter.current().setBadgeCount(0)
    }

    // MARK: - UNUserNotificationCenterDelegate

    /// Handle notification actions (approve, deny, restart) from the notification banner.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let userInfo = response.notification.request.content.userInfo
        let actionId = response.actionIdentifier

        Task { @MainActor in
            switch actionId {
            case Self.approveAction:
                if let agentName = userInfo["agentName"] as? String,
                   let requestId = userInfo["requestId"] as? String {
                    let client = DaemonClient()
                    try? await client.approve(requestId: requestId, agentName: agentName)
                }

            case Self.denyAction:
                if let agentName = userInfo["agentName"] as? String,
                   let requestId = userInfo["requestId"] as? String {
                    let client = DaemonClient()
                    try? await client.deny(requestId: requestId, agentName: agentName, reason: "Denied from notification")
                }

            case Self.restartAction:
                if let agentName = userInfo["agentName"] as? String {
                    let client = DaemonClient()
                    try? await client.restartAgent(name: agentName)
                }

            default:
                break
            }

            completionHandler()
        }
    }

    /// Show notifications even when the app is in the foreground.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound, .badge])
    }
}
