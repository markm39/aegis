import Foundation
import UserNotifications
import SwiftUI

/// Manages macOS notifications for agent events.
///
/// Provides notification categories with actionable buttons:
/// - Pending approval: Approve/Deny inline actions
/// - Agent crash: Restart/View actions
/// - Agent status changes: Informational notifications
///
/// Features:
/// - Native macOS notifications with action buttons
/// - Notification center integration
/// - Custom notification sounds
/// - Do Not Disturb awareness
/// - Notification grouping by agent
///
/// Notifications require user permission. The manager requests
/// authorization on init and degrades gracefully if denied.
@MainActor
final class NotificationManager: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    /// Whether notifications are authorized by the user.
    @Published var isAuthorized: Bool = false

    /// Track delivered notification IDs to avoid duplicates.
    private var deliveredIds: Set<String> = []

    /// Settings for notification preferences.
    private var settings: AppSettings { AppSettings.load() }

    // MARK: - Notification Category IDs

    static let pendingApprovalCategory = "AEGIS_PENDING_APPROVAL"
    static let agentCrashCategory = "AEGIS_AGENT_CRASH"
    static let agentStatusCategory = "AEGIS_AGENT_STATUS"
    static let batchPendingCategory = "AEGIS_BATCH_PENDING"

    // MARK: - Action IDs

    static let approveAction = "AEGIS_APPROVE"
    static let denyAction = "AEGIS_DENY"
    static let restartAction = "AEGIS_RESTART"
    static let viewAction = "AEGIS_VIEW"
    static let approveAllAction = "AEGIS_APPROVE_ALL"
    static let denyAllAction = "AEGIS_DENY_ALL"

    private var isSetUp = false

    override init() {
        super.init()
    }

    /// Call once after the SwiftUI app graph is ready (from a .task modifier).
    /// Sets this object as the notification center delegate, registers action
    /// categories, and requests user authorization.
    func setup() {
        guard !isSetUp else { return }
        isSetUp = true
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        registerCategories()
        requestAuthorization()
    }

    // MARK: - Setup

    /// Request notification authorization from the user.
    private func requestAuthorization() {
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, error in
            Task { @MainActor in
                self?.isAuthorized = granted
                if let error = error {
                    // Log but don't crash -- notifications are optional
                    print("[Aegis] Notification authorization error: \(error.localizedDescription)")
                }
            }
        }
    }

    /// Register notification categories with action buttons.
    private func registerCategories() {
        let center = UNUserNotificationCenter.current()

        // Pending approval: Approve / Deny
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
        let pendingCategory = UNNotificationCategory(
            identifier: Self.pendingApprovalCategory,
            actions: [approveAction, denyAction],
            intentIdentifiers: [],
            options: []
        )

        // Agent crash: Restart / View Dashboard
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

        // Agent status: View Dashboard
        let statusCategory = UNNotificationCategory(
            identifier: Self.agentStatusCategory,
            actions: [viewAction],
            intentIdentifiers: [],
            options: []
        )

        // Batch pending: Approve All / Deny All
        let approveAllAction = UNNotificationAction(
            identifier: Self.approveAllAction,
            title: "Approve All",
            options: [.authenticationRequired]
        )
        let denyAllAction = UNNotificationAction(
            identifier: Self.denyAllAction,
            title: "Deny All",
            options: [.authenticationRequired, .destructive]
        )
        let batchCategory = UNNotificationCategory(
            identifier: Self.batchPendingCategory,
            actions: [approveAllAction, denyAllAction, viewAction],
            intentIdentifiers: [],
            options: []
        )

        center.setNotificationCategories([pendingCategory, crashCategory, statusCategory, batchCategory])
    }

    // MARK: - Send Notifications

    /// Post a notification for a pending approval request.
    ///
    /// - Parameters:
    ///   - agentName: Name of the agent with the pending prompt.
    ///   - requestId: The unique pending request ID.
    ///   - prompt: The raw prompt text (truncated in the notification).
    func notifyPendingApproval(agentName: String, requestId: String, prompt: String) {
        guard isAuthorized else { return }

        let notificationId = "pending-\(requestId)"
        guard !deliveredIds.contains(notificationId) else { return }

        let content = UNMutableNotificationContent()
        content.title = "Aegis: Approval Needed"
        content.subtitle = agentName
        // Truncate long prompts to prevent notification overflow
        let truncated = prompt.count > 200 ? String(prompt.prefix(200)) + "..." : prompt
        content.body = truncated
        content.sound = settings.notificationSound ? .default : nil
        content.categoryIdentifier = Self.pendingApprovalCategory
        content.threadIdentifier = "aegis-agent-\(agentName)"
        content.userInfo = [
            "agentName": agentName,
            "requestId": requestId,
        ]

        let request = UNNotificationRequest(
            identifier: notificationId,
            content: content,
            trigger: nil // deliver immediately
        )

        deliveredIds.insert(notificationId)
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[Aegis] Failed to deliver notification: \(error.localizedDescription)")
            }
        }
    }

    /// Post a notification for multiple pending approvals (grouped).
    ///
    /// - Parameters:
    ///   - count: Number of pending approvals.
    ///   - agentNames: Names of agents with pending prompts.
    func notifyBatchPending(count: Int, agentNames: [String]) {
        guard isAuthorized, count > 0 else { return }

        let content = UNMutableNotificationContent()
        content.title = "Aegis: \(count) Pending Approval\(count == 1 ? "" : "s")"
        content.subtitle = agentNames.joined(separator: ", ")
        content.body = "\(count) agent request\(count == 1 ? " needs" : "s need") your attention."
        content.sound = settings.notificationSound ? .default : nil
        content.categoryIdentifier = Self.batchPendingCategory
        content.threadIdentifier = "aegis-batch-pending"
        content.userInfo = [
            "count": count,
            "agentNames": agentNames,
        ]

        let request = UNNotificationRequest(
            identifier: "batch-pending-\(Date().timeIntervalSince1970)",
            content: content,
            trigger: nil
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
        content.threadIdentifier = "aegis-agent-\(agentName)"
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

    /// Post a notification for an agent status change.
    ///
    /// - Parameters:
    ///   - agentName: Name of the agent.
    ///   - oldStatus: Previous status.
    ///   - newStatus: Current status.
    func notifyStatusChange(agentName: String, oldStatus: String, newStatus: String) {
        guard isAuthorized else { return }

        let content = UNMutableNotificationContent()
        content.title = "Aegis: Agent Status"
        content.subtitle = agentName
        content.body = "\(oldStatus) -> \(newStatus)"
        content.sound = settings.notificationSound ? .default : nil
        content.categoryIdentifier = Self.agentStatusCategory
        content.threadIdentifier = "aegis-agent-\(agentName)"
        content.userInfo = [
            "agentName": agentName,
        ]

        let request = UNNotificationRequest(
            identifier: "status-\(agentName)-\(Date().timeIntervalSince1970)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("[Aegis] Failed to deliver notification: \(error.localizedDescription)")
            }
        }
    }

    /// Remove all delivered notifications.
    func clearDelivered() {
        UNUserNotificationCenter.current().removeAllDeliveredNotifications()
        deliveredIds.removeAll()
    }

    /// Remove notifications for a specific agent.
    func clearForAgent(_ agentName: String) {
        let idsToRemove = deliveredIds.filter { $0.contains(agentName) }
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: Array(idsToRemove))
        deliveredIds.subtract(idsToRemove)
    }

    // MARK: - UNUserNotificationCenterDelegate

    /// Handle notification actions (approve, deny, restart).
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

            case Self.approveAllAction:
                let client = DaemonClient()
                // Fetch all pending and approve
                let agents = (try? await client.listAgents()) ?? []
                for agent in agents where agent.pendingCount > 0 {
                    if let prompts = try? await client.listPending(agentName: agent.name) {
                        for prompt in prompts {
                            try? await client.approve(requestId: prompt.requestId, agentName: agent.name)
                        }
                    }
                }

            case Self.denyAllAction:
                let client = DaemonClient()
                let agents = (try? await client.listAgents()) ?? []
                for agent in agents where agent.pendingCount > 0 {
                    if let prompts = try? await client.listPending(agentName: agent.name) {
                        for prompt in prompts {
                            try? await client.deny(requestId: prompt.requestId, agentName: agent.name, reason: "Denied from notification")
                        }
                    }
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
        completionHandler([.banner, .sound])
    }
}
