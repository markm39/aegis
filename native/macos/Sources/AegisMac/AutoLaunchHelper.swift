import Foundation
import ServiceManagement

/// Manages registering/unregistering the app as a login item.
///
/// Uses SMAppService (macOS 13+) for modern login item management.
/// Falls back gracefully if registration fails (e.g., sandboxing restrictions).
enum AutoLaunchHelper {
    /// Register or unregister as a login item.
    ///
    /// - Parameter enabled: Whether to enable launch at login.
    static func setEnabled(_ enabled: Bool) {
        let service = SMAppService.mainApp

        do {
            if enabled {
                try service.register()
            } else {
                try service.unregister()
            }
        } catch {
            print("[Aegis] Failed to \(enabled ? "register" : "unregister") login item: \(error.localizedDescription)")
        }
    }

    /// Check whether the app is currently registered as a login item.
    ///
    /// - Returns: True if the app is registered to launch at login.
    static func isEnabled() -> Bool {
        let service = SMAppService.mainApp
        return service.status == .enabled
    }

    /// Get the current registration status as a human-readable string.
    static var statusDescription: String {
        let service = SMAppService.mainApp
        switch service.status {
        case .enabled:
            return "Enabled"
        case .notRegistered:
            return "Not Registered"
        case .notFound:
            return "Not Found"
        case .requiresApproval:
            return "Requires Approval"
        @unknown default:
            return "Unknown"
        }
    }
}
