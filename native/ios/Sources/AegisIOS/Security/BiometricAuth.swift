import Foundation
import LocalAuthentication

/// Biometric authentication (Face ID / Touch ID) for protecting app access.
///
/// Provides a simple interface to:
/// - Check if biometric authentication is available
/// - Authenticate the user with Face ID, Touch ID, or device passcode fallback
///
/// Security notes:
/// - Uses LAPolicy.deviceOwnerAuthenticationWithBiometrics for primary auth
/// - Falls back to LAPolicy.deviceOwnerAuthentication (device passcode) if
///   biometrics are unavailable or the user prefers passcode
/// - Never stores biometric data -- all evaluation is handled by the OS
/// - The LAContext is created fresh for each authentication attempt to prevent
///   context reuse attacks
enum BiometricAuth {

    /// Check if biometric authentication is available on this device.
    ///
    /// - Returns: A tuple of (available, typeName) where typeName is
    ///   "Face ID", "Touch ID", or "Biometric" (generic fallback).
    static func checkAvailability() -> (available: Bool, type: String) {
        let context = LAContext()
        var error: NSError?
        let available = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        )

        let typeName: String
        switch context.biometryType {
        case .faceID:
            typeName = "Face ID"
        case .touchID:
            typeName = "Touch ID"
        case .opticID:
            typeName = "Optic ID"
        @unknown default:
            typeName = "Biometric"
        }

        return (available, typeName)
    }

    /// Authenticate the user using biometrics with device passcode fallback.
    ///
    /// Creates a fresh LAContext for each attempt. If biometrics fail or are
    /// unavailable, the system will automatically prompt for the device passcode.
    ///
    /// - Parameters:
    ///   - reason: Localized string explaining why authentication is needed.
    ///   - completion: Called on the main thread with the authentication result.
    static func authenticate(reason: String, completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        context.localizedFallbackTitle = "Use Passcode"

        // Check if biometrics are available
        var error: NSError?
        let biometricsAvailable = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        )

        // Use biometrics if available, otherwise fall back to device passcode
        let policy: LAPolicy = biometricsAvailable
            ? .deviceOwnerAuthenticationWithBiometrics
            : .deviceOwnerAuthentication

        context.evaluatePolicy(policy, localizedReason: reason) { success, authError in
            DispatchQueue.main.async {
                if success {
                    completion(true)
                } else {
                    // If biometrics failed, try device passcode as fallback
                    if biometricsAvailable, let laError = authError as? LAError,
                       laError.code == .userFallback || laError.code == .biometryLockout {
                        let fallbackContext = LAContext()
                        fallbackContext.evaluatePolicy(
                            .deviceOwnerAuthentication,
                            localizedReason: reason
                        ) { fallbackSuccess, _ in
                            DispatchQueue.main.async {
                                completion(fallbackSuccess)
                            }
                        }
                    } else {
                        completion(false)
                    }
                }
            }
        }
    }
}
