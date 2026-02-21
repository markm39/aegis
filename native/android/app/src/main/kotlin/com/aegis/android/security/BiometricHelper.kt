package com.aegis.android.security

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * Biometric authentication helper using AndroidX BiometricPrompt.
 *
 * Provides Face/Fingerprint authentication with device credential (PIN/pattern/password)
 * fallback. A fresh BiometricPrompt is created for each authentication attempt to
 * prevent context reuse.
 *
 * Security notes:
 * - Uses BiometricManager.Authenticators.BIOMETRIC_STRONG for primary auth
 * - Falls back to DEVICE_CREDENTIAL if biometrics are unavailable
 * - Never stores biometric data -- all evaluation is handled by the OS
 * - The prompt title and description clearly indicate the purpose
 */
object BiometricHelper {

    /**
     * Allowed authenticator types: strong biometric OR device credential (PIN/pattern).
     */
    private const val AUTHENTICATORS =
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
        BiometricManager.Authenticators.DEVICE_CREDENTIAL

    /**
     * Check if biometric or device credential authentication is available.
     *
     * @param activity The current activity context.
     * @return true if the device supports at least one authentication method.
     */
    fun canAuthenticate(activity: FragmentActivity): Boolean {
        val biometricManager = BiometricManager.from(activity)
        return biometricManager.canAuthenticate(AUTHENTICATORS) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Check if strong biometric (face/fingerprint) authentication is specifically available.
     *
     * @param activity The current activity context.
     * @return true if biometric hardware is present and enrolled.
     */
    fun hasBiometricHardware(activity: FragmentActivity): Boolean {
        val biometricManager = BiometricManager.from(activity)
        val result = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        )
        return result == BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Show the biometric authentication prompt.
     *
     * Creates a fresh BiometricPrompt for each invocation. If biometrics fail
     * or are unavailable, the system automatically offers device credential
     * (PIN/pattern/password) as fallback.
     *
     * @param activity The FragmentActivity hosting the prompt.
     * @param title The prompt title (e.g., "Unlock Aegis").
     * @param subtitle Optional subtitle text.
     * @param onSuccess Called on the main thread when authentication succeeds.
     * @param onFailure Called on the main thread when authentication fails.
     * @param onError Called on the main thread when an unrecoverable error occurs.
     *                Receives the error code and human-readable message.
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String = "Unlock Aegis",
        subtitle: String? = "Authenticate to access your agent fleet",
        onSuccess: () -> Unit,
        onFailure: () -> Unit = {},
        onError: (errorCode: Int, errString: CharSequence) -> Unit = { _, _ -> },
    ) {
        val executor = ContextCompat.getMainExecutor(activity)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onSuccess()
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                onFailure()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                onError(errorCode, errString)
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .apply {
                if (subtitle != null) setSubtitle(subtitle)
            }
            // Allow device credential (PIN/pattern) as fallback.
            // When DEVICE_CREDENTIAL is set, setNegativeButtonText must NOT be called.
            .setAllowedAuthenticators(AUTHENTICATORS)
            .build()

        prompt.authenticate(promptInfo)
    }
}
