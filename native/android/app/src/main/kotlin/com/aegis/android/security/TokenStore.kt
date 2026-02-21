package com.aegis.android.security

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Secure token storage backed by EncryptedSharedPreferences and Android Keystore.
 *
 * All secrets are encrypted using a MasterKey stored in the Android Keystore
 * hardware-backed (when available) security module. The key material never
 * leaves the Keystore and cannot be extracted.
 *
 * Security properties:
 * - AES-256-SIV for key encryption, AES-256-GCM for value encryption
 * - MasterKey is backed by Android Keystore (hardware-backed on supported devices)
 * - Encrypted preferences file is scoped to this app's private storage
 * - Token format validation: minimum 8 characters, no whitespace or control characters
 * - Tokens are never logged or included in error messages
 */
class TokenStore(context: Context) {

    private val masterKey: MasterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        PREFS_FILE_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    /**
     * Retrieve the stored API token.
     *
     * @return The token string, or null if no valid token is stored.
     */
    fun getToken(): String? {
        val token = prefs.getString(KEY_API_TOKEN, null) ?: return null
        return if (isValidFormat(token)) token else null
    }

    /**
     * Store a new API token.
     *
     * @param token The API token to store. Must pass format validation.
     * @return true if the token was stored successfully, false if validation failed.
     */
    fun saveToken(token: String): Boolean {
        if (!isValidFormat(token)) return false
        prefs.edit().putString(KEY_API_TOKEN, token).apply()
        return true
    }

    /**
     * Remove the stored API token.
     */
    fun deleteToken() {
        prefs.edit().remove(KEY_API_TOKEN).apply()
    }

    /**
     * Check whether a token is currently stored.
     */
    fun hasToken(): Boolean {
        return prefs.contains(KEY_API_TOKEN)
    }

    /**
     * Retrieve the stored server URL.
     *
     * @return The server URL, or the default localhost URL.
     */
    fun getServerUrl(): String {
        return prefs.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL) ?: DEFAULT_SERVER_URL
    }

    /**
     * Store the server URL.
     */
    fun saveServerUrl(url: String) {
        prefs.edit().putString(KEY_SERVER_URL, url).apply()
    }

    /**
     * Check whether biometric authentication is enabled.
     */
    fun isBiometricEnabled(): Boolean {
        return prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false)
    }

    /**
     * Set the biometric authentication preference.
     */
    fun setBiometricEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, enabled).apply()
    }

    /**
     * Check whether notifications are enabled.
     */
    fun isNotificationsEnabled(): Boolean {
        return prefs.getBoolean(KEY_NOTIFICATIONS_ENABLED, true)
    }

    /**
     * Set the notifications preference.
     */
    fun setNotificationsEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_NOTIFICATIONS_ENABLED, enabled).apply()
    }

    companion object {
        private const val PREFS_FILE_NAME = "aegis_secure_prefs"
        private const val KEY_API_TOKEN = "aegis_daemon_api_token"
        private const val KEY_SERVER_URL = "aegis_server_url"
        private const val KEY_BIOMETRIC_ENABLED = "aegis_biometric_enabled"
        private const val KEY_NOTIFICATIONS_ENABLED = "aegis_notifications_enabled"
        const val DEFAULT_SERVER_URL = "http://localhost:3100"

        /** Minimum acceptable token length to prevent empty/trivial tokens. */
        const val MINIMUM_TOKEN_LENGTH = 8

        /**
         * Validate the token format.
         *
         * This is a local format check only -- it does not verify the token
         * against the daemon. Checks:
         * - Non-empty
         * - Minimum length (8 characters)
         * - No whitespace or control characters (injection prevention)
         */
        fun isValidFormat(token: String): Boolean {
            if (token.length < MINIMUM_TOKEN_LENGTH) return false
            // Reject tokens with whitespace or control characters
            return token.none { ch ->
                ch.isWhitespace() || ch.code < 0x20 || ch.code == 0x7F
            }
        }
    }
}
