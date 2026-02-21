package com.aegis.android

import com.aegis.android.security.TokenStore
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for TokenStore validation logic.
 *
 * These tests exercise the static format validation which runs on the JVM
 * without Android dependencies. The actual EncryptedSharedPreferences
 * integration requires Android instrumentation tests.
 */
class TokenStoreTest {

    // -- Token Length Validation --

    @Test
    fun test_token_validation_rejects_short() {
        assertFalse(TokenStore.isValidFormat(""))
        assertFalse(TokenStore.isValidFormat("short"))
        assertFalse(TokenStore.isValidFormat("1234567"))  // 7 chars, minimum is 8
        assertFalse(TokenStore.isValidFormat("a"))
    }

    @Test
    fun test_token_validation_accepts_minimum_length() {
        assertTrue(TokenStore.isValidFormat("12345678"))  // exactly 8 chars
        assertTrue(TokenStore.isValidFormat("abcdefgh"))
    }

    @Test
    fun test_token_validation_accepts_long_tokens() {
        assertTrue(TokenStore.isValidFormat("this-is-a-very-long-api-token-1234567890"))
        assertTrue(TokenStore.isValidFormat("a".repeat(256)))
    }

    // -- Whitespace Rejection --

    @Test
    fun test_token_validation_rejects_whitespace() {
        assertFalse(TokenStore.isValidFormat("has space here"))
        assertFalse(TokenStore.isValidFormat("has\nnewline"))
        assertFalse(TokenStore.isValidFormat("has\ttab1234"))
        assertFalse(TokenStore.isValidFormat("trailing "))
        assertFalse(TokenStore.isValidFormat(" leading1"))
    }

    // -- Control Character Rejection --

    @Test
    fun test_token_validation_rejects_control_characters() {
        assertFalse(TokenStore.isValidFormat("has\u0000null1234"))
        assertFalse(TokenStore.isValidFormat("has\u001Bescape1"))
        assertFalse(TokenStore.isValidFormat("has\u007Fdelete1"))
        assertFalse(TokenStore.isValidFormat("abc\u0001defghij"))
    }

    // -- Valid Token Formats --

    @Test
    fun test_token_validation_accepts_valid_formats() {
        assertTrue(TokenStore.isValidFormat("sk-ant-1234567890abcdef"))
        assertTrue(TokenStore.isValidFormat("aegis_daemon_token_v1"))
        assertTrue(TokenStore.isValidFormat("ABCDEFGHabcdefgh12345678!@#\$%"))
        assertTrue(TokenStore.isValidFormat("token-with-dashes"))
        assertTrue(TokenStore.isValidFormat("token_with_underscores"))
    }

    // -- Minimum Length Constant --

    @Test
    fun test_minimum_token_length_is_8() {
        // Verify the constant matches the documented minimum
        assertTrue(TokenStore.MINIMUM_TOKEN_LENGTH == 8)
    }
}
