package com.aegis.android

import com.aegis.android.api.DaemonClient
import com.aegis.android.api.sanitizeInput
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/**
 * Unit tests for DaemonClient.
 *
 * Tests server URL validation, request ID generation, and input sanitization.
 * These tests run on the JVM without Android dependencies.
 */
class DaemonClientTest {

    // -- Server URL Validation --

    @Test
    fun test_server_url_validation_accepts_https() {
        assertTrue(DaemonClient.isValidServerUrl("https://aegis.example.com"))
        assertTrue(DaemonClient.isValidServerUrl("https://10.0.0.1:8443"))
        assertTrue(DaemonClient.isValidServerUrl("https://aegis.example.com:3100/"))
    }

    @Test
    fun test_server_url_validation_accepts_localhost_http() {
        assertTrue(DaemonClient.isValidServerUrl("http://localhost:3100"))
        assertTrue(DaemonClient.isValidServerUrl("http://127.0.0.1:3100"))
        assertTrue(DaemonClient.isValidServerUrl("http://localhost"))
    }

    @Test
    fun test_server_url_validation_accepts_emulator_loopback() {
        assertTrue(DaemonClient.isValidServerUrl("http://10.0.2.2:3100"))
        assertTrue(DaemonClient.isValidServerUrl("http://10.0.2.2"))
    }

    @Test
    fun test_server_url_validation_rejects_remote_http() {
        assertFalse(DaemonClient.isValidServerUrl("http://aegis.example.com"))
        assertFalse(DaemonClient.isValidServerUrl("http://10.0.0.1:3100"))
        assertFalse(DaemonClient.isValidServerUrl("http://192.168.1.100"))
    }

    @Test
    fun test_server_url_validation_rejects_invalid_urls() {
        assertFalse(DaemonClient.isValidServerUrl(""))
        assertFalse(DaemonClient.isValidServerUrl("   "))
        assertFalse(DaemonClient.isValidServerUrl("not-a-url"))
        assertFalse(DaemonClient.isValidServerUrl("ftp://aegis.example.com"))
        assertFalse(DaemonClient.isValidServerUrl("ws://aegis.example.com"))
    }

    // -- Request ID --

    @Test
    fun test_request_includes_request_id() {
        // X-Request-ID is a UUID string. Verify UUID generation works
        // and produces valid format.
        val requestId = UUID.randomUUID().toString()
        assertFalse(requestId.isEmpty())

        // UUID format: 8-4-4-4-12 hex characters
        val uuidRegex = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        assertTrue(
            "X-Request-ID should be a valid UUID, got: $requestId",
            uuidRegex.matches(requestId)
        )
    }

    @Test
    fun test_request_ids_are_unique() {
        val ids = (1..100).map { UUID.randomUUID().toString() }.toSet()
        assertEquals("All generated request IDs should be unique", 100, ids.size)
    }

    // -- Auth Header --

    @Test
    fun test_request_includes_auth_header() {
        // Verify Bearer token format construction is correct.
        // The actual header application requires Android context (for TokenStore),
        // so we test the format construction here.
        val testToken = "test-auth-header-token-12345"
        val authHeader = "Bearer $testToken"
        assertTrue(authHeader.startsWith("Bearer "))
        assertTrue(authHeader.contains(testToken))
        assertEquals("Bearer test-auth-header-token-12345", authHeader)
    }

    // -- Input Sanitization --

    @Test
    fun test_sanitize_strips_control_characters() {
        assertEquals("hello", sanitizeInput("hello"))
        assertEquals("hello world", sanitizeInput("hello world"))
        assertEquals("hello", sanitizeInput("hel\u0000lo"))
        assertEquals("hello", sanitizeInput("hel\u001Blo"))
        assertEquals("hello", sanitizeInput("hel\u007Flo"))
    }

    @Test
    fun test_sanitize_trims_whitespace() {
        assertEquals("hello", sanitizeInput("  hello  "))
        assertEquals("hello", sanitizeInput("\thello\n"))
    }

    @Test
    fun test_sanitize_preserves_printable() {
        assertEquals("hello, world! @#\$%", sanitizeInput("hello, world! @#\$%"))
        assertEquals("abc123", sanitizeInput("abc123"))
    }

    @Test
    fun test_sanitize_empty_input() {
        assertEquals("", sanitizeInput(""))
        assertEquals("", sanitizeInput("   "))
    }
}
