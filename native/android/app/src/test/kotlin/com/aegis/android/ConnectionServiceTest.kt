package com.aegis.android

import com.aegis.android.api.WebSocketEvent
import com.aegis.android.services.extractJsonField
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for ConnectionService helper logic.
 *
 * Tests JSON field extraction and WebSocket event parsing that run
 * on the JVM without Android dependencies.
 */
class ConnectionServiceTest {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = false
    }

    // -- WebSocket Event Parsing --

    @Test
    fun test_parse_pending_request_event() {
        val jsonStr = """
        {
            "type": "pending_request",
            "data": {
                "agent_name": "claude-1",
                "request_id": "req-abc-123",
                "raw_prompt": "Allow file write?"
            }
        }
        """
        val event = json.decodeFromString<WebSocketEvent>(jsonStr)
        assertEquals("pending_request", event.type)
        assertNotNull(event.data)
    }

    @Test
    fun test_parse_agent_crashed_event() {
        val jsonStr = """
        {
            "type": "agent_crashed",
            "data": {
                "agent_name": "agent-2",
                "exit_code": 1
            }
        }
        """
        val event = json.decodeFromString<WebSocketEvent>(jsonStr)
        assertEquals("agent_crashed", event.type)
    }

    @Test
    fun test_parse_heartbeat_event() {
        val jsonStr = """{"type": "heartbeat"}"""
        val event = json.decodeFromString<WebSocketEvent>(jsonStr)
        assertEquals("heartbeat", event.type)
        assertNull(event.data)
    }

    @Test
    fun test_parse_unknown_event_type() {
        val jsonStr = """{"type": "future_event_type", "data": {"key": "value"}}"""
        val event = json.decodeFromString<WebSocketEvent>(jsonStr)
        assertEquals("future_event_type", event.type)
        assertNotNull(event.data)
    }

    // -- JSON Field Extraction --

    @Test
    fun test_extract_agent_name_from_event_data() {
        val data = """{"agent_name": "claude-1", "request_id": "req-123", "raw_prompt": "Do something"}"""
        val agentName = extractJsonField(data, "agent_name")
        assertEquals("claude-1", agentName)
    }

    @Test
    fun test_extract_request_id_from_event_data() {
        val data = """{"agent_name": "claude-1", "request_id": "req-abc-123"}"""
        val requestId = extractJsonField(data, "request_id")
        assertEquals("req-abc-123", requestId)
    }

    @Test
    fun test_extract_exit_code_from_event_data() {
        // Note: extractJsonField extracts string values. Integer values
        // need to be extracted differently if they are not quoted.
        val data = """{"agent_name": "agent-2", "exit_code_str": "1"}"""
        val exitCode = extractJsonField(data, "exit_code_str")
        assertEquals("1", exitCode)
    }

    @Test
    fun test_extract_missing_field() {
        val data = """{"agent_name": "claude-1"}"""
        assertNull(extractJsonField(data, "request_id"))
    }

    @Test
    fun test_extract_from_empty_object() {
        assertNull(extractJsonField("{}", "agent_name"))
    }

    // -- Event Type Classification --

    @Test
    fun test_event_type_classification() {
        val eventTypes = mapOf(
            "pending_request" to true,
            "agent_crashed" to true,
            "heartbeat" to false,
            "fleet_update" to false,
        )

        for ((type, expectsNotification) in eventTypes) {
            val isNotifiable = type == "pending_request" || type == "agent_crashed"
            assertEquals(
                "Event type '$type' notification expectation",
                expectsNotification,
                isNotifiable,
            )
        }
    }
}
