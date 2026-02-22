package com.aegis.android

import com.aegis.android.api.AgentInfo
import com.aegis.android.api.AgentStatusKind
import com.aegis.android.api.ApiResponse
import com.aegis.android.api.ChatMessage
import com.aegis.android.api.DenyBody
import com.aegis.android.api.FleetStatus
import com.aegis.android.api.InputBody
import com.aegis.android.api.LocationData
import com.aegis.android.api.MessageRole
import com.aegis.android.api.PairingInfo
import com.aegis.android.api.PendingRequest
import com.aegis.android.api.RiskLevel
import com.aegis.android.api.WebSocketEvent
import com.aegis.android.api.WidgetState
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for API model deserialization.
 *
 * These mirror the iOS ModelsTests to ensure cross-platform consistency
 * in JSON parsing behavior. Also tests new chat, location, pairing, and
 * widget models.
 */
class ModelsTest {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = false
    }

    // -- Agent Info Deserialization --

    @Test
    fun test_agent_info_deserialization() {
        val jsonString = """
        {
            "name": "claude-1",
            "status": "Pending",
            "tool": "ClaudeCode",
            "working_dir": "/tmp/work",
            "role": "coder",
            "restart_count": 0,
            "pending_count": 2,
            "attention_needed": false,
            "is_orchestrator": false
        }
        """
        val agent = json.decodeFromString<AgentInfo>(jsonString)
        assertEquals("claude-1", agent.name)
        assertEquals(AgentStatusKind.PENDING, agent.statusKind)
        assertEquals("ClaudeCode", agent.tool)
        assertEquals("/tmp/work", agent.workingDir)
        assertEquals("coder", agent.role)
        assertEquals(0, agent.restartCount)
        assertEquals(2, agent.pendingCount)
        assertFalse(agent.attentionNeeded)
        assertFalse(agent.isOrchestrator)
    }

    @Test
    fun test_agent_info_tagged_status() {
        val jsonString = """
        {
            "name": "agent-2",
            "status": {"Running": {"pid": 12345}},
            "tool": "Generic",
            "working_dir": "/home/user",
            "restart_count": 2,
            "pending_count": 3,
            "attention_needed": true,
            "is_orchestrator": true
        }
        """
        val agent = json.decodeFromString<AgentInfo>(jsonString)
        assertEquals("agent-2", agent.name)
        assertEquals(AgentStatusKind.RUNNING, agent.statusKind)
        assertEquals(3, agent.pendingCount)
        assertTrue(agent.attentionNeeded)
        assertTrue(agent.isOrchestrator)
    }

    @Test
    fun test_agent_info_crashed_status() {
        val jsonString = """
        {
            "name": "agent-3",
            "status": {"Crashed": {"exit_code": 1, "restart_in_secs": 30}},
            "tool": "ClaudeCode",
            "working_dir": "/tmp",
            "restart_count": 5,
            "pending_count": 0,
            "attention_needed": false,
            "is_orchestrator": false
        }
        """
        val agent = json.decodeFromString<AgentInfo>(jsonString)
        assertEquals(AgentStatusKind.CRASHED, agent.statusKind)
        assertEquals(5, agent.restartCount)
    }

    @Test
    fun test_agent_info_nil_role() {
        val jsonString = """
        {
            "name": "agent-4",
            "status": "Stopped",
            "tool": "Generic",
            "working_dir": "/tmp",
            "restart_count": 0,
            "pending_count": 0,
            "attention_needed": false,
            "is_orchestrator": false
        }
        """
        val agent = json.decodeFromString<AgentInfo>(jsonString)
        assertNull(agent.role)
        assertEquals(AgentStatusKind.STOPPED, agent.statusKind)
    }

    // -- Pending Request Deserialization --

    @Test
    fun test_pending_request_deserialization() {
        val jsonString = """
        {
            "request_id": "abc-123",
            "raw_prompt": "Allow file write to /etc/passwd?",
            "age_secs": 45
        }
        """
        val prompt = json.decodeFromString<PendingRequest>(jsonString)
        assertEquals("abc-123", prompt.requestId)
        assertEquals("Allow file write to /etc/passwd?", prompt.rawPrompt)
        assertEquals(45L, prompt.ageSecs)
        assertEquals("", prompt.agentName)  // default when not provided
    }

    @Test
    fun test_pending_request_with_agent_name() {
        val jsonString = """
        {
            "request_id": "def-456",
            "raw_prompt": "Execute bash command?",
            "age_secs": 10,
            "agent_name": "claude-1"
        }
        """
        val prompt = json.decodeFromString<PendingRequest>(jsonString)
        assertEquals("claude-1", prompt.agentName)
    }

    // -- Risk Level --

    @Test
    fun test_high_risk_detection() {
        val prompt = PendingRequest(
            requestId = "1",
            rawPrompt = "rm -rf /important/data",
            ageSecs = 5,
            agentName = "test",
        )
        assertEquals(RiskLevel.HIGH, prompt.riskLevel)

        val passwordPrompt = PendingRequest(
            requestId = "2",
            rawPrompt = "Read password from config",
            ageSecs = 5,
            agentName = "test",
        )
        assertEquals(RiskLevel.HIGH, passwordPrompt.riskLevel)
    }

    @Test
    fun test_medium_risk_detection() {
        val prompt = PendingRequest(
            requestId = "1",
            rawPrompt = "Write file to /tmp/output.txt",
            ageSecs = 5,
            agentName = "test",
        )
        assertEquals(RiskLevel.MEDIUM, prompt.riskLevel)

        val installPrompt = PendingRequest(
            requestId = "2",
            rawPrompt = "npm install express",
            ageSecs = 5,
            agentName = "test",
        )
        assertEquals(RiskLevel.MEDIUM, installPrompt.riskLevel)
    }

    @Test
    fun test_low_risk_detection() {
        val prompt = PendingRequest(
            requestId = "1",
            rawPrompt = "Read file contents",
            ageSecs = 5,
            agentName = "test",
        )
        assertEquals(RiskLevel.LOW, prompt.riskLevel)
    }

    // -- FleetStatus --

    @Test
    fun test_fleet_status_deserialization() {
        val jsonString = """
        {
            "agents": [],
            "total_pending": 5
        }
        """
        val status = json.decodeFromString<FleetStatus>(jsonString)
        assertEquals(5, status.totalPending)
        assertTrue(status.agents.isEmpty())
    }

    // -- API Response --

    @Test
    fun test_success_response() {
        val jsonString = """{"ok": true, "message": "success", "data": null}"""
        val response = json.decodeFromString<ApiResponse>(jsonString)
        assertTrue(response.ok)
        assertEquals("success", response.message)
    }

    @Test
    fun test_error_response() {
        val jsonString = """{"ok": false, "message": "agent not found"}"""
        val response = json.decodeFromString<ApiResponse>(jsonString)
        assertFalse(response.ok)
        assertEquals("agent not found", response.message)
    }

    @Test
    fun test_response_with_data() {
        val jsonString = """{"ok": true, "message": "found", "data": {"count": 3, "items": ["a", "b"]}}"""
        val response = json.decodeFromString<ApiResponse>(jsonString)
        assertTrue(response.ok)
        assertNotNull(response.data)
    }

    // -- Request Bodies --

    @Test
    fun test_input_body_serialization() {
        val body = InputBody(text = "hello agent")
        val serialized = json.encodeToString(InputBody.serializer(), body)
        assertTrue(serialized.contains("\"text\""))
        assertTrue(serialized.contains("hello agent"))
    }

    @Test
    fun test_deny_body_serialization() {
        val body = DenyBody(reason = "too risky")
        val serialized = json.encodeToString(DenyBody.serializer(), body)
        assertTrue(serialized.contains("\"reason\""))
        assertTrue(serialized.contains("too risky"))
    }

    @Test
    fun test_deny_body_null_reason() {
        val body = DenyBody(reason = null)
        val serialized = json.encodeToString(DenyBody.serializer(), body)
        assertTrue(serialized.contains("null"))
    }

    // -- Status Kind --

    @Test
    fun test_status_kind_display_names() {
        assertEquals("Running", AgentStatusKind.RUNNING.displayName)
        assertEquals("Pending", AgentStatusKind.PENDING.displayName)
        assertEquals("Stopped", AgentStatusKind.STOPPED.displayName)
        assertEquals("Crashed", AgentStatusKind.CRASHED.displayName)
        assertEquals("Failed", AgentStatusKind.FAILED.displayName)
        assertEquals("Stopping", AgentStatusKind.STOPPING.displayName)
        assertEquals("Disabled", AgentStatusKind.DISABLED.displayName)
    }

    // -- Chat Models --

    @Test
    fun test_chat_message_deserialization() {
        val jsonString = """
        {
            "id": "msg-001",
            "role": "user",
            "content": "Hello agent",
            "timestamp": 1700000000000,
            "agent_name": "claude-1"
        }
        """
        val msg = json.decodeFromString<ChatMessage>(jsonString)
        assertEquals("msg-001", msg.id)
        assertEquals(MessageRole.USER, msg.role)
        assertEquals("Hello agent", msg.content)
        assertEquals(1700000000000L, msg.timestamp)
        assertEquals("claude-1", msg.agentName)
    }

    @Test
    fun test_chat_message_agent_role() {
        val jsonString = """
        {
            "id": "msg-002",
            "role": "agent",
            "content": "I can help with that.",
            "timestamp": 1700000001000
        }
        """
        val msg = json.decodeFromString<ChatMessage>(jsonString)
        assertEquals(MessageRole.AGENT, msg.role)
    }

    @Test
    fun test_chat_message_system_role() {
        val jsonString = """
        {
            "id": "msg-003",
            "role": "system",
            "content": "Agent connected.",
            "timestamp": 1700000002000
        }
        """
        val msg = json.decodeFromString<ChatMessage>(jsonString)
        assertEquals(MessageRole.SYSTEM, msg.role)
    }

    @Test
    fun test_chat_message_serialization() {
        val msg = ChatMessage(
            id = "test-id",
            role = MessageRole.USER,
            content = "test message",
            timestamp = 12345L,
            agentName = "test-agent",
        )
        val serialized = json.encodeToString(ChatMessage.serializer(), msg)
        assertTrue(serialized.contains("\"id\":\"test-id\""))
        assertTrue(serialized.contains("\"role\":\"user\""))
        assertTrue(serialized.contains("\"content\":\"test message\""))
    }

    // -- Pairing Models --

    @Test
    fun test_pairing_info_deserialization() {
        val jsonString = """
        {
            "server_url": "https://aegis.example.com:3100",
            "token": "sk-test-token-1234567890",
            "name": "Home Server"
        }
        """
        val info = json.decodeFromString<PairingInfo>(jsonString)
        assertEquals("https://aegis.example.com:3100", info.serverUrl)
        assertEquals("sk-test-token-1234567890", info.token)
        assertEquals("Home Server", info.name)
    }

    @Test
    fun test_pairing_info_without_name() {
        val jsonString = """
        {
            "server_url": "http://localhost:3100",
            "token": "dev-token-abcdefgh"
        }
        """
        val info = json.decodeFromString<PairingInfo>(jsonString)
        assertEquals("http://localhost:3100", info.serverUrl)
        assertNull(info.name)
    }

    // -- Location Models --

    @Test
    fun test_location_data_serialization() {
        val location = LocationData(
            latitude = 37.7749,
            longitude = -122.4194,
            accuracy = 10.0f,
            altitude = 15.0,
            timestamp = 1700000000000L,
        )
        val serialized = json.encodeToString(LocationData.serializer(), location)
        assertTrue(serialized.contains("37.7749"))
        assertTrue(serialized.contains("-122.4194"))
        assertTrue(serialized.contains("\"accuracy\""))
        assertTrue(serialized.contains("\"altitude\""))
    }

    @Test
    fun test_location_data_without_optional_fields() {
        val location = LocationData(
            latitude = 40.7128,
            longitude = -74.0060,
        )
        val serialized = json.encodeToString(LocationData.serializer(), location)
        assertTrue(serialized.contains("40.7128"))
        assertTrue(serialized.contains("-74.006"))
    }

    // -- WebSocket Models --

    @Test
    fun test_websocket_event_deserialization() {
        val jsonString = """
        {
            "type": "pending_request",
            "data": {"agent_name": "claude-1", "request_id": "req-123"}
        }
        """
        val event = json.decodeFromString<WebSocketEvent>(jsonString)
        assertEquals("pending_request", event.type)
        assertNotNull(event.data)
    }

    @Test
    fun test_websocket_event_without_data() {
        val jsonString = """{"type": "heartbeat"}"""
        val event = json.decodeFromString<WebSocketEvent>(jsonString)
        assertEquals("heartbeat", event.type)
        assertNull(event.data)
    }

    // -- Widget State --

    @Test
    fun test_widget_state_defaults() {
        val state = WidgetState()
        assertEquals(0, state.agentCount)
        assertEquals(0, state.runningCount)
        assertEquals(0, state.pendingCount)
        assertFalse(state.isConnected)
        assertEquals(0L, state.lastUpdated)
    }

    @Test
    fun test_widget_state_with_values() {
        val state = WidgetState(
            agentCount = 5,
            runningCount = 3,
            pendingCount = 2,
            isConnected = true,
            lastUpdated = 1700000000000L,
        )
        assertEquals(5, state.agentCount)
        assertEquals(3, state.runningCount)
        assertEquals(2, state.pendingCount)
        assertTrue(state.isConnected)
    }

    // -- Invalid JSON --

    @Test(expected = Exception::class)
    fun test_invalid_json_returns_error() {
        val malformed = """{ "name": "broken-agent", "status": }"""
        json.decodeFromString<AgentInfo>(malformed)
    }

    @Test(expected = Exception::class)
    fun test_missing_required_fields() {
        val incomplete = """{ "name": "partial-agent" }"""
        json.decodeFromString<AgentInfo>(incomplete)
    }

    @Test(expected = Exception::class)
    fun test_empty_json() {
        json.decodeFromString<AgentInfo>("{}")
    }
}
