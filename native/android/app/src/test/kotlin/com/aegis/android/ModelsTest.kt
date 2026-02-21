package com.aegis.android

import com.aegis.android.api.AgentInfo
import com.aegis.android.api.AgentStatusKind
import com.aegis.android.api.ApiResponse
import com.aegis.android.api.DenyBody
import com.aegis.android.api.FleetStatus
import com.aegis.android.api.InputBody
import com.aegis.android.api.PendingRequest
import com.aegis.android.api.RiskLevel
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
 * in JSON parsing behavior.
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
