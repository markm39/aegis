package com.aegis.android.api

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * Data models matching the Aegis daemon HTTP API.
 *
 * These mirror the Rust types serialized by serde_json on the daemon side.
 * Field names use snake_case via @SerialName to match the JSON wire format.
 */

// -- API Response Envelope --

/**
 * Generic response envelope matching the daemon's CommandResponse / DaemonResponse.
 */
@Serializable
data class ApiResponse(
    val ok: Boolean,
    val message: String,
    val data: JsonElement? = null,
)

// -- Agent Models --

/**
 * Agent status kind, matching Rust AgentStatus enum variants.
 * The daemon serializes status as either a bare string ("Pending") or a
 * tagged object ({"Running": {"pid": 123}}).
 */
enum class AgentStatusKind(val displayName: String) {
    PENDING("Pending"),
    RUNNING("Running"),
    STOPPED("Stopped"),
    CRASHED("Crashed"),
    FAILED("Failed"),
    STOPPING("Stopping"),
    DISABLED("Disabled");

    companion object {
        /**
         * Parse a status kind from a raw JSON status value.
         *
         * Handles both bare string variants ("Pending") and tagged objects
         * ({"Running": {"pid": 123}}) produced by serde's default enum serialization.
         */
        fun fromRawStatus(raw: JsonElement): AgentStatusKind {
            // Try as a bare string
            val str = raw.toString().trim('"')
            entries.forEach { kind ->
                if (kind.displayName == str) return kind
            }
            // Try as a tagged object -- look for a matching key
            if (raw.toString().startsWith("{")) {
                entries.forEach { kind ->
                    if (raw.toString().contains("\"${kind.displayName}\"")) return kind
                }
            }
            return PENDING
        }
    }
}

/**
 * Agent info matching the daemon's AgentSummary JSON shape.
 */
@Serializable
data class AgentInfo(
    val name: String,
    val status: JsonElement,
    val tool: String,
    @SerialName("working_dir") val workingDir: String,
    val role: String? = null,
    @SerialName("restart_count") val restartCount: Int = 0,
    @SerialName("pending_count") val pendingCount: Int = 0,
    @SerialName("attention_needed") val attentionNeeded: Boolean = false,
    @SerialName("is_orchestrator") val isOrchestrator: Boolean = false,
) {
    /** Parse the status enum variant from the JSON representation. */
    val statusKind: AgentStatusKind
        get() = AgentStatusKind.fromRawStatus(status)
}

// -- Fleet Status --

/**
 * Top-level fleet status summary.
 */
@Serializable
data class FleetStatus(
    val agents: List<AgentInfo>,
    @SerialName("total_pending") val totalPending: Int,
)

// -- Pending Prompt --

/**
 * Pending permission prompt matching the daemon's PendingPromptSummary.
 */
@Serializable
data class PendingRequest(
    @SerialName("request_id") val requestId: String,
    @SerialName("raw_prompt") val rawPrompt: String,
    @SerialName("age_secs") val ageSecs: Long,
    @SerialName("agent_name") val agentName: String = "",
) {
    /**
     * Estimate risk level based on prompt content.
     *
     * This is a heuristic for visual indication only -- the daemon's policy
     * engine makes the real security decisions.
     */
    val riskLevel: RiskLevel
        get() {
            val lower = rawPrompt.lowercase()

            // High risk: destructive operations, system modifications, credential access
            val highRiskPatterns = listOf(
                "rm -rf", "delete", "drop table", "format",
                "/etc/", "/system/", "sudo", "chmod 777",
                "password", "credential", "secret", "token",
                "curl | sh", "curl | bash",
                ".ssh/", "authorized_keys", "id_rsa"
            )
            if (highRiskPatterns.any { lower.contains(it) }) {
                return RiskLevel.HIGH
            }

            // Medium risk: file writes, network access, process spawning
            val mediumRiskPatterns = listOf(
                "write", "modify", "create", "install",
                "download", "upload", "fetch", "curl",
                "run", "spawn", "bash", "sh -c",
                "pip install", "npm install", "cargo install"
            )
            if (mediumRiskPatterns.any { lower.contains(it) }) {
                return RiskLevel.MEDIUM
            }

            return RiskLevel.LOW
        }
}

/**
 * Visual risk level for pending requests.
 */
enum class RiskLevel(val displayName: String) {
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High"),
}

// -- Chat Models --

/**
 * A single message in a chat conversation with an agent.
 */
@Serializable
data class ChatMessage(
    val id: String,
    val role: MessageRole,
    val content: String,
    val timestamp: Long = System.currentTimeMillis(),
    @SerialName("agent_name") val agentName: String = "",
)

/**
 * Role of a chat message sender.
 */
@Serializable
enum class MessageRole {
    @SerialName("user") USER,
    @SerialName("agent") AGENT,
    @SerialName("system") SYSTEM,
}

// -- Pairing Models --

/**
 * Connection information extracted from a QR code or manual entry.
 */
@Serializable
data class PairingInfo(
    @SerialName("server_url") val serverUrl: String,
    val token: String,
    val name: String? = null,
)

// -- Location Models --

/**
 * Location data to send to the daemon.
 */
@Serializable
data class LocationData(
    val latitude: Double,
    val longitude: Double,
    val accuracy: Float? = null,
    val altitude: Double? = null,
    val timestamp: Long = System.currentTimeMillis(),
)

// -- WebSocket Models --

/**
 * WebSocket event from the daemon for real-time updates.
 */
@Serializable
data class WebSocketEvent(
    val type: String,
    val data: JsonElement? = null,
)

// -- Widget Models --

/**
 * Snapshot of fleet state for widget display.
 */
data class WidgetState(
    val agentCount: Int = 0,
    val runningCount: Int = 0,
    val pendingCount: Int = 0,
    val isConnected: Boolean = false,
    val lastUpdated: Long = 0L,
)

// -- Request Bodies --

/**
 * Request body for sending text to an agent.
 */
@Serializable
data class InputBody(val text: String)

/**
 * Request body for denying a pending request.
 */
@Serializable
data class DenyBody(val reason: String? = null)
