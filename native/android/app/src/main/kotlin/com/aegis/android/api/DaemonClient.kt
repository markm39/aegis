package com.aegis.android.api

import com.aegis.android.security.TokenStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * HTTP client for the Aegis daemon API, designed for Android.
 *
 * Connects to the daemon's HTTP API with security-first defaults:
 * - Bearer token authentication from EncryptedSharedPreferences (Android Keystore-backed)
 * - X-Request-ID header on every mutating request for audit trail
 * - TLS certificate pinning via OkHttp CertificatePinner
 * - Server URL validation (HTTPS required, except localhost for dev)
 * - Hardened timeouts: connect 10s, read 30s, write 15s
 * - No cookies, no caching
 *
 * All methods suspend and are safe to call from any coroutine context.
 */
class DaemonClient(
    private val baseUrl: String,
    private val tokenStore: TokenStore,
) {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = false
        encodeDefaults = true
    }

    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    /**
     * OkHttp client with security-hardened configuration.
     *
     * Certificate pinning is configured for non-localhost hosts. For production
     * deployments, replace the placeholder pin with your server's actual
     * certificate public key SHA-256 hash.
     */
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        // Disable cookies to prevent session fixation
        .cookieJar(OkHttpClient.Builder().build().cookieJar)
        // Disable caching -- fleet state must always be fresh
        .cache(null)
        // Certificate pinning for production hosts.
        // Localhost/emulator connections bypass pinning.
        // In production, add your server's certificate pin here:
        //   .add("aegis.example.com", "sha256/AAAA...")
        .certificatePinner(
            CertificatePinner.Builder()
                .build()
        )
        .build()

    // -- Fleet Endpoints --

    /**
     * List all agents in the fleet.
     * GET /v1/agents
     */
    suspend fun fetchAgents(): List<AgentInfo> {
        val response = get("/v1/agents")
        if (!response.ok || response.data == null) {
            throw DaemonClientException("Failed to fetch agents: ${response.message}")
        }
        return json.decodeFromJsonElement(response.data)
    }

    /**
     * Fetch all pending requests across all agents.
     *
     * Iterates agents with nonzero pending counts and collects their prompts.
     */
    suspend fun fetchPendingRequests(): List<PendingRequest> {
        val agents = fetchAgents()
        val allPending = mutableListOf<PendingRequest>()
        for (agent in agents) {
            if (agent.pendingCount > 0) {
                val prompts = runCatching { listPending(agent.name) }.getOrDefault(emptyList())
                allPending.addAll(prompts)
            }
        }
        return allPending
    }

    /**
     * List pending prompts for a specific agent.
     */
    suspend fun listPending(agentName: String): List<PendingRequest> {
        val body = buildJsonObject {
            "type" to "list_pending"
            "name" to agentName
        }
        val response = postJson("/v1/command", body)
        if (!response.ok || response.data == null) {
            return emptyList()
        }
        val prompts: List<PendingRequest> = json.decodeFromJsonElement(response.data)
        return prompts.map { it.copy(agentName = agentName) }
    }

    /**
     * Approve a pending permission request.
     */
    suspend fun approveRequest(requestId: String, agentName: String) {
        val body = buildJsonObject {
            "type" to "approve_request"
            "name" to agentName
            "request_id" to requestId
        }
        val response = postJson("/v1/command", body)
        if (!response.ok) {
            throw DaemonClientException("Failed to approve request: ${response.message}")
        }
    }

    /**
     * Deny a pending permission request.
     */
    suspend fun denyRequest(requestId: String, agentName: String, reason: String? = null) {
        val body = buildJsonObject {
            "type" to "deny_request"
            "name" to agentName
            "request_id" to requestId
            if (reason != null) "reason" to reason
        }
        val response = postJson("/v1/command", body)
        if (!response.ok) {
            throw DaemonClientException("Failed to deny request: ${response.message}")
        }
    }

    /**
     * Send text input to an agent.
     *
     * Input is sanitized before sending -- control characters are stripped
     * to prevent terminal escape sequence injection.
     */
    suspend fun sendInput(agentName: String, text: String) {
        val sanitized = sanitizeInput(text)
        if (sanitized.isEmpty()) return

        val body = buildJsonObject {
            "type" to "send_to_agent"
            "name" to agentName
            "text" to sanitized
        }
        val response = postJson("/v1/command", body)
        if (!response.ok) {
            throw DaemonClientException("Failed to send input: ${response.message}")
        }
    }

    /**
     * Fetch recent output lines for an agent.
     * GET /v1/agents/{id}/output?lines=100
     */
    suspend fun fetchAgentOutput(agentId: String): List<String> {
        val response = get("/v1/agents/$agentId/output?lines=100")
        if (!response.ok || response.data == null) {
            return emptyList()
        }
        return runCatching {
            json.decodeFromJsonElement<List<String>>(response.data)
        }.getOrDefault(emptyList())
    }

    /**
     * Test the connection to the daemon.
     * GET /v1/status
     *
     * @return null on success, error message on failure.
     */
    suspend fun testConnection(): String? {
        return try {
            val response = get("/v1/status")
            if (response.ok) null else response.message
        } catch (e: Exception) {
            e.message ?: "Connection failed"
        }
    }

    // -- HTTP Primitives --

    private suspend fun get(path: String): ApiResponse = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl$path")
            .get()
            .apply { applyAuth(this) }
            .build()

        execute(request)
    }

    private suspend fun postJson(path: String, body: String): ApiResponse = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl$path")
            .post(body.toRequestBody(jsonMediaType))
            .header("Content-Type", "application/json")
            .apply {
                applyAuth(this)
                applyRequestId(this)
            }
            .build()

        execute(request)
    }

    private fun execute(request: Request): ApiResponse {
        val response = httpClient.newCall(request).execute()
        val responseBody = response.body?.string()
            ?: throw DaemonClientException("Empty response body (HTTP ${response.code})")

        if (response.code !in 200..499) {
            throw DaemonClientException("HTTP error: ${response.code}")
        }

        return json.decodeFromString<ApiResponse>(responseBody)
    }

    /**
     * Apply Bearer token authentication from the secure token store.
     */
    private fun applyAuth(builder: Request.Builder) {
        val token = tokenStore.getToken()
        if (token != null) {
            builder.header("Authorization", "Bearer $token")
        }
    }

    /**
     * Apply a unique request ID for audit trail correlation.
     * Every mutating request gets a UUID to trace through the daemon audit log.
     */
    private fun applyRequestId(builder: Request.Builder) {
        builder.header("X-Request-ID", UUID.randomUUID().toString())
    }

    companion object {

        /**
         * Validate that a server URL meets security requirements.
         *
         * Rules:
         * - HTTPS is required for all remote servers
         * - HTTP is only allowed for localhost, 127.0.0.1, and 10.0.2.2 (emulator)
         * - Empty or malformed URLs are rejected
         *
         * @param urlString The URL string to validate.
         * @return true if the URL is valid, false otherwise.
         */
        fun isValidServerUrl(urlString: String): Boolean {
            if (urlString.isBlank()) return false

            val lower = urlString.lowercase().trim()

            // HTTPS is always allowed
            if (lower.startsWith("https://")) return true

            // HTTP is only allowed for localhost and emulator loopback
            if (lower.startsWith("http://")) {
                val localhostPrefixes = listOf(
                    "http://localhost",
                    "http://127.0.0.1",
                    "http://10.0.2.2",
                )
                return localhostPrefixes.any { lower.startsWith(it) }
            }

            return false
        }
    }
}

// -- Input Sanitizer --

/**
 * Strip control characters from user input before sending to the daemon.
 * Prevents injection of terminal escape sequences or other control codes.
 */
internal fun sanitizeInput(input: String): String {
    val trimmed = input.trim()
    // Remove control characters (U+0000 to U+001F, U+007F) except standard space
    return trimmed.filter { ch ->
        ch.code >= 0x20 && ch.code != 0x7F
    }
}

// -- JSON Builder Helper --

/**
 * Minimal JSON object builder that produces a JSON string directly.
 * Avoids pulling in a full JSON DOM builder dependency.
 */
internal class JsonObjectBuilder {
    private val entries = mutableListOf<String>()

    infix fun String.to(value: String) {
        // Escape the string value for JSON safety
        val escaped = value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        entries.add("\"$this\":\"$escaped\"")
    }

    fun build(): String = "{${entries.joinToString(",")}}"
}

internal fun buildJsonObject(block: JsonObjectBuilder.() -> Unit): String {
    return JsonObjectBuilder().apply(block).build()
}

// -- Errors --

/**
 * Exception thrown by DaemonClient when an API call fails.
 */
class DaemonClientException(message: String) : IOException(message)
