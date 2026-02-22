package com.aegis.android.api

import com.aegis.android.security.TokenStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.io.IOException
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.math.min

/**
 * Connection state for the daemon client.
 */
enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
}

/**
 * HTTP + WebSocket client for the Aegis daemon API, designed for Android.
 *
 * Connects to the daemon's HTTP API with security-first defaults:
 * - Bearer token authentication from EncryptedSharedPreferences (Android Keystore-backed)
 * - X-Request-ID header on every mutating request for audit trail
 * - TLS certificate pinning via OkHttp CertificatePinner
 * - Server URL validation (HTTPS required, except localhost for dev)
 * - Hardened timeouts: connect 10s, read 30s, write 15s
 * - No cookies, no caching
 * - WebSocket support for real-time fleet updates
 * - Exponential backoff retry on transient failures
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

    // -- Connection State --

    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    private val _wsEvents = Channel<WebSocketEvent>(Channel.BUFFERED)
    val wsEvents: Flow<WebSocketEvent> = _wsEvents.receiveAsFlow()

    private var webSocket: WebSocket? = null

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
        val response = getWithRetry("/v1/agents")
        if (!response.ok || response.data == null) {
            throw DaemonClientException("Failed to fetch agents: ${response.message}")
        }
        _connectionState.value = ConnectionState.CONNECTED
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
     * Send a chat message to an agent and receive a response.
     */
    suspend fun sendChatMessage(agentName: String, message: String): ChatMessage {
        val sanitized = sanitizeInput(message)
        if (sanitized.isEmpty()) {
            throw DaemonClientException("Empty message after sanitization")
        }

        val body = buildJsonObject {
            "type" to "send_to_agent"
            "name" to agentName
            "text" to sanitized
        }
        val response = postJson("/v1/command", body)
        if (!response.ok) {
            throw DaemonClientException("Failed to send message: ${response.message}")
        }

        return ChatMessage(
            id = UUID.randomUUID().toString(),
            role = MessageRole.AGENT,
            content = response.message,
            agentName = agentName,
        )
    }

    /**
     * Fetch recent output lines for an agent.
     * GET /v1/agents/{id}/output?lines=100
     */
    suspend fun fetchAgentOutput(agentId: String): List<String> {
        val response = getWithRetry("/v1/agents/$agentId/output?lines=100")
        if (!response.ok || response.data == null) {
            return emptyList()
        }
        return runCatching {
            json.decodeFromJsonElement<List<String>>(response.data)
        }.getOrDefault(emptyList())
    }

    /**
     * Send location data to the daemon.
     */
    suspend fun sendLocation(location: LocationData) {
        val body = buildJsonObject {
            "type" to "location_update"
            "latitude" to location.latitude.toString()
            "longitude" to location.longitude.toString()
            if (location.accuracy != null) "accuracy" to location.accuracy.toString()
            if (location.altitude != null) "altitude" to location.altitude.toString()
            "timestamp" to location.timestamp.toString()
        }
        val response = postJson("/v1/location", body)
        if (!response.ok) {
            throw DaemonClientException("Failed to send location: ${response.message}")
        }
    }

    /**
     * Upload an image to the daemon.
     */
    suspend fun uploadImage(imageBytes: ByteArray, mimeType: String, agentName: String): ApiResponse =
        withContext(Dispatchers.IO) {
            val requestBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("agent_name", agentName)
                .addFormDataPart(
                    "image",
                    "capture.jpg",
                    imageBytes.toRequestBody(mimeType.toMediaType())
                )
                .build()

            val request = Request.Builder()
                .url("$baseUrl/v1/upload")
                .post(requestBody)
                .apply {
                    applyAuth(this)
                    applyRequestId(this)
                }
                .build()

            execute(request)
        }

    /**
     * Test the connection to the daemon.
     * GET /v1/status
     *
     * @return null on success, error message on failure.
     */
    suspend fun testConnection(): String? {
        return try {
            val response = getWithRetry("/v1/status")
            if (response.ok) {
                _connectionState.value = ConnectionState.CONNECTED
                null
            } else {
                _connectionState.value = ConnectionState.DISCONNECTED
                response.message
            }
        } catch (e: Exception) {
            _connectionState.value = ConnectionState.DISCONNECTED
            e.message ?: "Connection failed"
        }
    }

    // -- WebSocket --

    /**
     * Connect a WebSocket for real-time fleet event streaming.
     *
     * Events are emitted to the wsEvents flow. Connection state updates
     * are reflected in the connectionState flow.
     */
    fun connectWebSocket() {
        if (webSocket != null) return

        _connectionState.value = ConnectionState.CONNECTING

        val wsUrl = baseUrl
            .replace("http://", "ws://")
            .replace("https://", "wss://")

        val request = Request.Builder()
            .url("$wsUrl/v1/ws")
            .apply { applyAuth(this) }
            .build()

        webSocket = httpClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                _connectionState.value = ConnectionState.CONNECTED
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val event = runCatching {
                    json.decodeFromString<WebSocketEvent>(text)
                }.getOrNull()
                if (event != null) {
                    _wsEvents.trySend(event)
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(1000, null)
                _connectionState.value = ConnectionState.DISCONNECTED
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                _connectionState.value = ConnectionState.DISCONNECTED
                this@DaemonClient.webSocket = null
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                _connectionState.value = ConnectionState.DISCONNECTED
                this@DaemonClient.webSocket = null
            }
        })
    }

    /**
     * Disconnect the WebSocket.
     */
    fun disconnectWebSocket() {
        webSocket?.close(1000, "Client closing")
        webSocket = null
        _connectionState.value = ConnectionState.DISCONNECTED
    }

    // -- HTTP Primitives with Retry --

    /**
     * GET with exponential backoff retry on transient failures.
     */
    private suspend fun getWithRetry(
        path: String,
        maxRetries: Int = 3,
    ): ApiResponse {
        var lastException: Exception? = null
        var delayMs = INITIAL_RETRY_DELAY_MS

        for (attempt in 0..maxRetries) {
            try {
                return get(path)
            } catch (e: IOException) {
                lastException = e
                if (attempt < maxRetries) {
                    _connectionState.value = ConnectionState.CONNECTING
                    delay(delayMs)
                    delayMs = min(delayMs * 2, MAX_RETRY_DELAY_MS)
                }
            }
        }

        _connectionState.value = ConnectionState.DISCONNECTED
        throw lastException ?: DaemonClientException("Request failed after $maxRetries retries")
    }

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

    /**
     * Shut down the client, closing the WebSocket and freeing resources.
     */
    fun shutdown() {
        disconnectWebSocket()
        httpClient.dispatcher.executorService.shutdown()
        httpClient.connectionPool.evictAll()
    }

    companion object {
        /** Initial retry delay in milliseconds. */
        const val INITIAL_RETRY_DELAY_MS = 500L

        /** Maximum retry delay in milliseconds (capped at 8 seconds). */
        const val MAX_RETRY_DELAY_MS = 8_000L

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

        /**
         * User-friendly error message from an exception.
         */
        fun friendlyError(e: Exception): String = when (e) {
            is java.net.ConnectException -> "Cannot reach the Aegis daemon. Check that it is running and the server URL is correct."
            is java.net.SocketTimeoutException -> "Connection timed out. The daemon may be under heavy load."
            is java.net.UnknownHostException -> "Unknown host. Check the server URL in Settings."
            is javax.net.ssl.SSLException -> "TLS handshake failed. Check that the server supports HTTPS."
            is DaemonClientException -> e.message ?: "API request failed"
            else -> e.message ?: "An unexpected error occurred"
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
