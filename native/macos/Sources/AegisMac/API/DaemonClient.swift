import Foundation

/// HTTP client for the Aegis daemon API.
///
/// Connects to the local daemon at `http://localhost:3100/v1/`.
/// Authentication is via Bearer token stored in the macOS Keychain.
///
/// Features:
/// - WebSocket for real-time updates via /gateway/ws
/// - Auto-discover local daemon (check common socket paths)
/// - Connection state machine with exponential backoff retry
/// - Batch approve/deny operations
///
/// Security notes:
/// - All credentials are stored in Keychain, never in UserDefaults or on disk.
/// - URLSession is configured with no caching to prevent credential leakage.
/// - Connection timeout is 10 seconds to fail fast on unreachable daemon.
final class DaemonClient: @unchecked Sendable {
    /// Base URL for the daemon HTTP API.
    private(set) var baseURL: URL

    /// URLSession configured for security: no cache, short timeout.
    private let session: URLSession

    /// Token manager for Keychain-backed authentication.
    private let tokenManager = TokenManager()

    /// Current connection state.
    private(set) var connectionState: ConnectionState = .disconnected

    /// WebSocket task for real-time updates.
    private var webSocketTask: URLSessionWebSocketTask?

    /// Callback for WebSocket messages.
    var onGatewayMessage: ((GatewayResponse) -> Void)?

    /// Callback for connection state changes.
    var onConnectionStateChange: ((ConnectionState) -> Void)?

    /// Maximum retry attempts before giving up.
    private let maxRetryAttempts = 10

    /// Active WebSocket listening task.
    private var wsListenTask: Task<Void, Never>?

    init(baseURL: URL = URL(string: "http://localhost:3100")!) {
        self.baseURL = baseURL

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 30
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        // Disable cookies to prevent session fixation
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false

        self.session = URLSession(configuration: config)
    }

    // MARK: - Connection Management

    /// Auto-discover the daemon by checking common locations.
    /// Returns the URL if found, nil otherwise.
    static func discoverDaemon() async -> URL? {
        // Check common socket/port locations
        let candidates: [URL] = [
            URL(string: "http://localhost:3100")!,
            URL(string: "http://127.0.0.1:3100")!,
            URL(string: "http://localhost:3200")!,
        ]

        for candidate in candidates {
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 2
            let session = URLSession(configuration: config)
            let url = candidate.appendingPathComponent("/v1/status")
            var request = URLRequest(url: url)
            request.httpMethod = "GET"

            do {
                let (_, response) = try await session.data(for: request)
                if let http = response as? HTTPURLResponse, (200...499).contains(http.statusCode) {
                    return candidate
                }
            } catch {
                continue
            }
        }

        // Check for Unix socket files
        let socketPaths = [
            NSHomeDirectory() + "/.aegis/daemon.sock",
            "/tmp/aegis-daemon.sock",
            NSHomeDirectory() + "/.config/aegis/daemon.sock",
        ]

        for path in socketPaths {
            if FileManager.default.fileExists(atPath: path) {
                // Unix socket found -- caller can use it with a custom transport
                // For now, return the default HTTP URL as a signal that daemon exists
                return URL(string: "http://localhost:3100")!
            }
        }

        return nil
    }

    /// Update the base URL (e.g., after auto-discovery or settings change).
    func setBaseURL(_ url: URL) {
        self.baseURL = url
    }

    /// Transition connection state and notify observers.
    private func setState(_ newState: ConnectionState) {
        connectionState = newState
        onConnectionStateChange?(newState)
    }

    // MARK: - WebSocket

    /// Connect to the daemon's gateway WebSocket for real-time updates.
    func connectWebSocket() {
        disconnectWebSocket()
        setState(.connecting)

        // Build ws:// URL from the http:// base URL
        var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
        components.scheme = baseURL.scheme == "https" ? "wss" : "ws"
        components.path = "/gateway/ws"

        guard let wsURL = components.url else {
            setState(.disconnected)
            return
        }

        var request = URLRequest(url: wsURL)
        if let token = tokenManager.getToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let task = session.webSocketTask(with: request)
        self.webSocketTask = task
        task.resume()

        setState(.connected)
        startListening()
    }

    /// Disconnect the WebSocket.
    func disconnectWebSocket() {
        wsListenTask?.cancel()
        wsListenTask = nil
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        setState(.disconnected)
    }

    /// Start listening for WebSocket messages.
    private func startListening() {
        wsListenTask?.cancel()
        wsListenTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self = self, let ws = self.webSocketTask else { break }

                do {
                    let message = try await ws.receive()
                    switch message {
                    case .string(let text):
                        if let data = text.data(using: .utf8),
                           let response = try? JSONDecoder().decode(GatewayResponse.self, from: data) {
                            self.onGatewayMessage?(response)
                        }
                    case .data(let data):
                        if let response = try? JSONDecoder().decode(GatewayResponse.self, from: data) {
                            self.onGatewayMessage?(response)
                        }
                    @unknown default:
                        break
                    }
                } catch {
                    // WebSocket disconnected -- attempt reconnect
                    if !Task.isCancelled {
                        await self.reconnectWithBackoff()
                    }
                    break
                }
            }
        }
    }

    /// Send a message over the gateway WebSocket.
    func sendGatewayMessage(_ request: GatewayRequest) async throws {
        guard let ws = webSocketTask else {
            throw DaemonClientError.notConnected
        }
        let data = try JSONEncoder().encode(request)
        let text = String(data: data, encoding: .utf8) ?? ""
        try await ws.send(.string(text))
    }

    /// Reconnect with exponential backoff.
    private func reconnectWithBackoff() async {
        for attempt in 1...maxRetryAttempts {
            guard !Task.isCancelled else { return }

            setState(.reconnecting(attempt: attempt))

            // Exponential backoff: 1s, 2s, 4s, 8s, ... capped at 30s
            let delay = min(UInt64(pow(2.0, Double(attempt - 1))) * 1_000_000_000, 30_000_000_000)
            try? await Task.sleep(nanoseconds: delay)

            guard !Task.isCancelled else { return }

            // Try to reconnect
            var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false)!
            components.scheme = baseURL.scheme == "https" ? "wss" : "ws"
            components.path = "/gateway/ws"

            guard let wsURL = components.url else { continue }

            var request = URLRequest(url: wsURL)
            if let token = tokenManager.getToken() {
                request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            }

            let task = session.webSocketTask(with: request)
            self.webSocketTask = task
            task.resume()

            // Test the connection by sending a ping
            do {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    task.sendPing { error in
                        if let error = error {
                            continuation.resume(throwing: error)
                        } else {
                            continuation.resume()
                        }
                    }
                }
                setState(.connected)
                startListening()
                return
            } catch {
                task.cancel(with: .goingAway, reason: nil)
                continue
            }
        }

        setState(.disconnected)
    }

    // MARK: - Fleet Endpoints

    /// List all agents in the fleet.
    /// GET /v1/agents
    func listAgents() async throws -> [AgentInfo] {
        let response = try await get(path: "/v1/agents")
        guard response.ok, let data = response.data else {
            throw DaemonClientError.apiError(response.message)
        }
        // The daemon returns agents in the data field
        let jsonData = try JSONEncoder().encode(data)
        return try JSONDecoder().decode([AgentInfo].self, from: jsonData)
    }

    /// List pending prompts for a specific agent.
    /// Uses DaemonCommand::ListPending via the command endpoint.
    func listPending(agentName: String) async throws -> [PendingPrompt] {
        // The daemon exposes ListPending as a daemon command.
        // We POST to /v1/command with the appropriate payload.
        let body: [String: Any] = [
            "type": "list_pending",
            "name": agentName,
        ]
        let response = try await postJSON(path: "/v1/command", body: body)
        guard response.ok, let data = response.data else {
            return []
        }
        let jsonData = try JSONEncoder().encode(data)
        var prompts = try JSONDecoder().decode([PendingPrompt].self, from: jsonData)
        // Tag each prompt with the agent name
        for i in prompts.indices {
            prompts[i].agentName = agentName
        }
        return prompts
    }

    /// Approve a pending permission request.
    /// POST /v1/pending/{id}/approve (for pilot-level) or daemon command.
    func approve(requestId: String, agentName: String) async throws {
        let body: [String: Any] = [
            "type": "approve_request",
            "name": agentName,
            "request_id": requestId,
        ]
        let response = try await postJSON(path: "/v1/command", body: body)
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Deny a pending permission request.
    /// POST /v1/pending/{id}/deny (for pilot-level) or daemon command.
    func deny(requestId: String, agentName: String, reason: String?) async throws {
        let body: [String: Any] = [
            "type": "deny_request",
            "name": agentName,
            "request_id": requestId,
        ]
        let response = try await postJSON(path: "/v1/command", body: body)
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Batch approve all pending prompts.
    func approveAll(prompts: [PendingPrompt]) async throws {
        for prompt in prompts {
            try await approve(requestId: prompt.requestId, agentName: prompt.agentName)
        }
    }

    /// Batch deny all pending prompts.
    func denyAll(prompts: [PendingPrompt], reason: String?) async throws {
        for prompt in prompts {
            try await deny(requestId: prompt.requestId, agentName: prompt.agentName, reason: reason)
        }
    }

    /// Send text input to an agent.
    func sendToAgent(agentName: String, text: String) async throws {
        let body: [String: Any] = [
            "type": "send_to_agent",
            "name": agentName,
            "text": text,
        ]
        let response = try await postJSON(path: "/v1/command", body: body)
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Start a specific agent.
    /// POST /v1/agents/{name}/start
    func startAgent(name: String) async throws {
        let response = try await post(path: "/v1/agents/\(name)/start")
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Stop a specific agent.
    /// POST /v1/agents/{name}/stop
    func stopAgent(name: String) async throws {
        let response = try await post(path: "/v1/agents/\(name)/stop")
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Restart a specific agent.
    /// POST /v1/agents/{name}/restart
    func restartAgent(name: String) async throws {
        let response = try await post(path: "/v1/agents/\(name)/restart")
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Add a new agent to the fleet.
    func addAgent(name: String, tool: String, workingDir: String, role: String?) async throws {
        var body: [String: Any] = [
            "type": "add_agent",
            "name": name,
            "tool": tool,
            "working_dir": workingDir,
        ]
        if let role = role {
            body["role"] = role
        }
        let response = try await postJSON(path: "/v1/command", body: body)
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Remove an agent from the fleet.
    func removeAgent(name: String) async throws {
        let body: [String: Any] = [
            "type": "remove_agent",
            "name": name,
        ]
        let response = try await postJSON(path: "/v1/command", body: body)
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Get agent output lines.
    /// GET /v1/output?lines=N
    func getOutput(lines: Int = 50) async throws -> APIResponse {
        return try await get(path: "/v1/output?lines=\(lines)")
    }

    /// Get pilot status.
    /// GET /v1/status
    func getStatus() async throws -> APIResponse {
        return try await get(path: "/v1/status")
    }

    /// Check if the daemon is reachable.
    func ping() async -> Bool {
        do {
            _ = try await getStatus()
            return true
        } catch {
            return false
        }
    }

    // MARK: - Daemon Process Control

    /// Start the daemon process (looks for aegis binary in PATH).
    func startDaemon() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["aegis", "daemon", "start"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
    }

    /// Stop the daemon process via API.
    func stopDaemon() async throws {
        let body: [String: Any] = [
            "type": "shutdown",
        ]
        _ = try await postJSON(path: "/v1/command", body: body)
    }

    // MARK: - HTTP Primitives

    private func get(path: String) async throws -> APIResponse {
        let url = baseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        applyAuth(&request)
        return try await execute(request)
    }

    private func post(path: String) async throws -> APIResponse {
        let url = baseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        applyAuth(&request)
        return try await execute(request)
    }

    private func postJSON(path: String, body: [String: Any]) async throws -> APIResponse {
        let url = baseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        applyAuth(&request)
        return try await execute(request)
    }

    private func execute(_ request: URLRequest) async throws -> APIResponse {
        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw DaemonClientError.invalidResponse
        }

        guard (200...499).contains(httpResponse.statusCode) else {
            throw DaemonClientError.httpError(statusCode: httpResponse.statusCode)
        }

        let decoder = JSONDecoder()
        return try decoder.decode(APIResponse.self, from: data)
    }

    /// Apply Bearer token authentication from the Keychain.
    private func applyAuth(_ request: inout URLRequest) {
        if let token = tokenManager.getToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }
}

// MARK: - Errors

enum DaemonClientError: LocalizedError {
    case apiError(String)
    case invalidResponse
    case httpError(statusCode: Int)
    case notConnected

    var errorDescription: String? {
        switch self {
        case .apiError(let message):
            return "API error: \(message)"
        case .invalidResponse:
            return "Invalid response from daemon"
        case .httpError(let code):
            return "HTTP error: \(code)"
        case .notConnected:
            return "Not connected to daemon"
        }
    }
}
