import Foundation

/// HTTP client for the Aegis daemon API.
///
/// Connects to the local daemon at `http://localhost:3100/v1/`.
/// Authentication is via Bearer token stored in the macOS Keychain.
///
/// Security notes:
/// - All credentials are stored in Keychain, never in UserDefaults or on disk.
/// - URLSession is configured with no caching to prevent credential leakage.
/// - Connection timeout is 10 seconds to fail fast on unreachable daemon.
final class DaemonClient: @unchecked Sendable {
    /// Base URL for the daemon HTTP API.
    private let baseURL: URL

    /// URLSession configured for security: no cache, short timeout.
    private let session: URLSession

    /// Token manager for Keychain-backed authentication.
    private let tokenManager = TokenManager()

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
            "name": agentName
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
            "request_id": requestId
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
            "request_id": requestId
        ]
        let response = try await postJSON(path: "/v1/command", body: body)
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Send text input to an agent.
    func sendToAgent(agentName: String, text: String) async throws {
        let body: [String: Any] = [
            "type": "send_to_agent",
            "name": agentName,
            "text": text
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

    var errorDescription: String? {
        switch self {
        case .apiError(let message):
            return "API error: \(message)"
        case .invalidResponse:
            return "Invalid response from daemon"
        case .httpError(let code):
            return "HTTP error: \(code)"
        }
    }
}
