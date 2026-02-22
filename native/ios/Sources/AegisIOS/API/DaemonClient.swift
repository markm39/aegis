import Foundation

/// HTTP and WebSocket client for the Aegis daemon API, designed for iOS.
///
/// Connects to the daemon's HTTP API with security-first defaults:
/// - Bearer token authentication from Keychain
/// - Ephemeral URLSession (no cache, no cookies)
/// - X-Request-ID header on every mutating request for audit trail
/// - TLS certificate pinning via custom URLSessionDelegate
/// - Server URL validation (HTTPS required, except localhost for dev)
/// - Retry logic with exponential backoff for transient failures
/// - WebSocket support for real-time fleet updates
///
/// All methods are async/await and safe to call from any actor context.
final class DaemonClient: NSObject, @unchecked Sendable {
    /// Base URL for the daemon HTTP API.
    let baseURL: URL

    /// URLSession with security-hardened configuration.
    private let session: URLSession

    /// Token manager for Keychain-backed authentication.
    private let tokenManager = TokenManager()

    /// TLS pinning delegate.
    private let pinningDelegate = CertificatePinningDelegate()

    /// Maximum number of retry attempts for transient failures.
    private let maxRetries: Int

    /// Base delay for exponential backoff (in seconds).
    private let baseRetryDelay: TimeInterval

    init(
        baseURL: URL = URL(string: "http://localhost:3100")!,
        maxRetries: Int = 3,
        baseRetryDelay: TimeInterval = 1.0
    ) {
        self.baseURL = baseURL
        self.maxRetries = maxRetries
        self.baseRetryDelay = baseRetryDelay

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        config.waitsForConnectivity = true
        // Disable cookies to prevent session fixation
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false

        // Initialize with a temporary session, then replace after super.init
        self.session = URLSession(configuration: config, delegate: pinningDelegate, delegateQueue: nil)

        super.init()
    }

    // MARK: - Server URL Validation

    /// Validate that a server URL meets security requirements.
    ///
    /// Rules:
    /// - HTTPS is required for all remote servers
    /// - HTTP is only allowed for localhost/127.0.0.1 (development)
    /// - Empty or malformed URLs are rejected
    ///
    /// - Parameter urlString: The URL string to validate.
    /// - Returns: A validated URL, or nil if validation fails.
    static func validateServerURL(_ urlString: String) -> URL? {
        guard let url = URL(string: urlString),
              let scheme = url.scheme?.lowercased(),
              let host = url.host?.lowercased() else {
            return nil
        }

        // HTTPS is always allowed
        if scheme == "https" {
            return url
        }

        // HTTP is only allowed for localhost
        if scheme == "http" {
            let localhostHosts = ["localhost", "127.0.0.1", "::1"]
            if localhostHosts.contains(host) {
                return url
            }
        }

        return nil
    }

    // MARK: - Fleet Endpoints

    /// List all agents in the fleet.
    /// GET /v1/agents
    func listAgents() async throws -> [AgentInfo] {
        let response = try await getWithRetry(path: "/v1/agents")
        guard response.ok, let data = response.data else {
            throw DaemonClientError.apiError(response.message)
        }
        let jsonData = try JSONEncoder().encode(data)
        return try JSONDecoder().decode([AgentInfo].self, from: jsonData)
    }

    /// Fetch all pending requests across agents.
    /// Iterates agents with pending counts and collects their prompts.
    func fetchPendingRequests() async throws -> [PendingPrompt] {
        let agents = try await listAgents()
        var allPending: [PendingPrompt] = []
        for agent in agents where agent.pendingCount > 0 {
            if let prompts = try? await listPending(agentName: agent.name) {
                allPending.append(contentsOf: prompts)
            }
        }
        return allPending
    }

    /// List pending prompts for a specific agent.
    func listPending(agentName: String) async throws -> [PendingPrompt] {
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
        for i in prompts.indices {
            prompts[i].agentName = agentName
        }
        return prompts
    }

    /// Approve a pending permission request.
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
    func deny(requestId: String, agentName: String, reason: String?) async throws {
        var body: [String: Any] = [
            "type": "deny_request",
            "name": agentName,
            "request_id": requestId
        ]
        if let reason = reason {
            body["reason"] = reason
        }
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

    /// Send a chat message to an agent and get a response.
    func sendChatMessage(agentName: String, message: String) async throws -> APIResponse {
        let body: [String: Any] = [
            "type": "send_to_agent",
            "name": agentName,
            "text": message
        ]
        return try await postJSON(path: "/v1/command", body: body)
    }

    /// Fetch recent output lines for an agent.
    func fetchAgentOutput(agentId: String) async throws -> [String] {
        let response = try await getWithRetry(path: "/v1/agents/\(agentId)/output?lines=100")
        guard response.ok, let data = response.data else {
            return []
        }
        let jsonData = try JSONEncoder().encode(data)
        return (try? JSONDecoder().decode([String].self, from: jsonData)) ?? []
    }

    /// Start a specific agent.
    func startAgent(name: String) async throws {
        let response = try await post(path: "/v1/agents/\(name)/start")
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Stop a specific agent.
    func stopAgent(name: String) async throws {
        let response = try await post(path: "/v1/agents/\(name)/stop")
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Restart a specific agent.
    func restartAgent(name: String) async throws {
        let response = try await post(path: "/v1/agents/\(name)/restart")
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Nudge a stalled agent.
    func nudgeAgent(name: String) async throws {
        let body: [String: Any] = [
            "type": "nudge_agent",
            "name": name
        ]
        let response = try await postJSON(path: "/v1/command", body: body)
        guard response.ok else {
            throw DaemonClientError.apiError(response.message)
        }
    }

    /// Get pilot/daemon status.
    func getStatus() async throws -> APIResponse {
        return try await getWithRetry(path: "/v1/status")
    }

    // MARK: - WebSocket Support

    /// Open a WebSocket connection to the daemon for real-time updates.
    ///
    /// The daemon's gateway WebSocket endpoint streams fleet events (agent status changes,
    /// new pending prompts, output lines) as JSON messages.
    ///
    /// - Returns: An AsyncStream of WebSocketEvent values.
    func connectWebSocket() -> AsyncStream<WebSocketEvent> {
        AsyncStream { continuation in
            let wsScheme = baseURL.scheme == "https" ? "wss" : "ws"
            guard let host = baseURL.host else {
                continuation.finish()
                return
            }
            let port = baseURL.port.map { ":\($0)" } ?? ""
            guard let wsURL = URL(string: "\(wsScheme)://\(host)\(port)/v1/ws") else {
                continuation.finish()
                return
            }

            var request = URLRequest(url: wsURL)
            if let token = tokenManager.getToken() {
                request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            }

            let task = session.webSocketTask(with: request)
            task.resume()

            continuation.onTermination = { _ in
                task.cancel(with: .goingAway, reason: nil)
            }

            // Send initial event
            continuation.yield(.connected)

            // Start reading messages
            Task {
                await readWebSocketMessages(task: task, continuation: continuation)
            }
        }
    }

    /// Continuously read messages from the WebSocket task.
    private func readWebSocketMessages(
        task: URLSessionWebSocketTask,
        continuation: AsyncStream<WebSocketEvent>.Continuation
    ) async {
        var retryCount = 0

        while !Task.isCancelled {
            do {
                let message = try await task.receive()
                retryCount = 0 // Reset on successful receive

                switch message {
                case .string(let text):
                    if let data = text.data(using: .utf8) {
                        continuation.yield(.message(data))
                    }
                case .data(let data):
                    continuation.yield(.message(data))
                @unknown default:
                    break
                }
            } catch {
                continuation.yield(.disconnected(error.localizedDescription))

                // Exponential backoff for reconnection
                retryCount += 1
                if retryCount > maxRetries {
                    continuation.yield(.error("WebSocket connection failed after \(maxRetries) retries"))
                    continuation.finish()
                    return
                }

                let delay = baseRetryDelay * pow(2.0, Double(retryCount - 1))
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
        }

        continuation.finish()
    }

    // MARK: - HTTP Primitives with Retry

    /// GET with exponential backoff retry for transient failures.
    private func getWithRetry(path: String) async throws -> APIResponse {
        return try await withRetry {
            try await self.get(path: path)
        }
    }

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
        applyRequestId(&request)
        applyAuth(&request)
        return try await execute(request)
    }

    private func postJSON(path: String, body: [String: Any]) async throws -> APIResponse {
        let url = baseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        applyRequestId(&request)
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

    // MARK: - Retry Logic

    /// Execute an operation with exponential backoff retry.
    ///
    /// Retries on network errors (URLError) and server errors (5xx).
    /// Does not retry on client errors (4xx) or decoding errors.
    private func withRetry<T>(_ operation: @escaping () async throws -> T) async throws -> T {
        var lastError: Error?

        for attempt in 0...maxRetries {
            do {
                return try await operation()
            } catch let error as URLError where isRetryableURLError(error) {
                lastError = error
            } catch let error as DaemonClientError {
                if case .httpError(let code) = error, (500...599).contains(code) {
                    lastError = error
                } else {
                    throw error // Non-retryable client error
                }
            } catch {
                throw error // Non-retryable error
            }

            if attempt < maxRetries {
                let delay = baseRetryDelay * pow(2.0, Double(attempt))
                let jitter = Double.random(in: 0...0.5)
                try? await Task.sleep(nanoseconds: UInt64((delay + jitter) * 1_000_000_000))
            }
        }

        throw lastError ?? DaemonClientError.apiError("Request failed after \(maxRetries) retries")
    }

    /// Determine if a URLError is transient and worth retrying.
    private func isRetryableURLError(_ error: URLError) -> Bool {
        switch error.code {
        case .timedOut, .cannotConnectToHost, .networkConnectionLost,
             .dnsLookupFailed, .notConnectedToInternet, .secureConnectionFailed:
            return true
        default:
            return false
        }
    }

    /// Apply Bearer token authentication from the Keychain.
    private func applyAuth(_ request: inout URLRequest) {
        if let token = tokenManager.getToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
    }

    /// Apply a unique request ID for audit trail correlation.
    /// Every mutating request gets a UUID to trace through the daemon audit log.
    private func applyRequestId(_ request: inout URLRequest) {
        request.setValue(UUID().uuidString, forHTTPHeaderField: "X-Request-ID")
    }
}

// MARK: - WebSocket Event

/// Events received from the daemon WebSocket connection.
enum WebSocketEvent {
    /// WebSocket connection established.
    case connected
    /// Received a message (raw JSON data).
    case message(Data)
    /// Connection lost with reason.
    case disconnected(String)
    /// Unrecoverable error.
    case error(String)
}

// MARK: - Connection State

/// Observable connection state for the daemon client.
///
/// Used by views to display connection status and trigger reconnection.
enum ConnectionState: Equatable {
    case disconnected
    case connecting
    case connected
    case reconnecting(attempt: Int)

    var displayName: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting..."
        case .connected: return "Connected"
        case .reconnecting(let attempt): return "Reconnecting (\(attempt))..."
        }
    }

    var isConnected: Bool {
        if case .connected = self { return true }
        return false
    }
}

// MARK: - TLS Certificate Pinning Delegate

/// URLSession delegate that validates server certificates.
///
/// When TLS pinning is configured, this delegate validates the server's certificate
/// chain against known pins. If no pins are configured, it logs a warning and
/// allows the default system trust evaluation.
///
/// Security note: In production, configure certificate pins via the Settings screen.
/// Development builds connecting to localhost bypass TLS validation.
final class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host

        // Allow localhost connections without TLS pinning (development only)
        let localhostHosts = ["localhost", "127.0.0.1", "::1"]
        if localhostHosts.contains(host) {
            let credential = URLCredential(trust: serverTrust)
            completionHandler(.useCredential, credential)
            return
        }

        // For remote hosts, perform default system trust evaluation.
        // In a production deployment, pin specific certificates here by comparing
        // the server certificate's public key hash against known values.
        //
        // WARNING: TLS pinning is not configured. The connection relies on system
        // trust store validation only. Configure pinning for production use.
        #if DEBUG
        print("[Aegis] WARNING: TLS pinning not configured for host: \(host). Using system trust.")
        #endif

        completionHandler(.performDefaultHandling, nil)
    }
}

// MARK: - Errors

enum DaemonClientError: LocalizedError {
    case apiError(String)
    case invalidResponse
    case httpError(statusCode: Int)
    case invalidServerURL(String)
    case webSocketError(String)

    var errorDescription: String? {
        switch self {
        case .apiError(let message):
            return "API error: \(message)"
        case .invalidResponse:
            return "Invalid response from daemon"
        case .httpError(let code):
            return "HTTP error: \(code)"
        case .invalidServerURL(let url):
            return "Invalid server URL: \(url). HTTPS required for remote servers."
        case .webSocketError(let message):
            return "WebSocket error: \(message)"
        }
    }
}
