import SwiftUI
import UserNotifications

/// Aegis iOS application for fleet management, agent monitoring, and approval workflows.
///
/// The app provides five main tabs:
/// - Dashboard: Fleet overview with agent status
/// - Pending: Approval queue with swipe actions
/// - Chat: Direct agent interaction with message bubbles
/// - Camera: Image capture and sharing with agents
/// - Settings: Server configuration, pairing, and security
@main
struct AegisIOSApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var pushManager = PushManager()
    @StateObject private var locationService = LocationService()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(pushManager)
                .environmentObject(locationService)
                .onAppear {
                    appState.startPolling()
                }
                .onOpenURL { url in
                    handleDeepLink(url)
                }
        }
    }

    /// Handle deep links from notifications and external sources.
    ///
    /// Supported URL schemes:
    /// - aegis://dashboard
    /// - aegis://pending
    /// - aegis://pending/{requestId}
    /// - aegis://chat/{agentName}
    /// - aegis://agent/{agentName}
    private func handleDeepLink(_ url: URL) {
        guard url.scheme == "aegis" else { return }

        switch url.host {
        case "dashboard":
            appState.selectedTab = .dashboard
        case "pending":
            appState.selectedTab = .pending
            if let requestId = url.pathComponents.dropFirst().first {
                appState.deepLinkRequestId = requestId
            }
        case "chat":
            appState.selectedTab = .chat
            if let agentName = url.pathComponents.dropFirst().first {
                appState.deepLinkAgentName = agentName
            }
        case "agent":
            appState.selectedTab = .dashboard
            if let agentName = url.pathComponents.dropFirst().first {
                appState.deepLinkAgentName = agentName
            }
        default:
            break
        }
    }
}

// MARK: - Tab Identifiers

/// Identifiers for the main navigation tabs.
enum AppTab: Hashable {
    case dashboard
    case pending
    case chat
    case camera
    case settings
}

// MARK: - Content View

/// Root view with tab navigation across all primary sections.
///
/// Features:
/// - Biometric lock screen (when enabled in settings)
/// - Tab badges for pending approval count
/// - Deep link support for notification taps
/// - State restoration across app lifecycle
struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var requireBiometric: Bool = UserDefaults.standard.bool(forKey: "biometric_enabled")
    @State private var isUnlocked: Bool = false

    var body: some View {
        Group {
            if requireBiometric && !isUnlocked {
                lockedView
            } else {
                mainTabView
            }
        }
        .onAppear {
            // If biometric is not enabled, skip the lock screen
            if !requireBiometric {
                isUnlocked = true
            }
        }
    }

    private var mainTabView: some View {
        TabView(selection: $appState.selectedTab) {
            DashboardView()
                .tabItem {
                    Label("Dashboard", systemImage: "shield.checkered")
                }
                .tag(AppTab.dashboard)
                .badge(appState.runningCount)

            PendingView()
                .tabItem {
                    Label("Pending", systemImage: "bell.badge")
                }
                .tag(AppTab.pending)
                .badge(appState.totalPendingCount)

            ChatView()
                .tabItem {
                    Label("Chat", systemImage: "bubble.left.and.bubble.right")
                }
                .tag(AppTab.chat)

            CameraView()
                .tabItem {
                    Label("Camera", systemImage: "camera")
                }
                .tag(AppTab.camera)

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
                .tag(AppTab.settings)
        }
    }

    private var lockedView: some View {
        VStack(spacing: 24) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 64))
                .foregroundStyle(.blue)

            Text("Aegis Fleet Manager")
                .font(.title2)
                .fontWeight(.bold)

            Text("Authenticate to access your agent fleet")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Button("Unlock") {
                authenticate()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .onAppear {
            authenticate()
        }
    }

    private func authenticate() {
        BiometricAuth.authenticate(reason: "Unlock Aegis to access your agent fleet") { success in
            if success {
                isUnlocked = true
            }
        }
    }
}

// MARK: - Input Sanitizer

/// Strips control characters from user input before sending to the daemon.
/// Prevents injection of terminal escape sequences or other control codes.
enum InputSanitizer {
    static func sanitize(_ input: String) -> String {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Remove control characters (U+0000 to U+001F, U+007F) except common whitespace
        return String(trimmed.unicodeScalars.filter { scalar in
            // Allow printable characters and standard space
            scalar.value >= 0x20 && scalar.value != 0x7F
        })
    }
}

// MARK: - App State

/// Observable application state that manages daemon connection and fleet data.
///
/// Polls the daemon API periodically and exposes agent/pending data to all views.
/// All state mutations happen on the main actor to ensure UI consistency.
///
/// Supports:
/// - HTTP polling (fallback, always active)
/// - WebSocket for real-time updates (when available)
/// - Deep linking from notifications
/// - Connection state tracking with auto-reconnect
@MainActor
final class AppState: ObservableObject {
    @Published var agents: [AgentInfo] = []
    @Published var pendingPrompts: [PendingPrompt] = []
    @Published var connectionError: String?
    @Published var isConnected: Bool = false
    @Published var connectionState: ConnectionState = .disconnected
    @Published var recentActivity: [ActivityEntry] = []

    // Navigation state for deep linking
    @Published var selectedTab: AppTab = .dashboard
    @Published var deepLinkAgentName: String?
    @Published var deepLinkRequestId: String?

    private var client: DaemonClient
    private var pollTask: Task<Void, Never>?
    private var wsTask: Task<Void, Never>?

    init() {
        self.client = DaemonClient()
    }

    deinit {
        pollTask?.cancel()
        wsTask?.cancel()
    }

    /// Reconfigure the client with a new base URL.
    /// Called when the user changes the server URL in settings.
    func reconfigure(baseURL: URL) {
        client = DaemonClient(baseURL: baseURL)
        // Restart polling with the new client
        startPolling()
        // Restart WebSocket if it was active
        connectWebSocket()
    }

    /// Begin periodic polling of the daemon API every 5 seconds.
    func startPolling() {
        pollTask?.cancel()
        connectionState = .connecting
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 5_000_000_000) // 5 seconds
            }
        }
    }

    /// Fetch latest fleet data from the daemon.
    func refresh() async {
        do {
            let agentList = try await client.listAgents()

            // Track activity: detect status changes
            for newAgent in agentList {
                if let oldAgent = agents.first(where: { $0.name == newAgent.name }) {
                    if oldAgent.statusKind != newAgent.statusKind {
                        let entry = ActivityEntry(
                            agentName: newAgent.name,
                            description: "\(newAgent.name): \(oldAgent.statusKind.displayName) -> \(newAgent.statusKind.displayName)",
                            timestamp: Date()
                        )
                        recentActivity.insert(entry, at: 0)
                        // Keep only last 50 entries
                        if recentActivity.count > 50 {
                            recentActivity = Array(recentActivity.prefix(50))
                        }
                    }
                }
            }

            self.agents = agentList
            self.isConnected = true
            self.connectionState = .connected
            self.connectionError = nil

            // Collect pending prompts for agents that have them
            var allPending: [PendingPrompt] = []
            for agent in agentList where agent.pendingCount > 0 {
                if let prompts = try? await client.listPending(agentName: agent.name) {
                    allPending.append(contentsOf: prompts)
                }
            }
            self.pendingPrompts = allPending
        } catch {
            self.isConnected = false
            self.connectionState = .disconnected
            self.connectionError = error.localizedDescription
        }
    }

    /// Connect to the daemon WebSocket for real-time updates.
    func connectWebSocket() {
        wsTask?.cancel()
        wsTask = Task { [weak self] in
            guard let self = self else { return }
            let stream = self.client.connectWebSocket()
            for await event in stream {
                switch event {
                case .connected:
                    self.connectionState = .connected
                case .message:
                    // Trigger a refresh when we get a WebSocket message
                    // The message itself contains event data, but for simplicity
                    // we just refresh the full state.
                    await self.refresh()
                case .disconnected:
                    self.connectionState = .disconnected
                case .error:
                    self.connectionState = .disconnected
                }
            }
        }
    }

    /// Test connection to the daemon. Returns nil on success, error message on failure.
    func testConnection() async -> String? {
        do {
            _ = try await client.getStatus()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    // MARK: - Agent Actions

    func approve(requestId: String, agentName: String) async throws {
        try await client.approve(requestId: requestId, agentName: agentName)
        await refresh()
    }

    func deny(requestId: String, agentName: String, reason: String?) async throws {
        try await client.deny(requestId: requestId, agentName: agentName, reason: reason)
        await refresh()
    }

    func sendInput(agentName: String, text: String) async throws {
        let sanitized = InputSanitizer.sanitize(text)
        guard !sanitized.isEmpty else { return }
        try await client.sendToAgent(agentName: agentName, text: sanitized)
    }

    func startAgent(name: String) async throws {
        try await client.startAgent(name: name)
        await refresh()
    }

    func stopAgent(name: String) async throws {
        try await client.stopAgent(name: name)
        await refresh()
    }

    func restartAgent(name: String) async throws {
        try await client.restartAgent(name: name)
        await refresh()
    }

    func nudgeAgent(name: String) async throws {
        try await client.nudgeAgent(name: name)
    }

    func fetchAgentOutput(agentId: String) async throws -> [String] {
        return try await client.fetchAgentOutput(agentId: agentId)
    }

    // MARK: - Computed Summaries

    var runningCount: Int {
        agents.filter { $0.statusKind == .running }.count
    }

    var totalPendingCount: Int {
        agents.reduce(0) { $0 + $1.pendingCount }
    }

    var healthSummary: String {
        if agents.isEmpty {
            return "No agents"
        }
        var parts: [String] = []
        parts.append("\(runningCount)/\(agents.count) running")
        if totalPendingCount > 0 {
            parts.append("\(totalPendingCount) pending")
        }
        let crashed = agents.filter { $0.statusKind == .crashed || $0.statusKind == .failed }.count
        if crashed > 0 {
            parts.append("\(crashed) failed")
        }
        return parts.joined(separator: ", ")
    }
}

// MARK: - Activity Entry

/// A single entry in the recent activity feed.
struct ActivityEntry: Identifiable {
    let id = UUID()
    let agentName: String
    let description: String
    let timestamp: Date

    var timeAgo: String {
        let seconds = Int(Date().timeIntervalSince(timestamp))
        if seconds < 60 { return "\(seconds)s ago" }
        if seconds < 3600 { return "\(seconds / 60)m ago" }
        return "\(seconds / 3600)h ago"
    }
}
