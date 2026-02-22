import SwiftUI

/// Aegis macOS menu bar application.
///
/// Runs as a menu bar-only app (no Dock icon). The main window opens
/// on demand via "Open Dashboard" in the menu bar dropdown.
@main
struct AegisMacApp: App {
    @StateObject private var fleetState = FleetState()
    @StateObject private var notificationManager = NotificationManager()
    @StateObject private var hotkeyManager = HotkeyManager()
    @StateObject private var gatewayManager = GatewayManager()

    var body: some Scene {
        // Menu bar icon with dropdown
        MenuBarExtra("Aegis", systemImage: menuBarIcon) {
            MenuBarView(fleetState: fleetState, gatewayManager: gatewayManager)
                .task {
                    notificationManager.setup()
                }
        }
        .menuBarExtraStyle(.window)

        // Dashboard window, opened on demand
        Window("Aegis Dashboard", id: "dashboard") {
            DashboardWindow(fleetState: fleetState)
                .frame(minWidth: 900, minHeight: 600)
        }

        // Chat window
        Window("Aegis Chat", id: "chat") {
            ChatWindow(fleetState: fleetState)
                .frame(minWidth: 600, minHeight: 400)
        }
        .defaultSize(width: 700, height: 500)

        // Voice overlay
        Window("Aegis Voice", id: "voice") {
            VoiceOverlay(fleetState: fleetState)
                .frame(width: 280, height: 320)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 280, height: 320)

        // Settings window
        Settings {
            SettingsWindow(
                fleetState: fleetState,
                hotkeyManager: hotkeyManager,
                notificationManager: notificationManager
            )
        }
    }

    /// Pick the menu bar icon based on fleet health.
    private var menuBarIcon: String {
        if fleetState.agents.isEmpty {
            return "shield"
        }
        let hasPending = fleetState.agents.contains { $0.pendingCount > 0 }
        let hasCrashed = fleetState.agents.contains { $0.statusKind == .crashed || $0.statusKind == .failed }
        if hasCrashed {
            return "shield.slash"
        }
        if hasPending {
            return "shield.lefthalf.filled"
        }
        return "shield.checkered"
    }
}

// MARK: - Fleet State

/// Observable fleet state, polled from the daemon API.
@MainActor
final class FleetState: ObservableObject {
    @Published var agents: [AgentInfo] = []
    @Published var pendingPrompts: [PendingPrompt] = []
    @Published var connectionError: String?
    @Published var isConnected: Bool = false
    @Published var connectionState: ConnectionState = .disconnected
    @Published var recentActivity: [ActivityEvent] = []
    @Published var searchFilter: String = ""

    let client = DaemonClient()
    private var pollTask: Task<Void, Never>?

    init() {
        startPolling()
        setupWebSocket()
    }

    deinit {
        pollTask?.cancel()
        client.disconnectWebSocket()
    }

    /// Begin periodic polling of the daemon API.
    func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 3_000_000_000) // 3 seconds
            }
        }
    }

    /// Setup WebSocket for real-time updates.
    private func setupWebSocket() {
        client.onConnectionStateChange = { [weak self] state in
            Task { @MainActor in
                self?.connectionState = state
            }
        }

        client.onGatewayMessage = { [weak self] response in
            Task { @MainActor in
                self?.handleGatewayMessage(response)
            }
        }

        client.connectWebSocket()
    }

    /// Handle a gateway WebSocket message.
    private func handleGatewayMessage(_ response: GatewayResponse) {
        // Refresh on any gateway event to keep state fresh
        Task { await refresh() }

        // Add to activity feed based on method
        if let method = response.method {
            let event = ActivityEvent(
                timestamp: Date(),
                agentName: "",
                summary: method,
                kind: .info
            )
            addActivity(event)
        }
    }

    /// Add an activity event, keeping only the most recent entries.
    func addActivity(_ event: ActivityEvent) {
        recentActivity.insert(event, at: 0)
        if recentActivity.count > 50 {
            recentActivity = Array(recentActivity.prefix(50))
        }
    }

    /// Fetch latest fleet data from the daemon.
    func refresh() async {
        do {
            let agentList = try await client.listAgents()

            // Detect changes for activity feed
            let previousAgents = self.agents
            for agent in agentList {
                if let prev = previousAgents.first(where: { $0.name == agent.name }) {
                    if prev.statusKind != agent.statusKind {
                        let kind: ActivityEvent.ActivityKind
                        switch agent.statusKind {
                        case .running: kind = .agentStart
                        case .stopped: kind = .agentStop
                        case .crashed, .failed: kind = .agentCrash
                        default: kind = .info
                        }
                        addActivity(ActivityEvent(
                            timestamp: Date(),
                            agentName: agent.name,
                            summary: "\(agent.name): \(prev.statusKind.displayName) -> \(agent.statusKind.displayName)",
                            kind: kind
                        ))
                    }
                }
            }

            self.agents = agentList
            self.isConnected = true
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
            self.connectionError = error.localizedDescription
        }
    }

    /// Approve a pending permission request.
    func approve(requestId: String, agentName: String) async throws {
        try await client.approve(requestId: requestId, agentName: agentName)
        addActivity(ActivityEvent(
            timestamp: Date(),
            agentName: agentName,
            summary: "Approved request for \(agentName)",
            kind: .approval
        ))
        await refresh()
    }

    /// Deny a pending permission request.
    func deny(requestId: String, agentName: String, reason: String?) async throws {
        try await client.deny(requestId: requestId, agentName: agentName, reason: reason)
        addActivity(ActivityEvent(
            timestamp: Date(),
            agentName: agentName,
            summary: "Denied request for \(agentName)",
            kind: .denial
        ))
        await refresh()
    }

    /// Approve all pending prompts.
    func approveAll() async throws {
        try await client.approveAll(prompts: pendingPrompts)
        addActivity(ActivityEvent(
            timestamp: Date(),
            agentName: "",
            summary: "Approved all \(pendingPrompts.count) pending requests",
            kind: .approval
        ))
        await refresh()
    }

    /// Deny all pending prompts.
    func denyAll(reason: String?) async throws {
        try await client.denyAll(prompts: pendingPrompts, reason: reason)
        addActivity(ActivityEvent(
            timestamp: Date(),
            agentName: "",
            summary: "Denied all \(pendingPrompts.count) pending requests",
            kind: .denial
        ))
        await refresh()
    }

    /// Send text input to an agent.
    func sendInput(agentName: String, text: String) async throws {
        try await client.sendToAgent(agentName: agentName, text: text)
    }

    /// Start an agent.
    func startAgent(name: String) async throws {
        try await client.startAgent(name: name)
        await refresh()
    }

    /// Stop an agent.
    func stopAgent(name: String) async throws {
        try await client.stopAgent(name: name)
        await refresh()
    }

    /// Restart an agent.
    func restartAgent(name: String) async throws {
        try await client.restartAgent(name: name)
        await refresh()
    }

    /// Add a new agent.
    func addAgent(name: String, tool: String, workingDir: String, role: String?) async throws {
        try await client.addAgent(name: name, tool: tool, workingDir: workingDir, role: role)
        addActivity(ActivityEvent(
            timestamp: Date(),
            agentName: name,
            summary: "Added agent \(name)",
            kind: .agentStart
        ))
        await refresh()
    }

    /// Remove an agent.
    func removeAgent(name: String) async throws {
        try await client.removeAgent(name: name)
        addActivity(ActivityEvent(
            timestamp: Date(),
            agentName: name,
            summary: "Removed agent \(name)",
            kind: .agentStop
        ))
        await refresh()
    }

    // MARK: - Computed summaries

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

    /// Agents filtered by the current search term.
    var filteredAgents: [AgentInfo] {
        if searchFilter.isEmpty {
            return agents
        }
        let term = searchFilter.lowercased()
        return agents.filter { agent in
            agent.name.lowercased().contains(term) ||
            agent.tool.lowercased().contains(term) ||
            agent.statusKind.displayName.lowercased().contains(term) ||
            (agent.role?.lowercased().contains(term) ?? false)
        }
    }
}
