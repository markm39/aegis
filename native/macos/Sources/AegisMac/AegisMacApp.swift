import SwiftUI

/// Aegis macOS menu bar application.
///
/// Runs as a menu bar-only app (no Dock icon). The main window opens
/// on demand via "Open Dashboard" in the menu bar dropdown.
@main
struct AegisMacApp: App {
    @StateObject private var fleetState = FleetState()
    @StateObject private var notificationManager = NotificationManager()

    var body: some Scene {
        // Menu bar icon with dropdown
        MenuBarExtra("Aegis", systemImage: menuBarIcon) {
            MenuBarView(fleetState: fleetState)
        }
        .menuBarExtraStyle(.window)

        // Dashboard window, opened on demand
        Window("Aegis Dashboard", id: "dashboard") {
            DashboardWindow(fleetState: fleetState)
                .frame(minWidth: 800, minHeight: 500)
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

    private let client = DaemonClient()
    private var pollTask: Task<Void, Never>?

    init() {
        startPolling()
    }

    deinit {
        pollTask?.cancel()
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

    /// Fetch latest fleet data from the daemon.
    func refresh() async {
        do {
            let agentList = try await client.listAgents()
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
        await refresh()
    }

    /// Deny a pending permission request.
    func deny(requestId: String, agentName: String, reason: String?) async throws {
        try await client.deny(requestId: requestId, agentName: agentName, reason: reason)
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
}
