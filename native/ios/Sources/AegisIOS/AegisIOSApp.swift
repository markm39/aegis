import SwiftUI

/// Aegis iOS application for fleet management, agent monitoring, and approval workflows.
///
/// The app provides four main tabs:
/// - Dashboard: Fleet overview with agent status
/// - Pending: Approval queue with swipe actions
/// - Chat: Direct agent interaction
/// - Settings: Server configuration and security
@main
struct AegisIOSApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var pushManager = PushManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(pushManager)
                .onAppear {
                    appState.startPolling()
                }
        }
    }
}

// MARK: - Content View

/// Root view with tab navigation across all four primary sections.
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
        TabView {
            DashboardView()
                .tabItem {
                    Label("Dashboard", systemImage: "shield.checkered")
                }
                .badge(appState.runningCount)

            PendingView()
                .tabItem {
                    Label("Pending", systemImage: "bell.badge")
                }
                .badge(appState.totalPendingCount)

            ChatView()
                .tabItem {
                    Label("Chat", systemImage: "bubble.left.and.bubble.right")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
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

// MARK: - Chat View (agent interaction)

/// Simple chat interface for sending input to a selected agent.
struct ChatView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedAgent: String?
    @State private var inputText: String = ""
    @State private var outputLines: [String] = []
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if appState.agents.isEmpty {
                    ContentUnavailableView(
                        "No Agents",
                        systemImage: "bubble.left.and.bubble.right",
                        description: Text("Connect to the daemon to interact with agents.")
                    )
                } else {
                    // Agent picker
                    Picker("Agent", selection: $selectedAgent) {
                        Text("Select an agent").tag(nil as String?)
                        ForEach(appState.agents, id: \.name) { agent in
                            Text(agent.name).tag(agent.name as String?)
                        }
                    }
                    .pickerStyle(.segmented)
                    .padding()

                    // Output area
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 2) {
                                ForEach(Array(outputLines.enumerated()), id: \.offset) { index, line in
                                    Text(line)
                                        .font(.system(.caption, design: .monospaced))
                                        .textSelection(.enabled)
                                        .id(index)
                                }
                            }
                            .padding(.horizontal)
                        }
                        .onChange(of: outputLines.count) { _ in
                            if let last = outputLines.indices.last {
                                proxy.scrollTo(last, anchor: .bottom)
                            }
                        }
                    }
                    .frame(maxHeight: .infinity)

                    Divider()

                    // Input bar
                    HStack(spacing: 8) {
                        TextField("Send input to agent...", text: $inputText)
                            .textFieldStyle(.roundedBorder)
                            .onSubmit { sendInput() }

                        Button {
                            sendInput()
                        } label: {
                            Image(systemName: "arrow.up.circle.fill")
                                .font(.title2)
                        }
                        .disabled(sanitizedInput.isEmpty || selectedAgent == nil)
                    }
                    .padding()
                }

                // Error banner
                if let error = errorMessage {
                    errorBanner(error)
                }
            }
            .navigationTitle("Chat")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    /// Sanitized user input with control characters stripped.
    private var sanitizedInput: String {
        InputSanitizer.sanitize(inputText)
    }

    private func sendInput() {
        let text = sanitizedInput
        guard !text.isEmpty, let agent = selectedAgent else { return }
        inputText = ""
        outputLines.append("> \(text)")
        Task {
            do {
                try await appState.sendInput(agentName: agent, text: text)
                errorMessage = nil
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func errorBanner(_ message: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle")
                .foregroundStyle(.red)
            Text(message)
                .font(.caption)
                .foregroundStyle(.red)
            Spacer()
            Button("Dismiss") {
                errorMessage = nil
            }
            .font(.caption)
        }
        .padding(8)
        .background(Color.red.opacity(0.1))
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
@MainActor
final class AppState: ObservableObject {
    @Published var agents: [AgentInfo] = []
    @Published var pendingPrompts: [PendingPrompt] = []
    @Published var connectionError: String?
    @Published var isConnected: Bool = false

    private var client: DaemonClient
    private var pollTask: Task<Void, Never>?

    init() {
        self.client = DaemonClient()
    }

    deinit {
        pollTask?.cancel()
    }

    /// Reconfigure the client with a new base URL.
    /// Called when the user changes the server URL in settings.
    func reconfigure(baseURL: URL) {
        client = DaemonClient(baseURL: baseURL)
        // Restart polling with the new client
        startPolling()
    }

    /// Begin periodic polling of the daemon API every 5 seconds.
    func startPolling() {
        pollTask?.cancel()
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
