import SwiftUI

/// Sidebar section for navigation.
enum DashboardSection: String, CaseIterable, Identifiable {
    case allAgents = "All Agents"
    case pending = "Pending"
    case activity = "Activity"

    var id: String { rawValue }

    var iconName: String {
        switch self {
        case .allAgents: return "cpu"
        case .pending: return "bell.badge"
        case .activity: return "clock.arrow.circlepath"
        }
    }
}

/// Main dashboard window showing agent table, detail view, and pending approvals.
struct DashboardWindow: View {
    @ObservedObject var fleetState: FleetState
    @State private var selectedAgentName: String?
    @State private var selectedSection: DashboardSection = .allAgents
    @State private var showAddAgentSheet = false
    @State private var searchText: String = ""

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detailContent
        }
        .navigationTitle("Aegis Fleet Dashboard")
        .searchable(text: $searchText, prompt: "Filter agents...")
        .onChange(of: searchText) { newValue in
            fleetState.searchFilter = newValue
        }
        .toolbar {
            ToolbarItemGroup(placement: .automatic) {
                connectionIndicator

                Button {
                    Task { await fleetState.refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh fleet status")

                Button {
                    showAddAgentSheet = true
                } label: {
                    Image(systemName: "plus")
                }
                .help("Add a new agent")
            }
        }
        .sheet(isPresented: $showAddAgentSheet) {
            AddAgentSheet(fleetState: fleetState, isPresented: $showAddAgentSheet)
        }
    }

    // MARK: - Detail Content

    @ViewBuilder
    private var detailContent: some View {
        switch selectedSection {
        case .allAgents:
            if let name = selectedAgentName,
               let agent = fleetState.agents.first(where: { $0.name == name }) {
                AgentDetailView(
                    agent: agent,
                    pendingPrompts: fleetState.pendingPrompts.filter { $0.agentName == name },
                    fleetState: fleetState
                )
            } else {
                agentOverviewTable
            }

        case .pending:
            pendingOverview

        case .activity:
            activityView
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List {
            Section("Navigation") {
                ForEach(DashboardSection.allCases) { section in
                    Button {
                        selectedSection = section
                        if section != .allAgents {
                            selectedAgentName = nil
                        }
                    } label: {
                        Label {
                            HStack {
                                Text(section.rawValue)
                                Spacer()
                                if section == .pending && fleetState.totalPendingCount > 0 {
                                    Text("\(fleetState.totalPendingCount)")
                                        .font(.caption2)
                                        .fontWeight(.bold)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color.orange)
                                        .foregroundStyle(.white)
                                        .clipShape(Capsule())
                                }
                            }
                        } icon: {
                            Image(systemName: section.iconName)
                        }
                    }
                    .buttonStyle(.plain)
                    .padding(.vertical, 2)
                }
            }

            Section("Fleet (\(fleetState.healthSummary))") {
                ForEach(fleetState.filteredAgents, id: \.name) { agent in
                    Button {
                        selectedSection = .allAgents
                        selectedAgentName = agent.name
                    } label: {
                        agentRow(agent)
                    }
                    .buttonStyle(.plain)
                }
            }

            if fleetState.totalPendingCount > 0 {
                Section("Pending Approvals (\(fleetState.totalPendingCount))") {
                    ForEach(fleetState.pendingPrompts, id: \.requestId) { prompt in
                        pendingRow(prompt)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .frame(minWidth: 240)
    }

    // MARK: - Agent Overview Table

    private var agentOverviewTable: some View {
        VStack(spacing: 0) {
            if fleetState.filteredAgents.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: searchText.isEmpty ? "shield" : "magnifyingglass")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text(searchText.isEmpty ? "No Agents" : "No Matching Agents")
                        .font(.headline)
                    Text(
                        searchText.isEmpty
                            ? "Add an agent to get started."
                            : "No agents match '\(searchText)'."
                    )
                    .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(fleetState.filteredAgents) {
                    TableColumn("Status") { agent in
                        HStack(spacing: 6) {
                            Circle()
                                .fill(statusColor(for: agent.statusKind))
                                .frame(width: 10, height: 10)
                            Text(agent.statusKind.displayName)
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                    .width(min: 100, ideal: 120)

                    TableColumn("Name") { agent in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(agent.name)
                                .fontWeight(.medium)
                            if let role = agent.role {
                                Text(role)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .width(min: 120, ideal: 180)

                    TableColumn("Driver") { agent in
                        Text(agent.tool)
                            .font(.system(.body, design: .monospaced))
                    }
                    .width(min: 80, ideal: 100)

                    TableColumn("Restarts") { agent in
                        Text("\(agent.restartCount)")
                            .font(.system(.body, design: .monospaced))
                    }
                    .width(min: 60, ideal: 80)

                    TableColumn("Pending") { agent in
                        if agent.pendingCount > 0 {
                            Text("\(agent.pendingCount)")
                                .font(.caption)
                                .fontWeight(.bold)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(Color.orange)
                                .foregroundStyle(.white)
                                .clipShape(Capsule())
                        } else {
                            Text("0")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .width(min: 60, ideal: 80)

                    TableColumn("Actions") { agent in
                        HStack(spacing: 4) {
                            Button {
                                selectedAgentName = agent.name
                            } label: {
                                Image(systemName: "info.circle")
                            }
                            .buttonStyle(.borderless)
                            .help("View details")

                            if agent.statusKind == .running {
                                Button {
                                    Task { try? await fleetState.stopAgent(name: agent.name) }
                                } label: {
                                    Image(systemName: "stop.circle")
                                }
                                .buttonStyle(.borderless)
                                .help("Stop agent")
                            } else if agent.statusKind == .stopped || agent.statusKind == .crashed {
                                Button {
                                    Task { try? await fleetState.startAgent(name: agent.name) }
                                } label: {
                                    Image(systemName: "play.circle")
                                }
                                .buttonStyle(.borderless)
                                .help("Start agent")
                            }
                        }
                    }
                    .width(min: 80, ideal: 100)
                }
            }
        }
    }

    // MARK: - Pending Overview

    private var pendingOverview: some View {
        VStack(spacing: 0) {
            if fleetState.pendingPrompts.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.circle")
                        .font(.largeTitle)
                        .foregroundStyle(.green)
                    Text("No Pending Approvals")
                        .font(.headline)
                    Text("All agent requests have been handled.")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                // Batch actions toolbar
                HStack {
                    Text("\(fleetState.pendingPrompts.count) pending approval\(fleetState.pendingPrompts.count == 1 ? "" : "s")")
                        .font(.headline)
                    Spacer()
                    Button("Approve All") {
                        Task { try? await fleetState.approveAll() }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)

                    Button("Deny All") {
                        Task { try? await fleetState.denyAll(reason: nil) }
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)
                }
                .padding()

                Divider()

                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(fleetState.pendingPrompts, id: \.requestId) { prompt in
                            PendingPromptCard(prompt: prompt, fleetState: fleetState)
                        }
                    }
                    .padding()
                }
            }
        }
    }

    // MARK: - Activity View

    private var activityView: some View {
        VStack(spacing: 0) {
            if fleetState.recentActivity.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "clock")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("No Recent Activity")
                        .font(.headline)
                    Text("Activity will appear here as agents run.")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(fleetState.recentActivity) { event in
                            HStack(spacing: 8) {
                                Image(systemName: event.iconName)
                                    .foregroundStyle(activityColor(for: event.kind))
                                    .frame(width: 20)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(event.summary)
                                        .font(.body)
                                    if !event.agentName.isEmpty {
                                        Text(event.agentName)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }

                                Spacer()

                                Text(event.relativeTime)
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                            }
                            .padding(.horizontal)
                            .padding(.vertical, 4)

                            Divider()
                                .padding(.leading, 36)
                        }
                    }
                    .padding(.vertical)
                }
            }
        }
    }

    private func activityColor(for kind: ActivityEvent.ActivityKind) -> Color {
        switch kind {
        case .approval: return .green
        case .denial: return .red
        case .agentStart: return .blue
        case .agentStop: return .gray
        case .agentCrash: return .red
        case .info: return .secondary
        }
    }

    // MARK: - Row Views

    private func agentRow(_ agent: AgentInfo) -> some View {
        HStack(spacing: 6) {
            Circle()
                .fill(statusColor(for: agent.statusKind))
                .frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 1) {
                Text(agent.name)
                    .fontWeight(.medium)
                Text(agent.tool)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if agent.pendingCount > 0 {
                Text("\(agent.pendingCount)")
                    .font(.caption2)
                    .fontWeight(.bold)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.orange)
                    .foregroundStyle(.white)
                    .clipShape(Capsule())
            }
            if agent.attentionNeeded {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.yellow)
                    .font(.caption)
            }
        }
        .padding(.vertical, 2)
    }

    private func pendingRow(_ prompt: PendingPrompt) -> some View {
        HStack {
            Image(systemName: "questionmark.circle")
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 1) {
                Text(prompt.agentName)
                    .font(.caption)
                    .fontWeight(.medium)
                Text(prompt.rawPrompt)
                    .font(.caption2)
                    .lineLimit(2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var connectionIndicator: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(fleetState.isConnected ? Color.green : Color.red)
                .frame(width: 6, height: 6)
            Text(fleetState.isConnected ? "Connected" : "Disconnected")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func statusColor(for status: AgentStatusKind) -> Color {
        switch status {
        case .running:
            return .green
        case .pending, .stopping:
            return .yellow
        case .stopped, .disabled:
            return .gray
        case .crashed, .failed:
            return .red
        }
    }
}

// MARK: - Pending Prompt Card

struct PendingPromptCard: View {
    let prompt: PendingPrompt
    @ObservedObject var fleetState: FleetState
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(prompt.agentName, systemImage: "cpu")
                    .font(.subheadline)
                    .fontWeight(.medium)
                Spacer()
                Text("Age: \(prompt.ageSecs)s")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text(prompt.rawPrompt)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(5)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.primary.opacity(0.05))
                .clipShape(RoundedRectangle(cornerRadius: 4))

            HStack {
                if let error = errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Spacer()
                Button("Approve") {
                    Task {
                        do {
                            try await fleetState.approve(
                                requestId: prompt.requestId,
                                agentName: prompt.agentName
                            )
                        } catch {
                            errorMessage = error.localizedDescription
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)

                Button("Deny") {
                    Task {
                        do {
                            try await fleetState.deny(
                                requestId: prompt.requestId,
                                agentName: prompt.agentName,
                                reason: nil
                            )
                        } catch {
                            errorMessage = error.localizedDescription
                        }
                    }
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }
        }
        .padding(12)
        .background(Color.orange.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}

// MARK: - Add Agent Sheet

struct AddAgentSheet: View {
    @ObservedObject var fleetState: FleetState
    @Binding var isPresented: Bool
    @State private var agentName = ""
    @State private var agentTool = "ClaudeCode"
    @State private var workingDir = ""
    @State private var role = ""
    @State private var errorMessage: String?

    private let tools = ["ClaudeCode", "Generic"]

    var body: some View {
        VStack(spacing: 16) {
            Text("Add Agent")
                .font(.headline)

            Form {
                TextField("Agent Name:", text: $agentName)
                Picker("Driver:", selection: $agentTool) {
                    ForEach(tools, id: \.self) { tool in
                        Text(tool).tag(tool)
                    }
                }
                TextField("Working Directory:", text: $workingDir)
                TextField("Role (optional):", text: $role)
            }

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            HStack {
                Button("Cancel") {
                    isPresented = false
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Add") {
                    Task {
                        do {
                            try await fleetState.addAgent(
                                name: agentName,
                                tool: agentTool,
                                workingDir: workingDir,
                                role: role.isEmpty ? nil : role
                            )
                            isPresented = false
                        } catch {
                            errorMessage = error.localizedDescription
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(agentName.isEmpty || workingDir.isEmpty)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 450)
    }
}
