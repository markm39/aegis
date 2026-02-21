import SwiftUI

/// Main dashboard window showing agent table, detail view, and pending approvals.
struct DashboardWindow: View {
    @ObservedObject var fleetState: FleetState
    @State private var selectedAgentName: String?

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            if let name = selectedAgentName,
               let agent = fleetState.agents.first(where: { $0.name == name }) {
                AgentDetailView(
                    agent: agent,
                    pendingPrompts: fleetState.pendingPrompts.filter { $0.agentName == name },
                    fleetState: fleetState
                )
            } else {
                ContentUnavailableView(
                    "Select an Agent",
                    systemImage: "shield",
                    description: Text("Choose an agent from the sidebar to view details.")
                )
            }
        }
        .navigationTitle("Aegis Fleet Dashboard")
        .toolbar {
            ToolbarItem(placement: .automatic) {
                connectionIndicator
            }
            ToolbarItem(placement: .automatic) {
                Button {
                    Task { await fleetState.refresh() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh fleet status")
            }
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List(selection: $selectedAgentName) {
            Section("Fleet (\(fleetState.healthSummary))") {
                ForEach(fleetState.agents, id: \.name) { agent in
                    agentRow(agent)
                        .tag(agent.name)
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
        .frame(minWidth: 220)
    }

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
