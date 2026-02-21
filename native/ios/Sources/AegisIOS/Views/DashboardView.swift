import SwiftUI

/// Fleet dashboard showing all agents with status, pending counts, and navigation to details.
///
/// Features:
/// - Agent list with color-coded status indicators
/// - Pending count badges on agents with outstanding approvals
/// - Pull-to-refresh for manual data reload
/// - Auto-refresh every 5 seconds via AppState polling
/// - Navigation to AgentDetailView for each agent
struct DashboardView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        NavigationStack {
            Group {
                if !appState.isConnected && appState.agents.isEmpty {
                    disconnectedView
                } else if appState.agents.isEmpty {
                    emptyFleetView
                } else {
                    agentList
                }
            }
            .navigationTitle("Fleet")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    connectionIndicator
                }
            }
        }
    }

    // MARK: - Agent List

    private var agentList: some View {
        List {
            // Fleet summary header
            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(appState.healthSummary)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if appState.totalPendingCount > 0 {
                        HStack(spacing: 4) {
                            Image(systemName: "bell.badge")
                                .foregroundStyle(.orange)
                            Text("\(appState.totalPendingCount)")
                                .fontWeight(.semibold)
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }

            // Agent rows
            Section("Agents") {
                ForEach(appState.agents, id: \.name) { agent in
                    NavigationLink {
                        AgentDetailView(agent: agent)
                    } label: {
                        agentRow(agent)
                    }
                }
            }
        }
        .refreshable {
            await appState.refresh()
        }
    }

    private func agentRow(_ agent: AgentInfo) -> some View {
        HStack(spacing: 12) {
            // Status indicator
            Circle()
                .fill(statusColor(for: agent.statusKind))
                .frame(width: 12, height: 12)

            // Agent info
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(agent.name)
                        .font(.body)
                        .fontWeight(.medium)
                    if agent.isOrchestrator {
                        Image(systemName: "arrow.triangle.branch")
                            .font(.caption2)
                            .foregroundStyle(.blue)
                    }
                }
                HStack(spacing: 8) {
                    Text(agent.tool)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(agent.statusKind.displayName)
                        .font(.caption)
                        .foregroundStyle(statusColor(for: agent.statusKind))
                }
            }

            Spacer()

            // Badges
            HStack(spacing: 8) {
                if agent.pendingCount > 0 {
                    Text("\(agent.pendingCount)")
                        .font(.caption2)
                        .fontWeight(.bold)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
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
        }
        .padding(.vertical, 4)
    }

    // MARK: - Empty / Disconnected States

    private var disconnectedView: some View {
        ContentUnavailableView {
            Label("Disconnected", systemImage: "wifi.slash")
        } description: {
            Text("Cannot reach the Aegis daemon. Check your server URL in Settings.")
        } actions: {
            Button("Retry") {
                Task { await appState.refresh() }
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private var emptyFleetView: some View {
        ContentUnavailableView {
            Label("No Agents", systemImage: "shield")
        } description: {
            Text("No agents are configured in the fleet. Add agents via the daemon or TUI.")
        } actions: {
            Button("Refresh") {
                Task { await appState.refresh() }
            }
            .buttonStyle(.bordered)
        }
    }

    // MARK: - Toolbar

    private var connectionIndicator: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(appState.isConnected ? Color.green : Color.red)
                .frame(width: 8, height: 8)
            Text(appState.isConnected ? "Connected" : "Offline")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: - Helpers

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
