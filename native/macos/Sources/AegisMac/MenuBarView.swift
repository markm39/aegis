import SwiftUI

/// Dropdown content shown when the menu bar icon is clicked.
struct MenuBarView: View {
    @ObservedObject var fleetState: FleetState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Connection status / health summary
            headerSection

            Divider()

            // Agent list
            if fleetState.agents.isEmpty {
                Text("No agents configured")
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 8)
            } else {
                agentListSection
            }

            // Pending approvals summary
            if fleetState.totalPendingCount > 0 {
                Divider()
                pendingSection
            }

            Divider()

            // Actions
            Button {
                openWindow(id: "dashboard")
            } label: {
                Label("Open Dashboard", systemImage: "rectangle.grid.1x2")
            }
            .keyboardShortcut("d", modifiers: .command)

            Button {
                Task { await fleetState.refresh() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .keyboardShortcut("r", modifiers: .command)

            Divider()

            Button("Quit Aegis") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q", modifiers: .command)
        }
        .padding(12)
        .frame(width: 300)
    }

    // MARK: - Sections

    private var headerSection: some View {
        HStack {
            Circle()
                .fill(fleetState.isConnected ? Color.green : Color.red)
                .frame(width: 8, height: 8)
            Text(fleetState.isConnected ? fleetState.healthSummary : "Disconnected")
                .font(.headline)
            Spacer()
        }
        .padding(.horizontal, 8)
    }

    private var agentListSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(fleetState.agents, id: \.name) { agent in
                HStack(spacing: 6) {
                    Circle()
                        .fill(statusColor(for: agent.statusKind))
                        .frame(width: 8, height: 8)
                    Text(agent.name)
                        .lineLimit(1)
                    Spacer()
                    if agent.pendingCount > 0 {
                        Text("\(agent.pendingCount)")
                            .font(.caption)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.orange.opacity(0.2))
                            .clipShape(Capsule())
                    }
                    if agent.attentionNeeded {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.yellow)
                            .font(.caption)
                    }
                    Text(agent.statusKind.displayName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
            }
        }
    }

    private var pendingSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: "bell.badge")
                    .foregroundStyle(.orange)
                Text("\(fleetState.totalPendingCount) pending approval\(fleetState.totalPendingCount == 1 ? "" : "s")")
                    .font(.subheadline)
                    .fontWeight(.medium)
            }
            .padding(.horizontal, 8)
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
