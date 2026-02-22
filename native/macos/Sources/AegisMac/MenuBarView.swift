import SwiftUI

/// Dropdown content shown when the menu bar icon is clicked.
struct MenuBarView: View {
    @ObservedObject var fleetState: FleetState
    @ObservedObject var gatewayManager: GatewayManager
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

            // Pending approvals with quick actions
            if fleetState.totalPendingCount > 0 {
                Divider()
                pendingSection
            }

            // Recent activity feed
            if !fleetState.recentActivity.isEmpty {
                Divider()
                activitySection
            }

            Divider()

            // Daemon controls
            daemonControlSection

            Divider()

            // Quick actions
            actionSection

            Divider()

            Button("Quit Aegis") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q", modifiers: .command)
        }
        .padding(12)
        .frame(width: 320)
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack {
            Circle()
                .fill(statusIndicatorColor)
                .frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 2) {
                Text(fleetState.isConnected ? fleetState.healthSummary : "Disconnected")
                    .font(.headline)
                if let error = fleetState.connectionError {
                    Text(error)
                        .font(.caption2)
                        .foregroundStyle(.red)
                        .lineLimit(1)
                }
            }
            Spacer()
            Text(fleetState.connectionState.displayName)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 8)
    }

    /// Status indicator color: green=all good, yellow=pending, red=error.
    private var statusIndicatorColor: Color {
        if !fleetState.isConnected {
            return .red
        }
        let hasCrashed = fleetState.agents.contains {
            $0.statusKind == .crashed || $0.statusKind == .failed
        }
        if hasCrashed {
            return .red
        }
        if fleetState.totalPendingCount > 0 {
            return .yellow
        }
        return .green
    }

    // MARK: - Agent List

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

    // MARK: - Pending Section

    private var pendingSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: "bell.badge")
                    .foregroundStyle(.orange)
                Text("\(fleetState.totalPendingCount) pending approval\(fleetState.totalPendingCount == 1 ? "" : "s")")
                    .font(.subheadline)
                    .fontWeight(.medium)
                Spacer()
            }
            .padding(.horizontal, 8)

            // Show first few pending prompts
            ForEach(Array(fleetState.pendingPrompts.prefix(3)), id: \.requestId) { prompt in
                HStack(spacing: 4) {
                    Text(prompt.agentName)
                        .font(.caption)
                        .fontWeight(.medium)
                    Text(prompt.rawPrompt)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                .padding(.horizontal, 12)
            }

            // Approve All / Deny All buttons
            HStack(spacing: 8) {
                Button {
                    Task { try? await fleetState.approveAll() }
                } label: {
                    Label("Approve All", systemImage: "checkmark.circle.fill")
                        .font(.caption)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .controlSize(.small)

                Button {
                    Task { try? await fleetState.denyAll(reason: nil) }
                } label: {
                    Label("Deny All", systemImage: "xmark.circle.fill")
                        .font(.caption)
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .controlSize(.small)
            }
            .padding(.horizontal, 8)
        }
    }

    // MARK: - Activity Feed

    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Recent Activity")
                .font(.caption)
                .fontWeight(.medium)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 8)

            ForEach(Array(fleetState.recentActivity.prefix(5))) { event in
                HStack(spacing: 6) {
                    Image(systemName: event.iconName)
                        .font(.caption2)
                        .foregroundStyle(activityColor(for: event.kind))
                    Text(event.summary)
                        .font(.caption2)
                        .lineLimit(1)
                    Spacer()
                    Text(event.relativeTime)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                .padding(.horizontal, 8)
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

    // MARK: - Daemon Controls

    private var daemonControlSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                if gatewayManager.isDaemonRunning {
                    Button {
                        Task { await gatewayManager.stopDaemon() }
                    } label: {
                        Label("Stop Daemon", systemImage: "stop.fill")
                            .font(.caption)
                    }
                    .controlSize(.small)
                } else {
                    Button {
                        Task { await gatewayManager.startDaemon() }
                    } label: {
                        Label("Start Daemon", systemImage: "play.fill")
                            .font(.caption)
                    }
                    .controlSize(.small)
                }

                Spacer()

                HStack(spacing: 4) {
                    Circle()
                        .fill(gatewayManager.isDaemonRunning ? Color.green : Color.gray)
                        .frame(width: 6, height: 6)
                    Text(gatewayManager.isDaemonRunning ? "Daemon Running" : "Daemon Stopped")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 8)
        }
    }

    // MARK: - Actions

    private var actionSection: some View {
        VStack(alignment: .leading, spacing: 2) {
            Button {
                openWindow(id: "dashboard")
            } label: {
                Label("Open Dashboard", systemImage: "rectangle.grid.1x2")
            }
            .keyboardShortcut("d", modifiers: .command)

            Button {
                openWindow(id: "chat")
            } label: {
                Label("Open Chat", systemImage: "bubble.left.and.bubble.right")
            }
            .keyboardShortcut("c", modifiers: [.command, .shift])

            Button {
                openWindow(id: "voice")
            } label: {
                Label("Voice Mode", systemImage: "waveform")
            }
            .keyboardShortcut("v", modifiers: [.command, .shift])

            Button {
                Task { await fleetState.refresh() }
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .keyboardShortcut("r", modifiers: .command)
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
