import SwiftUI
#if canImport(WidgetKit)
import WidgetKit
#endif

// MARK: - Widget Data

/// Snapshot of fleet status used by widget views.
///
/// When WidgetKit is available, this conforms to TimelineEntry.
/// The views can also be used standalone for previews.
struct AegisWidgetEntry
    #if canImport(WidgetKit)
    : TimelineEntry
    #endif
{
    let date: Date
    let totalAgents: Int
    let runningAgents: Int
    let pendingApprovals: Int
    let failedAgents: Int
    let agentSummaries: [WidgetAgentSummary]
}

/// Minimal agent summary for widget display.
struct WidgetAgentSummary: Identifiable {
    let id = UUID()
    let name: String
    let status: AgentStatusKind
    let pendingCount: Int
}

// MARK: - Timeline Provider

#if canImport(WidgetKit)
/// Provides timeline entries for the Aegis home screen widget.
///
/// Fetches fleet status from the daemon API and generates periodic timeline entries.
/// Falls back to placeholder data when the daemon is unreachable.
struct AegisWidgetProvider: TimelineProvider {
    typealias Entry = AegisWidgetEntry

    func placeholder(in context: Context) -> AegisWidgetEntry {
        AegisWidgetEntry(
            date: Date(),
            totalAgents: 3,
            runningAgents: 2,
            pendingApprovals: 1,
            failedAgents: 0,
            agentSummaries: [
                WidgetAgentSummary(name: "claude-1", status: .running, pendingCount: 0),
                WidgetAgentSummary(name: "claude-2", status: .running, pendingCount: 1),
                WidgetAgentSummary(name: "agent-3", status: .stopped, pendingCount: 0),
            ]
        )
    }

    func getSnapshot(in context: Context, completion: @escaping (AegisWidgetEntry) -> Void) {
        if context.isPreview {
            completion(placeholder(in: context))
            return
        }

        Task {
            let entry = await fetchEntry()
            completion(entry)
        }
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<AegisWidgetEntry>) -> Void) {
        Task {
            let entry = await fetchEntry()
            // Refresh every 5 minutes
            let nextUpdate = Calendar.current.date(byAdding: .minute, value: 5, to: entry.date) ?? entry.date
            let timeline = Timeline(entries: [entry], policy: .after(nextUpdate))
            completion(timeline)
        }
    }

    /// Fetch current fleet status from the daemon.
    private func fetchEntry() async -> AegisWidgetEntry {
        let client = DaemonClient()
        do {
            let agents = try await client.listAgents()
            let summaries = agents.prefix(5).map { agent in
                WidgetAgentSummary(
                    name: agent.name,
                    status: agent.statusKind,
                    pendingCount: agent.pendingCount
                )
            }
            return AegisWidgetEntry(
                date: Date(),
                totalAgents: agents.count,
                runningAgents: agents.filter { $0.statusKind == .running }.count,
                pendingApprovals: agents.reduce(0) { $0 + $1.pendingCount },
                failedAgents: agents.filter { $0.statusKind == .crashed || $0.statusKind == .failed }.count,
                agentSummaries: Array(summaries)
            )
        } catch {
            // Return empty entry when daemon is unreachable
            return AegisWidgetEntry(
                date: Date(),
                totalAgents: 0,
                runningAgents: 0,
                pendingApprovals: 0,
                failedAgents: 0,
                agentSummaries: []
            )
        }
    }
}
#endif

// MARK: - Widget Views

/// Small widget showing agent count and pending approvals.
struct AegisWidgetSmallView: View {
    let entry: AegisWidgetEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "shield.checkered")
                    .foregroundStyle(.blue)
                Text("Aegis")
                    .font(.headline)
                    .fontWeight(.bold)
            }

            Spacer()

            if entry.totalAgents == 0 {
                Text("Disconnected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(.green)
                            .frame(width: 8, height: 8)
                        Text("\(entry.runningAgents)/\(entry.totalAgents) running")
                            .font(.caption)
                    }

                    if entry.pendingApprovals > 0 {
                        HStack(spacing: 4) {
                            Image(systemName: "bell.badge")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                            Text("\(entry.pendingApprovals) pending")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }

                    if entry.failedAgents > 0 {
                        HStack(spacing: 4) {
                            Image(systemName: "exclamationmark.circle")
                                .font(.caption2)
                                .foregroundStyle(.red)
                            Text("\(entry.failedAgents) failed")
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                    }
                }
            }
        }
        .padding()
    }
}

/// Medium widget showing agent list with status.
struct AegisWidgetMediumView: View {
    let entry: AegisWidgetEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Header
            HStack {
                Image(systemName: "shield.checkered")
                    .foregroundStyle(.blue)
                Text("Aegis Fleet")
                    .font(.headline)
                    .fontWeight(.bold)
                Spacer()
                if entry.pendingApprovals > 0 {
                    Text("\(entry.pendingApprovals)")
                        .font(.caption2)
                        .fontWeight(.bold)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.orange)
                        .foregroundStyle(.white)
                        .clipShape(Capsule())
                }
            }

            if entry.agentSummaries.isEmpty {
                Spacer()
                HStack {
                    Spacer()
                    Text("No agents connected")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                Spacer()
            } else {
                // Agent rows
                ForEach(entry.agentSummaries) { agent in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(statusColor(agent.status))
                            .frame(width: 8, height: 8)
                        Text(agent.name)
                            .font(.caption)
                            .lineLimit(1)
                        Spacer()
                        Text(agent.status.displayName)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        if agent.pendingCount > 0 {
                            Text("\(agent.pendingCount)")
                                .font(.caption2)
                                .fontWeight(.bold)
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }
        }
        .padding()
    }

    private func statusColor(_ status: AgentStatusKind) -> Color {
        switch status {
        case .running: return .green
        case .pending, .stopping: return .yellow
        case .stopped, .disabled: return .gray
        case .crashed, .failed: return .red
        }
    }
}

/// Lock screen widget showing pending approval count.
struct AegisLockScreenView: View {
    let entry: AegisWidgetEntry

    var body: some View {
        if entry.pendingApprovals > 0 {
            Label("\(entry.pendingApprovals) pending", systemImage: "bell.badge")
        } else if entry.totalAgents > 0 {
            Label("\(entry.runningAgents) running", systemImage: "shield.checkered")
        } else {
            Label("Offline", systemImage: "wifi.slash")
        }
    }
}

// MARK: - Widget Configuration

/// The main Aegis widget for home screen and lock screen.
///
/// Supports three families:
/// - systemSmall: Fleet summary (agent count, pending, failures)
/// - systemMedium: Agent list with individual statuses
/// - accessoryCircular / accessoryRectangular: Lock screen pending count
///
/// Note: This struct defines the widget configuration. To use it, register
/// it in a WidgetBundle in the widget extension target.
struct AegisWidget {
    /// The widget kind identifier.
    static let kind = "com.aegis.ios.widget"

    #if canImport(WidgetKit)
    /// Creates the widget view for the given entry and family.
    @ViewBuilder
    static func view(for entry: AegisWidgetEntry, family: WidgetFamily) -> some View {
        switch family {
        case .systemSmall:
            AegisWidgetSmallView(entry: entry)
        case .systemMedium:
            AegisWidgetMediumView(entry: entry)
        default:
            AegisLockScreenView(entry: entry)
        }
    }
    #endif
}
