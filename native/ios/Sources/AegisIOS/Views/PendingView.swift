import SwiftUI

/// View showing all pending approval requests across all agents.
///
/// Features:
/// - List of pending requests grouped by risk level
/// - Each row shows: agent name, action description, risk level badge
/// - Swipe right to approve (green), swipe left to deny (red)
/// - Confirmation alert before every approve/deny action
/// - Pull-to-refresh for manual reload
struct PendingView: View {
    @EnvironmentObject var appState: AppState

    @State private var showApproveConfirm: Bool = false
    @State private var showDenyAlert: Bool = false
    @State private var selectedPrompt: PendingPrompt?
    @State private var denyReason: String = ""
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if appState.pendingPrompts.isEmpty {
                    emptyView
                } else {
                    pendingList
                }
            }
            .navigationTitle("Pending Approvals")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if !appState.pendingPrompts.isEmpty {
                        Text("\(appState.pendingPrompts.count)")
                            .font(.caption)
                            .fontWeight(.bold)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.orange)
                            .foregroundStyle(.white)
                            .clipShape(Capsule())
                    }
                }
            }
            .alert("Confirm Approval", isPresented: $showApproveConfirm) {
                Button("Approve", role: .none) {
                    if let prompt = selectedPrompt {
                        performApprove(prompt)
                    }
                }
                Button("Cancel", role: .cancel) {
                    selectedPrompt = nil
                }
            } message: {
                if let prompt = selectedPrompt {
                    Text("Approve request from \(prompt.agentName)?\n\n\(truncated(prompt.rawPrompt, maxLength: 150))")
                }
            }
            .alert("Deny Request", isPresented: $showDenyAlert) {
                TextField("Reason (optional)", text: $denyReason)
                Button("Deny", role: .destructive) {
                    if let prompt = selectedPrompt {
                        performDeny(prompt, reason: denyReason.isEmpty ? nil : denyReason)
                    }
                }
                Button("Cancel", role: .cancel) {
                    selectedPrompt = nil
                }
            } message: {
                if let prompt = selectedPrompt {
                    Text("Deny request from \(prompt.agentName)?")
                }
            }
            // Error banner
            .safeAreaInset(edge: .bottom) {
                if let error = errorMessage {
                    errorBanner(error)
                }
            }
        }
    }

    // MARK: - Pending List

    private var pendingList: some View {
        List {
            // High risk first, then medium, then low
            let highRisk = appState.pendingPrompts.filter { $0.riskLevel == .high }
            let mediumRisk = appState.pendingPrompts.filter { $0.riskLevel == .medium }
            let lowRisk = appState.pendingPrompts.filter { $0.riskLevel == .low }

            if !highRisk.isEmpty {
                Section {
                    ForEach(highRisk, id: \.requestId) { prompt in
                        pendingRow(prompt)
                    }
                } header: {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                        Text("High Risk")
                    }
                }
            }

            if !mediumRisk.isEmpty {
                Section {
                    ForEach(mediumRisk, id: \.requestId) { prompt in
                        pendingRow(prompt)
                    }
                } header: {
                    HStack {
                        Image(systemName: "exclamationmark.circle")
                            .foregroundStyle(.yellow)
                        Text("Medium Risk")
                    }
                }
            }

            if !lowRisk.isEmpty {
                Section {
                    ForEach(lowRisk, id: \.requestId) { prompt in
                        pendingRow(prompt)
                    }
                } header: {
                    HStack {
                        Image(systemName: "checkmark.circle")
                            .foregroundStyle(.green)
                        Text("Low Risk")
                    }
                }
            }
        }
        .refreshable {
            await appState.refresh()
        }
    }

    private func pendingRow(_ prompt: PendingPrompt) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            // Agent name and age
            HStack {
                Text(prompt.agentName)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Spacer()
                Text("\(prompt.ageSecs)s ago")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            // Prompt text
            Text(prompt.rawPrompt)
                .font(.system(.caption, design: .monospaced))
                .lineLimit(3)
                .foregroundStyle(.secondary)

            // Risk badge
            HStack {
                riskBadge(prompt.riskLevel)
                Spacer()
            }
        }
        .padding(.vertical, 4)
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            Button {
                selectedPrompt = prompt
                denyReason = ""
                showDenyAlert = true
            } label: {
                Label("Deny", systemImage: "xmark.circle")
            }
            .tint(.red)
        }
        .swipeActions(edge: .leading, allowsFullSwipe: false) {
            Button {
                selectedPrompt = prompt
                showApproveConfirm = true
            } label: {
                Label("Approve", systemImage: "checkmark.circle")
            }
            .tint(.green)
        }
    }

    // MARK: - Empty State

    private var emptyView: some View {
        ContentUnavailableView {
            Label("No Pending Requests", systemImage: "checkmark.shield")
        } description: {
            Text("All clear. No agents are waiting for approval.")
        }
    }

    // MARK: - Helpers

    private func riskBadge(_ risk: RiskLevel) -> some View {
        Text(risk.rawValue)
            .font(.caption2)
            .fontWeight(.semibold)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(riskColor(risk).opacity(0.2))
            .foregroundStyle(riskColor(risk))
            .clipShape(Capsule())
    }

    private func riskColor(_ risk: RiskLevel) -> Color {
        switch risk {
        case .low: return .green
        case .medium: return .yellow
        case .high: return .red
        }
    }

    private func truncated(_ text: String, maxLength: Int) -> String {
        if text.count > maxLength {
            return String(text.prefix(maxLength)) + "..."
        }
        return text
    }

    private func performApprove(_ prompt: PendingPrompt) {
        Task {
            do {
                try await appState.approve(requestId: prompt.requestId, agentName: prompt.agentName)
                errorMessage = nil
            } catch {
                errorMessage = error.localizedDescription
            }
            selectedPrompt = nil
        }
    }

    private func performDeny(_ prompt: PendingPrompt, reason: String?) {
        Task {
            do {
                try await appState.deny(requestId: prompt.requestId, agentName: prompt.agentName, reason: reason)
                errorMessage = nil
            } catch {
                errorMessage = error.localizedDescription
            }
            selectedPrompt = nil
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
