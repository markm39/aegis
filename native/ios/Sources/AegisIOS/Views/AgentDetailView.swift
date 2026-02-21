import SwiftUI

/// Detail view for a single agent showing status, output log, pending approvals, and input.
///
/// Sections:
/// - Agent info: name, model/tool, status, uptime, working directory
/// - Output log: monospace scrollview with auto-scroll to bottom
/// - Pending approvals: approve/deny buttons with confirmation
/// - Input: text field for sending input to the agent
struct AgentDetailView: View {
    let agent: AgentInfo
    @EnvironmentObject var appState: AppState

    @State private var inputText: String = ""
    @State private var outputLines: [String] = []
    @State private var showDenyAlert: Bool = false
    @State private var denyPromptId: String?
    @State private var denyReason: String = ""
    @State private var showApproveConfirm: Bool = false
    @State private var approvePromptId: String?
    @State private var errorMessage: String?
    @State private var outputRefreshTask: Task<Void, Never>?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Agent info section
                infoSection

                // Output log
                outputSection

                // Pending approvals
                if !pendingPrompts.isEmpty {
                    pendingSection
                }

                // Input section
                inputSection
            }
            .padding()
        }
        .navigationTitle(agent.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                agentActionsMenu
            }
        }
        .alert("Confirm Approval", isPresented: $showApproveConfirm) {
            Button("Approve", role: .none) {
                if let promptId = approvePromptId {
                    performApprove(promptId: promptId)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Are you sure you want to approve this request?")
        }
        .alert("Deny Request", isPresented: $showDenyAlert) {
            TextField("Reason (optional)", text: $denyReason)
            Button("Deny", role: .destructive) {
                if let promptId = denyPromptId {
                    performDeny(promptId: promptId, reason: denyReason.isEmpty ? nil : denyReason)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Provide an optional reason for denying this request.")
        }
        .onAppear { startOutputRefresh() }
        .onDisappear { outputRefreshTask?.cancel() }
        // Error banner
        .safeAreaInset(edge: .bottom) {
            if let error = errorMessage {
                errorBanner(error)
            }
        }
    }

    // MARK: - Computed

    private var pendingPrompts: [PendingPrompt] {
        appState.pendingPrompts.filter { $0.agentName == agent.name }
    }

    // MARK: - Info Section

    private var infoSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                detailRow("Status", value: agent.statusKind.displayName, color: statusColor)
                detailRow("Tool", value: agent.tool)
                detailRow("Working Dir", value: agent.workingDir)
                if let role = agent.role {
                    detailRow("Role", value: role)
                }
                detailRow("Restarts", value: "\(agent.restartCount)")
                detailRow("Pending", value: "\(agent.pendingCount)")
                detailRow("Orchestrator", value: agent.isOrchestrator ? "Yes" : "No")
                if agent.attentionNeeded {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.yellow)
                        Text("Attention needed")
                            .font(.subheadline)
                            .fontWeight(.medium)
                    }
                }
            }
        } label: {
            Label("Agent Info", systemImage: "info.circle")
        }
    }

    private func detailRow(_ label: String, value: String, color: Color? = nil) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .frame(width: 100, alignment: .leading)
            Text(value)
                .font(.system(.subheadline, design: .monospaced))
                .foregroundStyle(color ?? .primary)
            Spacer()
        }
    }

    // MARK: - Output Section

    private var outputSection: some View {
        GroupBox {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        if outputLines.isEmpty {
                            Text("No output available")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .padding(8)
                        } else {
                            ForEach(Array(outputLines.enumerated()), id: \.offset) { index, line in
                                Text(line)
                                    .font(.system(.caption2, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(index)
                            }
                        }
                    }
                    .padding(4)
                }
                .frame(maxHeight: 300)
                .onChange(of: outputLines.count) { _ in
                    if let last = outputLines.indices.last {
                        withAnimation(.easeOut(duration: 0.2)) {
                            proxy.scrollTo(last, anchor: .bottom)
                        }
                    }
                }
            }
            .background(Color(.systemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        } label: {
            Label("Output", systemImage: "terminal")
        }
    }

    // MARK: - Pending Section

    private var pendingSection: some View {
        GroupBox {
            VStack(spacing: 12) {
                ForEach(pendingPrompts, id: \.requestId) { prompt in
                    VStack(alignment: .leading, spacing: 8) {
                        // Prompt text
                        Text(prompt.rawPrompt)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(6)
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(.systemGroupedBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 6))

                        // Metadata and actions
                        HStack {
                            // Risk badge
                            riskBadge(prompt.riskLevel)

                            Text("Age: \(prompt.ageSecs)s")
                                .font(.caption2)
                                .foregroundStyle(.secondary)

                            Spacer()

                            Button {
                                approvePromptId = prompt.requestId
                                showApproveConfirm = true
                            } label: {
                                Label("Approve", systemImage: "checkmark.circle")
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.green)
                            .controlSize(.small)

                            Button {
                                denyPromptId = prompt.requestId
                                denyReason = ""
                                showDenyAlert = true
                            } label: {
                                Label("Deny", systemImage: "xmark.circle")
                            }
                            .buttonStyle(.bordered)
                            .tint(.red)
                            .controlSize(.small)
                        }
                    }
                    .padding(8)
                    .background(Color.orange.opacity(0.05))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
        } label: {
            Label("Pending Approvals (\(pendingPrompts.count))", systemImage: "bell.badge")
        }
    }

    // MARK: - Input Section

    private var inputSection: some View {
        GroupBox {
            HStack(spacing: 8) {
                TextField("Send input to agent...", text: $inputText)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { sendInput() }

                Button {
                    sendInput()
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title3)
                }
                .disabled(InputSanitizer.sanitize(inputText).isEmpty)
            }
        } label: {
            Label("Input", systemImage: "keyboard")
        }
    }

    // MARK: - Agent Actions Menu

    private var agentActionsMenu: some View {
        Menu {
            switch agent.statusKind {
            case .running:
                Button {
                    performAction { try await appState.stopAgent(name: agent.name) }
                } label: {
                    Label("Stop", systemImage: "stop.circle")
                }
                Button {
                    performAction { try await appState.restartAgent(name: agent.name) }
                } label: {
                    Label("Restart", systemImage: "arrow.counterclockwise.circle")
                }
            case .stopped, .crashed, .failed, .pending, .disabled:
                Button {
                    performAction { try await appState.startAgent(name: agent.name) }
                } label: {
                    Label("Start", systemImage: "play.circle")
                }
            case .stopping:
                Text("Stopping...")
            }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
    }

    // MARK: - Helpers

    private var statusColor: Color {
        switch agent.statusKind {
        case .running: return .green
        case .pending, .stopping: return .yellow
        case .stopped, .disabled: return .gray
        case .crashed, .failed: return .red
        }
    }

    private func riskBadge(_ risk: RiskLevel) -> some View {
        Text(risk.rawValue)
            .font(.caption2)
            .fontWeight(.semibold)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
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

    private func sendInput() {
        let text = InputSanitizer.sanitize(inputText)
        guard !text.isEmpty else { return }
        inputText = ""
        performAction {
            try await appState.sendInput(agentName: agent.name, text: text)
        }
    }

    private func performApprove(promptId: String) {
        performAction {
            try await appState.approve(requestId: promptId, agentName: agent.name)
        }
    }

    private func performDeny(promptId: String, reason: String?) {
        performAction {
            try await appState.deny(requestId: promptId, agentName: agent.name, reason: reason)
        }
    }

    private func performAction(_ action: @escaping () async throws -> Void) {
        Task {
            do {
                try await action()
                errorMessage = nil
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func startOutputRefresh() {
        outputRefreshTask?.cancel()
        outputRefreshTask = Task {
            while !Task.isCancelled {
                do {
                    let lines = try await appState.fetchAgentOutput(agentId: agent.name)
                    await MainActor.run {
                        self.outputLines = lines
                    }
                } catch {
                    // Silently continue -- output fetch is best-effort
                }
                try? await Task.sleep(nanoseconds: 3_000_000_000)
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
