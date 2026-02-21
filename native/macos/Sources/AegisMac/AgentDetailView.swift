import SwiftUI

/// Detail view for a single agent: status, output, pending approvals, input.
struct AgentDetailView: View {
    let agent: AgentInfo
    let pendingPrompts: [PendingPrompt]
    @ObservedObject var fleetState: FleetState

    @State private var inputText: String = ""
    @State private var denyReason: String = ""
    @State private var showDenySheet: Bool = false
    @State private var selectedPromptId: String?
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Agent header
            agentHeader
                .padding()

            Divider()

            // Main content
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Status details
                    statusSection

                    // Pending approvals
                    if !pendingPrompts.isEmpty {
                        pendingSection
                    }

                    // Input field
                    inputSection
                }
                .padding()
            }

            // Error banner
            if let error = errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                    Spacer()
                    Button("Dismiss") {
                        errorMessage = nil
                    }
                    .buttonStyle(.plain)
                    .font(.caption)
                }
                .padding(8)
                .background(Color.red.opacity(0.1))
            }
        }
        .sheet(isPresented: $showDenySheet) {
            denySheet
        }
    }

    // MARK: - Header

    private var agentHeader: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 12, height: 12)
                    Text(agent.name)
                        .font(.title2)
                        .fontWeight(.bold)
                }
                HStack(spacing: 16) {
                    Label(agent.tool, systemImage: "wrench")
                    Label(agent.statusKind.displayName, systemImage: "circle.fill")
                    if agent.restartCount > 0 {
                        Label("Restarts: \(agent.restartCount)", systemImage: "arrow.counterclockwise")
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            agentActions
        }
    }

    private var agentActions: some View {
        HStack(spacing: 8) {
            switch agent.statusKind {
            case .running:
                Button("Stop") {
                    performAction { try await fleetState.stopAgent(name: agent.name) }
                }
                Button("Restart") {
                    performAction { try await fleetState.restartAgent(name: agent.name) }
                }
            case .stopped, .crashed, .failed, .pending, .disabled:
                Button("Start") {
                    performAction { try await fleetState.startAgent(name: agent.name) }
                }
            case .stopping:
                Text("Stopping...")
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Status Section

    private var statusSection: some View {
        GroupBox("Status") {
            VStack(alignment: .leading, spacing: 6) {
                detailRow("Working Directory", value: agent.workingDir)
                if let role = agent.role {
                    detailRow("Role", value: role)
                }
                detailRow("Pending Approvals", value: "\(agent.pendingCount)")
                detailRow("Attention Needed", value: agent.attentionNeeded ? "Yes" : "No")
                detailRow("Orchestrator", value: agent.isOrchestrator ? "Yes" : "No")
            }
            .padding(8)
        }
    }

    private func detailRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 160, alignment: .trailing)
            Text(value)
                .textSelection(.enabled)
            Spacer()
        }
        .font(.system(.body, design: .monospaced))
    }

    // MARK: - Pending Section

    private var pendingSection: some View {
        GroupBox("Pending Approvals (\(pendingPrompts.count))") {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(pendingPrompts, id: \.requestId) { prompt in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(prompt.rawPrompt)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(5)
                            .padding(8)
                            .background(Color.primary.opacity(0.05))
                            .clipShape(RoundedRectangle(cornerRadius: 4))

                        HStack {
                            Text("Age: \(prompt.ageSecs)s")
                                .font(.caption)
                                .foregroundStyle(.secondary)

                            Spacer()

                            Button("Approve") {
                                performAction {
                                    try await fleetState.approve(
                                        requestId: prompt.requestId,
                                        agentName: prompt.agentName
                                    )
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(.green)

                            Button("Deny") {
                                selectedPromptId = prompt.requestId
                                denyReason = ""
                                showDenySheet = true
                            }
                            .buttonStyle(.bordered)
                            .tint(.red)
                        }
                    }
                    .padding(8)
                    .background(Color.orange.opacity(0.05))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
            .padding(8)
        }
    }

    // MARK: - Input Section

    private var inputSection: some View {
        GroupBox("Send Input") {
            HStack {
                TextField("Type a message to send to the agent...", text: $inputText)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { sendInput() }

                Button("Send") { sendInput() }
                    .buttonStyle(.borderedProminent)
                    .disabled(inputText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(8)
        }
    }

    // MARK: - Deny Sheet

    private var denySheet: some View {
        VStack(spacing: 16) {
            Text("Deny Request")
                .font(.headline)

            Text("Optionally provide a reason for denying this request.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            TextField("Reason (optional)", text: $denyReason)
                .textFieldStyle(.roundedBorder)

            HStack {
                Button("Cancel") {
                    showDenySheet = false
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Deny") {
                    guard let promptId = selectedPromptId else { return }
                    showDenySheet = false
                    performAction {
                        try await fleetState.deny(
                            requestId: promptId,
                            agentName: agent.name,
                            reason: denyReason.isEmpty ? nil : denyReason
                        )
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(width: 400)
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

    private func sendInput() {
        let text = inputText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        inputText = ""
        performAction {
            try await fleetState.sendInput(agentName: agent.name, text: text)
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
}
