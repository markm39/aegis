import SwiftUI

/// Full chat interface for bidirectional communication with agents.
///
/// Features:
/// - Message bubbles: user messages right-aligned (blue), agent responses left-aligned (gray)
/// - Real-time output polling for agent responses
/// - Input field with send button and keyboard submit
/// - Scrollable message history with auto-scroll to latest
/// - Loading indicator while agent is processing
/// - Agent selector when multiple agents are available
/// - Basic markdown rendering in agent responses (bold, code, links)
///
/// Messages are ephemeral -- they exist only for the current session.
/// The chat view polls for agent output and interleaves it with user messages.
struct ChatView: View {
    @EnvironmentObject var appState: AppState

    @State private var selectedAgent: String?
    @State private var inputText: String = ""
    @State private var messages: [ChatMessage] = []
    @State private var errorMessage: String?
    @State private var isWaitingForResponse: Bool = false
    @State private var outputPollTask: Task<Void, Never>?
    @State private var lastOutputCount: Int = 0

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
                    agentPicker

                    // Message list
                    messageList

                    // Typing indicator
                    if isWaitingForResponse {
                        typingIndicator
                    }

                    Divider()

                    // Input bar
                    inputBar
                }

                // Error banner
                if let error = errorMessage {
                    errorBanner(error)
                }
            }
            .navigationTitle("Chat")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if !messages.isEmpty {
                        Button("Clear") {
                            messages.removeAll()
                            lastOutputCount = 0
                        }
                        .font(.caption)
                    }
                }
            }
            .onChange(of: selectedAgent) { newAgent in
                // Reset chat when switching agents
                messages.removeAll()
                lastOutputCount = 0
                startOutputPolling()
            }
            .onDisappear {
                outputPollTask?.cancel()
            }
        }
    }

    // MARK: - Agent Picker

    private var agentPicker: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(appState.agents, id: \.name) { agent in
                    Button {
                        selectedAgent = agent.name
                    } label: {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(agent.statusKind == .running ? Color.green : Color.gray)
                                .frame(width: 8, height: 8)
                            Text(agent.name)
                                .font(.subheadline)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(
                            selectedAgent == agent.name
                                ? Color.blue.opacity(0.15)
                                : Color(.systemGroupedBackground)
                        )
                        .clipShape(Capsule())
                        .overlay(
                            Capsule()
                                .stroke(
                                    selectedAgent == agent.name ? Color.blue : Color.clear,
                                    lineWidth: 1.5
                                )
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
    }

    // MARK: - Message List

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 12) {
                    if messages.isEmpty && selectedAgent != nil {
                        VStack(spacing: 8) {
                            Image(systemName: "text.bubble")
                                .font(.system(size: 32))
                                .foregroundStyle(.secondary)
                            Text("Send a message to \(selectedAgent ?? "agent")")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.top, 60)
                    }

                    ForEach(messages) { message in
                        MessageBubble(message: message)
                            .id(message.id)
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
            }
            .onChange(of: messages.count) { _ in
                if let lastMessage = messages.last {
                    withAnimation(.easeOut(duration: 0.2)) {
                        proxy.scrollTo(lastMessage.id, anchor: .bottom)
                    }
                }
            }
        }
        .frame(maxHeight: .infinity)
    }

    // MARK: - Typing Indicator

    private var typingIndicator: some View {
        HStack(spacing: 4) {
            ProgressView()
                .controlSize(.small)
            Text("\(selectedAgent ?? "Agent") is processing...")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal)
        .padding(.vertical, 4)
    }

    // MARK: - Input Bar

    private var inputBar: some View {
        HStack(spacing: 8) {
            TextField("Message...", text: $inputText, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
                .onSubmit { sendMessage() }

            Button {
                sendMessage()
            } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
                    .foregroundStyle(canSend ? .blue : .gray)
            }
            .disabled(!canSend)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    // MARK: - Error Banner

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

    // MARK: - Logic

    private var canSend: Bool {
        !sanitizedInput.isEmpty && selectedAgent != nil
    }

    private var sanitizedInput: String {
        InputSanitizer.sanitize(inputText)
    }

    private func sendMessage() {
        let text = sanitizedInput
        guard !text.isEmpty, let agent = selectedAgent else { return }
        inputText = ""

        // Add user message
        let userMessage = ChatMessage(
            role: .user,
            content: text,
            timestamp: Date()
        )
        messages.append(userMessage)
        isWaitingForResponse = true

        Task {
            do {
                try await appState.sendInput(agentName: agent, text: text)
                errorMessage = nil
            } catch {
                errorMessage = error.localizedDescription
                isWaitingForResponse = false
            }
        }
    }

    private func startOutputPolling() {
        outputPollTask?.cancel()
        guard let agent = selectedAgent else { return }

        outputPollTask = Task {
            while !Task.isCancelled {
                do {
                    let lines = try await appState.fetchAgentOutput(agentId: agent)
                    await MainActor.run {
                        // Only process new lines
                        if lines.count > lastOutputCount {
                            let newLines = Array(lines[lastOutputCount...])
                            let combined = newLines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
                            if !combined.isEmpty {
                                let agentMessage = ChatMessage(
                                    role: .agent,
                                    content: combined,
                                    timestamp: Date()
                                )
                                messages.append(agentMessage)
                                isWaitingForResponse = false
                            }
                            lastOutputCount = lines.count
                        }
                    }
                } catch {
                    // Silently continue -- output fetch is best-effort
                }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }
}

// MARK: - Chat Message Model

/// A single message in the chat conversation.
struct ChatMessage: Identifiable {
    let id = UUID()
    let role: MessageRole
    let content: String
    let timestamp: Date

    enum MessageRole {
        case user
        case agent
    }
}

// MARK: - Message Bubble View

/// Renders a single chat message as a bubble with role-appropriate styling.
///
/// - User messages: right-aligned, blue background, white text
/// - Agent messages: left-aligned, gray background, primary text, monospaced for code
struct MessageBubble: View {
    let message: ChatMessage

    var body: some View {
        HStack {
            if message.role == .user {
                Spacer(minLength: 60)
            }

            VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 4) {
                // Message content
                if message.role == .agent {
                    renderAgentContent(message.content)
                } else {
                    Text(message.content)
                        .foregroundStyle(.white)
                }

                // Timestamp
                Text(formattedTime(message.timestamp))
                    .font(.caption2)
                    .foregroundStyle(
                        message.role == .user ? .white.opacity(0.7) : .secondary
                    )
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(bubbleBackground)
            .clipShape(RoundedRectangle(cornerRadius: 16))

            if message.role == .agent {
                Spacer(minLength: 60)
            }
        }
    }

    private var bubbleBackground: Color {
        switch message.role {
        case .user:
            return .blue
        case .agent:
            return Color(.systemGray5)
        }
    }

    /// Render agent content with basic formatting.
    ///
    /// Handles:
    /// - Code blocks (backtick-wrapped text rendered in monospaced font)
    /// - Bold text (**text**)
    /// - Plain text
    @ViewBuilder
    private func renderAgentContent(_ content: String) -> some View {
        let lines = content.split(separator: "\n", omittingEmptySubsequences: false)

        VStack(alignment: .leading, spacing: 4) {
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                let lineStr = String(line)
                if lineStr.hasPrefix("```") || lineStr.hasPrefix("    ") {
                    // Code line
                    Text(lineStr.replacingOccurrences(of: "```", with: ""))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.primary)
                        .padding(4)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(.systemGray6))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                } else if lineStr.contains("**") {
                    // Bold segments
                    formattedText(lineStr)
                } else {
                    Text(lineStr)
                        .font(.subheadline)
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)
                }
            }
        }
    }

    /// Parse inline **bold** markers and render as attributed text.
    private func formattedText(_ text: String) -> some View {
        var result = Text("")
        let parts = text.components(separatedBy: "**")
        for (index, part) in parts.enumerated() {
            if index % 2 == 1 {
                result = result + Text(part).bold()
            } else {
                result = result + Text(part)
            }
        }
        return result
            .font(.subheadline)
            .foregroundStyle(.primary)
    }

    private func formattedTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "h:mm a"
        return formatter.string(from: date)
    }
}
