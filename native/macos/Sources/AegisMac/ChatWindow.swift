import SwiftUI
import UniformTypeIdentifiers

/// Floating chat window for interacting with agents.
///
/// Features:
/// - Agent selector dropdown
/// - Message history with code block detection
/// - File drag-and-drop to share files with agent
/// - Split-pane: agent output on left, chat input on right
struct ChatWindow: View {
    @ObservedObject var fleetState: FleetState
    @State private var selectedAgentName: String?
    @State private var messageInput: String = ""
    @State private var messages: [ChatMessage] = []
    @State private var isDropTargeted: Bool = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            // Agent selector toolbar
            agentToolbar

            Divider()

            if selectedAgentName != nil {
                // Main chat area
                HSplitView {
                    // Left: agent output / message history
                    messageHistoryView
                        .frame(minWidth: 300)

                    // Right: chat input
                    chatInputPane
                        .frame(minWidth: 250)
                }
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "bubble.left.and.bubble.right")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("Select an Agent")
                        .font(.headline)
                    Text("Choose an agent from the dropdown to start chatting.")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $isDropTargeted) { providers in
            handleFileDrop(providers)
        }
        .overlay {
            if isDropTargeted {
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(Color.accentColor, lineWidth: 3)
                    .background(Color.accentColor.opacity(0.1))
                    .overlay {
                        VStack {
                            Image(systemName: "arrow.down.doc.fill")
                                .font(.largeTitle)
                            Text("Drop file to share with agent")
                                .font(.headline)
                        }
                        .foregroundStyle(.secondary)
                    }
            }
        }
    }

    // MARK: - Agent Toolbar

    private var agentToolbar: some View {
        HStack(spacing: 12) {
            Image(systemName: "bubble.left.and.bubble.right.fill")
                .foregroundStyle(.tint)

            Picker("Agent:", selection: $selectedAgentName) {
                Text("Select Agent...").tag(nil as String?)
                ForEach(fleetState.agents, id: \.name) { agent in
                    HStack {
                        Circle()
                            .fill(statusColor(for: agent.statusKind))
                            .frame(width: 8, height: 8)
                        Text(agent.name)
                    }
                    .tag(agent.name as String?)
                }
            }
            .frame(maxWidth: 200)

            Spacer()

            if let name = selectedAgentName,
               let agent = fleetState.agents.first(where: { $0.name == name }) {
                HStack(spacing: 4) {
                    Circle()
                        .fill(statusColor(for: agent.statusKind))
                        .frame(width: 8, height: 8)
                    Text(agent.statusKind.displayName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Button {
                messages.removeAll()
            } label: {
                Image(systemName: "trash")
            }
            .help("Clear chat history")
            .disabled(messages.isEmpty)
        }
        .padding(10)
    }

    // MARK: - Message History

    private var messageHistoryView: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach(messages) { message in
                        ChatBubbleView(message: message)
                            .id(message.id)
                    }
                }
                .padding()
            }
            .onChange(of: messages.count) { _ in
                if let last = messages.last {
                    withAnimation {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }

    // MARK: - Chat Input Pane

    private var chatInputPane: some View {
        VStack(spacing: 0) {
            // Input label
            HStack {
                Text("Message")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if let agentName = selectedAgentName {
                    Text("to \(agentName)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.top, 8)

            // Text editor
            TextEditor(text: $messageInput)
                .font(.system(.body, design: .monospaced))
                .scrollContentBackground(.hidden)
                .padding(8)

            // Error banner
            if let error = errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                    Spacer()
                    Button("Dismiss") { errorMessage = nil }
                        .buttonStyle(.plain)
                        .font(.caption)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 4)
            }

            Divider()

            // Send controls
            HStack {
                Text("Press Send to deliver message")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                Spacer()
                Button("Send") {
                    sendMessage()
                }
                .buttonStyle(.borderedProminent)
                .disabled(messageInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .keyboardShortcut(.return, modifiers: .command)
            }
            .padding(8)
        }
        .background(Color(nsColor: .controlBackgroundColor))
    }

    // MARK: - Actions

    private func sendMessage() {
        let text = messageInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, let agentName = selectedAgentName else { return }

        // Add user message to history
        messages.append(ChatMessage(
            timestamp: Date(),
            sender: .user,
            content: text,
            isCode: false
        ))

        messageInput = ""

        // Send to agent
        Task {
            do {
                try await fleetState.sendInput(agentName: agentName, text: text)
                errorMessage = nil
            } catch {
                errorMessage = error.localizedDescription
                messages.append(ChatMessage(
                    timestamp: Date(),
                    sender: .system,
                    content: "Failed to send: \(error.localizedDescription)",
                    isCode: false
                ))
            }
        }
    }

    private func handleFileDrop(_ providers: [NSItemProvider]) -> Bool {
        guard let agentName = selectedAgentName else { return false }

        for provider in providers {
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
                guard let data = item as? Data,
                      let url = URL(dataRepresentation: data, relativeTo: nil) else { return }

                let path = url.path
                Task { @MainActor in
                    // Add system message about the file
                    messages.append(ChatMessage(
                        timestamp: Date(),
                        sender: .system,
                        content: "Shared file: \(path)",
                        isCode: false
                    ))

                    // Send file path to agent
                    do {
                        try await fleetState.sendInput(
                            agentName: agentName,
                            text: "File shared: \(path)"
                        )
                    } catch {
                        errorMessage = error.localizedDescription
                    }
                }
            }
        }
        return true
    }

    private func statusColor(for status: AgentStatusKind) -> Color {
        switch status {
        case .running: return .green
        case .pending, .stopping: return .yellow
        case .stopped, .disabled: return .gray
        case .crashed, .failed: return .red
        }
    }
}

// MARK: - Chat Bubble View

struct ChatBubbleView: View {
    let message: ChatMessage

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            // Sender icon
            Image(systemName: senderIcon)
                .foregroundStyle(senderColor)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 4) {
                // Sender label and timestamp
                HStack {
                    Text(senderLabel)
                        .font(.caption)
                        .fontWeight(.medium)
                        .foregroundStyle(senderColor)
                    Text(timeString)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }

                // Message content
                if message.isCode {
                    Text(message.content)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.primary.opacity(0.05))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                } else {
                    // Detect code blocks in content
                    ForEach(Array(parseContent(message.content).enumerated()), id: \.offset) { _, block in
                        if block.isCode {
                            Text(block.text)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .padding(8)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color(nsColor: .textBackgroundColor))
                                .clipShape(RoundedRectangle(cornerRadius: 6))
                        } else {
                            Text(block.text)
                                .textSelection(.enabled)
                        }
                    }
                }
            }

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 4)
    }

    private var senderIcon: String {
        switch message.sender {
        case .user: return "person.fill"
        case .agent: return "cpu"
        case .system: return "info.circle"
        }
    }

    private var senderLabel: String {
        switch message.sender {
        case .user: return "You"
        case .agent: return "Agent"
        case .system: return "System"
        }
    }

    private var senderColor: Color {
        switch message.sender {
        case .user: return .blue
        case .agent: return .green
        case .system: return .secondary
        }
    }

    private var timeString: String {
        let formatter = DateFormatter()
        formatter.timeStyle = .short
        return formatter.string(from: message.timestamp)
    }

    /// Parse message content to detect code blocks (```...```) and inline code.
    private func parseContent(_ text: String) -> [ContentBlock] {
        var blocks: [ContentBlock] = []
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        var inCodeBlock = false
        var currentBlock = ""

        for line in lines {
            let lineStr = String(line)
            if lineStr.hasPrefix("```") {
                if inCodeBlock {
                    // End code block
                    blocks.append(ContentBlock(text: currentBlock, isCode: true))
                    currentBlock = ""
                    inCodeBlock = false
                } else {
                    // Start code block
                    if !currentBlock.isEmpty {
                        blocks.append(ContentBlock(text: currentBlock, isCode: false))
                        currentBlock = ""
                    }
                    inCodeBlock = true
                }
            } else {
                if !currentBlock.isEmpty {
                    currentBlock += "\n"
                }
                currentBlock += lineStr
            }
        }

        if !currentBlock.isEmpty {
            blocks.append(ContentBlock(text: currentBlock, isCode: inCodeBlock))
        }

        if blocks.isEmpty {
            blocks.append(ContentBlock(text: text, isCode: false))
        }

        return blocks
    }
}

/// A block of content that may be code or plain text.
struct ContentBlock {
    let text: String
    let isCode: Bool
}
