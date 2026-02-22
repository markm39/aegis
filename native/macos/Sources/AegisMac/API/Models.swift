import Foundation

// MARK: - API Response Envelope

/// Generic response envelope matching the daemon's `CommandResponse` / `DaemonResponse`.
struct APIResponse: Codable {
    let ok: Bool
    let message: String
    let data: AnyCodableValue?
}

// MARK: - Agent Models

/// Parsed agent status kind, matching Rust `AgentStatus` enum variants.
enum AgentStatusKind: String, Codable {
    case pending = "Pending"
    case running = "Running"
    case stopped = "Stopped"
    case crashed = "Crashed"
    case failed = "Failed"
    case stopping = "Stopping"
    case disabled = "Disabled"

    var displayName: String {
        switch self {
        case .pending: return "Pending"
        case .running: return "Running"
        case .stopped: return "Stopped"
        case .crashed: return "Crashed"
        case .failed: return "Failed"
        case .stopping: return "Stopping"
        case .disabled: return "Disabled"
        }
    }
}

/// Agent info matching the daemon's `AgentSummary` JSON shape.
struct AgentInfo: Codable, Identifiable {
    var id: String { name }

    let name: String
    let status: AnyCodableValue
    let tool: String
    let workingDir: String
    let role: String?
    let restartCount: UInt32
    let pendingCount: Int
    let attentionNeeded: Bool
    let isOrchestrator: Bool

    enum CodingKeys: String, CodingKey {
        case name, status, tool
        case workingDir = "working_dir"
        case role
        case restartCount = "restart_count"
        case pendingCount = "pending_count"
        case attentionNeeded = "attention_needed"
        case isOrchestrator = "is_orchestrator"
    }

    /// Parse the status enum variant from the JSON representation.
    ///
    /// The Rust `AgentStatus` serializes as either a bare string ("Pending")
    /// or a tagged object ({"Running": {"pid": 123}}).
    var statusKind: AgentStatusKind {
        // Try string value first (bare variants like "Pending", "Stopping", "Disabled")
        if case .string(let s) = status {
            return AgentStatusKind(rawValue: s) ?? .pending
        }
        // Try object with variant key ({"Running": {"pid": 123}})
        if case .object(let dict) = status {
            for key in dict.keys {
                if let kind = AgentStatusKind(rawValue: key) {
                    return kind
                }
            }
        }
        return .pending
    }
}

// MARK: - Pending Prompt

/// Pending permission prompt matching the daemon's `PendingPromptSummary`.
struct PendingPrompt: Codable, Identifiable {
    var id: String { requestId }

    let requestId: String
    let rawPrompt: String
    let ageSecs: UInt64
    /// Name of the agent this prompt belongs to. Set by the client after fetching.
    var agentName: String

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case rawPrompt = "raw_prompt"
        case ageSecs = "age_secs"
        case agentName = "agent_name"
    }

    init(requestId: String, rawPrompt: String, ageSecs: UInt64, agentName: String) {
        self.requestId = requestId
        self.rawPrompt = rawPrompt
        self.ageSecs = ageSecs
        self.agentName = agentName
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.requestId = try container.decode(String.self, forKey: .requestId)
        self.rawPrompt = try container.decode(String.self, forKey: .rawPrompt)
        self.ageSecs = try container.decode(UInt64.self, forKey: .ageSecs)
        self.agentName = try container.decodeIfPresent(String.self, forKey: .agentName) ?? ""
    }
}

// MARK: - Activity Event

/// Represents a recent activity event for the activity feed.
struct ActivityEvent: Identifiable {
    let id = UUID()
    let timestamp: Date
    let agentName: String
    let summary: String
    let kind: ActivityKind

    enum ActivityKind {
        case approval
        case denial
        case agentStart
        case agentStop
        case agentCrash
        case info
    }

    var iconName: String {
        switch kind {
        case .approval: return "checkmark.circle.fill"
        case .denial: return "xmark.circle.fill"
        case .agentStart: return "play.circle.fill"
        case .agentStop: return "stop.circle.fill"
        case .agentCrash: return "exclamationmark.triangle.fill"
        case .info: return "info.circle.fill"
        }
    }

    var relativeTime: String {
        let interval = Date().timeIntervalSince(timestamp)
        if interval < 60 {
            return "just now"
        } else if interval < 3600 {
            let mins = Int(interval / 60)
            return "\(mins)m ago"
        } else {
            let hours = Int(interval / 3600)
            return "\(hours)h ago"
        }
    }
}

// MARK: - Gateway WebSocket Messages

/// Request sent to the daemon's gateway WebSocket.
struct GatewayRequest: Codable {
    let method: String
    let id: String?
    let params: [String: AnyCodableValue]?

    init(method: String, id: String? = nil, params: [String: AnyCodableValue]? = nil) {
        self.method = method
        self.id = id
        self.params = params
    }
}

/// Response received from the daemon's gateway WebSocket.
struct GatewayResponse: Codable {
    let ok: Bool
    let id: String?
    let method: String?
    let data: AnyCodableValue?
    let error: String?
}

// MARK: - Chat Message

/// A message in a chat conversation with an agent.
struct ChatMessage: Identifiable {
    let id = UUID()
    let timestamp: Date
    let sender: ChatSender
    let content: String
    let isCode: Bool

    enum ChatSender {
        case user
        case agent
        case system
    }
}

// MARK: - Input Body

/// Request body for sending text to an agent.
struct InputBody: Codable {
    let text: String
}

/// Request body for denying a pending request.
struct DenyBody: Codable {
    let reason: String?
}

// MARK: - Connection State

/// State machine for daemon connection.
enum ConnectionState: Equatable {
    case disconnected
    case connecting
    case connected
    case reconnecting(attempt: Int)

    var displayName: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting..."
        case .connected: return "Connected"
        case .reconnecting(let attempt): return "Reconnecting (\(attempt))..."
        }
    }

    var isActive: Bool {
        switch self {
        case .connected: return true
        default: return false
        }
    }
}

// MARK: - Hotkey Configuration

/// A configurable global hotkey binding.
struct HotkeyBinding: Identifiable, Codable {
    var id: String { action }
    let action: String
    let displayName: String
    var keyCode: UInt16
    var modifiers: UInt

    static let defaultBindings: [HotkeyBinding] = [
        HotkeyBinding(action: "toggleDashboard", displayName: "Toggle Dashboard", keyCode: 0x00, modifiers: 0x180900),
        HotkeyBinding(action: "openChat", displayName: "Open Chat", keyCode: 0x08, modifiers: 0x180900),
        HotkeyBinding(action: "toggleVoice", displayName: "Toggle Voice", keyCode: 0x09, modifiers: 0x180900),
        HotkeyBinding(action: "showPending", displayName: "Show Pending", keyCode: 0x23, modifiers: 0x180900),
    ]
}

// MARK: - Settings

/// Persisted application settings.
struct AppSettings: Codable {
    var launchAtLogin: Bool = false
    var autoConnect: Bool = true
    var daemonURL: String = "http://localhost:3100"
    var socketPath: String = ""
    var useSocket: Bool = false
    var notificationSound: Bool = true
    var notificationBadge: Bool = true
    var trayIconStyle: TrayIconStyle = .shield

    enum TrayIconStyle: String, Codable, CaseIterable {
        case shield = "shield"
        case dot = "dot"
        case letter = "letter"

        var displayName: String {
            switch self {
            case .shield: return "Shield"
            case .dot: return "Dot"
            case .letter: return "A"
            }
        }
    }

    /// Load settings from UserDefaults.
    static func load() -> AppSettings {
        guard let data = UserDefaults.standard.data(forKey: "aegis.settings"),
              let settings = try? JSONDecoder().decode(AppSettings.self, from: data) else {
            return AppSettings()
        }
        return settings
    }

    /// Save settings to UserDefaults.
    func save() {
        if let data = try? JSONEncoder().encode(self) {
            UserDefaults.standard.set(data, forKey: "aegis.settings")
        }
    }
}

// MARK: - Flexible JSON Value

/// A type-erased JSON value for handling dynamic `data` fields and
/// serde-tagged enum variants from the Rust daemon.
enum AnyCodableValue: Codable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case object([String: AnyCodableValue])
    case array([AnyCodableValue])
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
            return
        }
        if let boolVal = try? container.decode(Bool.self) {
            self = .bool(boolVal)
        } else if let intVal = try? container.decode(Int.self) {
            self = .int(intVal)
        } else if let doubleVal = try? container.decode(Double.self) {
            self = .double(doubleVal)
        } else if let stringVal = try? container.decode(String.self) {
            self = .string(stringVal)
        } else if let arrayVal = try? container.decode([AnyCodableValue].self) {
            self = .array(arrayVal)
        } else if let objectVal = try? container.decode([String: AnyCodableValue].self) {
            self = .object(objectVal)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unable to decode AnyCodableValue"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let v): try container.encode(v)
        case .int(let v): try container.encode(v)
        case .double(let v): try container.encode(v)
        case .bool(let v): try container.encode(v)
        case .object(let v): try container.encode(v)
        case .array(let v): try container.encode(v)
        case .null: try container.encodeNil()
        }
    }
}
