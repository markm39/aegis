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

// MARK: - Input Body

/// Request body for sending text to an agent.
struct InputBody: Codable {
    let text: String
}

/// Request body for denying a pending request.
struct DenyBody: Codable {
    let reason: String?
}

// MARK: - Flexible JSON Value

/// A type-erased JSON value for handling dynamic `data` fields and
/// serde-tagged enum variants from the Rust daemon.
enum AnyCodableValue: Codable {
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
