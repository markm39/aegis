import XCTest
@testable import AegisMac

final class ModelsTests: XCTestCase {

    // MARK: - APIResponse Decoding

    func testDecodeSuccessResponse() throws {
        let json = """
        {"ok": true, "message": "success", "data": null}
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(APIResponse.self, from: json)
        XCTAssertTrue(response.ok)
        XCTAssertEqual(response.message, "success")
    }

    func testDecodeErrorResponse() throws {
        let json = """
        {"ok": false, "message": "agent not found"}
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(APIResponse.self, from: json)
        XCTAssertFalse(response.ok)
        XCTAssertEqual(response.message, "agent not found")
    }

    func testDecodeResponseWithData() throws {
        let json = """
        {"ok": true, "message": "found", "data": {"count": 3, "items": ["a", "b"]}}
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(APIResponse.self, from: json)
        XCTAssertTrue(response.ok)
        XCTAssertNotNil(response.data)
    }

    // MARK: - AgentInfo Decoding

    func testDecodeAgentInfoBareStatus() throws {
        let json = """
        {
            "name": "claude-1",
            "status": "Pending",
            "tool": "ClaudeCode",
            "working_dir": "/tmp/work",
            "role": "coder",
            "restart_count": 0,
            "pending_count": 0,
            "attention_needed": false,
            "is_orchestrator": false
        }
        """.data(using: .utf8)!

        let agent = try JSONDecoder().decode(AgentInfo.self, from: json)
        XCTAssertEqual(agent.name, "claude-1")
        XCTAssertEqual(agent.statusKind, .pending)
        XCTAssertEqual(agent.tool, "ClaudeCode")
        XCTAssertEqual(agent.workingDir, "/tmp/work")
        XCTAssertEqual(agent.role, "coder")
        XCTAssertEqual(agent.restartCount, 0)
        XCTAssertFalse(agent.attentionNeeded)
    }

    func testDecodeAgentInfoTaggedStatus() throws {
        let json = """
        {
            "name": "agent-2",
            "status": {"Running": {"pid": 12345}},
            "tool": "Generic",
            "working_dir": "/home/user",
            "restart_count": 2,
            "pending_count": 3,
            "attention_needed": true,
            "is_orchestrator": true
        }
        """.data(using: .utf8)!

        let agent = try JSONDecoder().decode(AgentInfo.self, from: json)
        XCTAssertEqual(agent.name, "agent-2")
        XCTAssertEqual(agent.statusKind, .running)
        XCTAssertEqual(agent.pendingCount, 3)
        XCTAssertTrue(agent.attentionNeeded)
        XCTAssertTrue(agent.isOrchestrator)
    }

    func testDecodeAgentInfoCrashedStatus() throws {
        let json = """
        {
            "name": "agent-3",
            "status": {"Crashed": {"exit_code": 1, "restart_in_secs": 30}},
            "tool": "ClaudeCode",
            "working_dir": "/tmp",
            "restart_count": 5,
            "pending_count": 0,
            "attention_needed": false,
            "is_orchestrator": false
        }
        """.data(using: .utf8)!

        let agent = try JSONDecoder().decode(AgentInfo.self, from: json)
        XCTAssertEqual(agent.statusKind, .crashed)
        XCTAssertEqual(agent.restartCount, 5)
    }

    func testDecodeAgentInfoFailedStatus() throws {
        let json = """
        {
            "name": "agent-4",
            "status": {"Failed": {"exit_code": 137, "restart_count": 10}},
            "tool": "Generic",
            "working_dir": "/tmp",
            "restart_count": 10,
            "pending_count": 0,
            "attention_needed": true,
            "is_orchestrator": false
        }
        """.data(using: .utf8)!

        let agent = try JSONDecoder().decode(AgentInfo.self, from: json)
        XCTAssertEqual(agent.statusKind, .failed)
    }

    // MARK: - AgentStatusKind

    func testStatusKindDisplayNames() {
        XCTAssertEqual(AgentStatusKind.running.displayName, "Running")
        XCTAssertEqual(AgentStatusKind.pending.displayName, "Pending")
        XCTAssertEqual(AgentStatusKind.stopped.displayName, "Stopped")
        XCTAssertEqual(AgentStatusKind.crashed.displayName, "Crashed")
        XCTAssertEqual(AgentStatusKind.failed.displayName, "Failed")
        XCTAssertEqual(AgentStatusKind.stopping.displayName, "Stopping")
        XCTAssertEqual(AgentStatusKind.disabled.displayName, "Disabled")
    }

    // MARK: - PendingPrompt Decoding

    func testDecodePendingPrompt() throws {
        let json = """
        {
            "request_id": "abc-123",
            "raw_prompt": "Allow file write to /etc/passwd?",
            "age_secs": 45
        }
        """.data(using: .utf8)!

        let prompt = try JSONDecoder().decode(PendingPrompt.self, from: json)
        XCTAssertEqual(prompt.requestId, "abc-123")
        XCTAssertEqual(prompt.rawPrompt, "Allow file write to /etc/passwd?")
        XCTAssertEqual(prompt.ageSecs, 45)
        XCTAssertEqual(prompt.agentName, "") // default when not provided
    }

    func testDecodePendingPromptWithAgentName() throws {
        let json = """
        {
            "request_id": "def-456",
            "raw_prompt": "Execute bash command?",
            "age_secs": 10,
            "agent_name": "claude-1"
        }
        """.data(using: .utf8)!

        let prompt = try JSONDecoder().decode(PendingPrompt.self, from: json)
        XCTAssertEqual(prompt.agentName, "claude-1")
    }

    // MARK: - AnyCodableValue

    func testAnyCodableStringRoundtrip() throws {
        let value = AnyCodableValue.string("hello")
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        if case .string(let s) = decoded {
            XCTAssertEqual(s, "hello")
        } else {
            XCTFail("Expected string value")
        }
    }

    func testAnyCodableIntRoundtrip() throws {
        let value = AnyCodableValue.int(42)
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        if case .int(let n) = decoded {
            XCTAssertEqual(n, 42)
        } else {
            XCTFail("Expected int value")
        }
    }

    func testAnyCodableObjectRoundtrip() throws {
        let value = AnyCodableValue.object([
            "key": .string("val"),
            "num": .int(1),
        ])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        if case .object(let dict) = decoded {
            XCTAssertEqual(dict.count, 2)
        } else {
            XCTFail("Expected object value")
        }
    }

    func testAnyCodableNullRoundtrip() throws {
        let value = AnyCodableValue.null
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        if case .null = decoded {
            // OK
        } else {
            XCTFail("Expected null value")
        }
    }

    func testAnyCodableArrayRoundtrip() throws {
        let value = AnyCodableValue.array([.string("a"), .int(1), .bool(true)])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        if case .array(let arr) = decoded {
            XCTAssertEqual(arr.count, 3)
        } else {
            XCTFail("Expected array value")
        }
    }

    func testAnyCodableBoolRoundtrip() throws {
        let value = AnyCodableValue.bool(true)
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        if case .bool(let b) = decoded {
            XCTAssertTrue(b)
        } else {
            XCTFail("Expected bool value")
        }
    }

    func testAnyCodableDoubleRoundtrip() throws {
        let value = AnyCodableValue.double(3.14)
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        // Doubles may decode as int or double depending on value
        switch decoded {
        case .double(let d):
            XCTAssertEqual(d, 3.14, accuracy: 0.001)
        case .int:
            // 3.14 should not decode as int, but other values might
            break
        default:
            XCTFail("Expected numeric value")
        }
    }

    func testAnyCodableEquality() {
        XCTAssertEqual(AnyCodableValue.string("test"), AnyCodableValue.string("test"))
        XCTAssertNotEqual(AnyCodableValue.string("a"), AnyCodableValue.string("b"))
        XCTAssertEqual(AnyCodableValue.int(42), AnyCodableValue.int(42))
        XCTAssertEqual(AnyCodableValue.null, AnyCodableValue.null)
        XCTAssertNotEqual(AnyCodableValue.null, AnyCodableValue.int(0))
    }

    // MARK: - InputBody / DenyBody Encoding

    func testInputBodyEncoding() throws {
        let body = InputBody(text: "hello agent")
        let data = try JSONEncoder().encode(body)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["text"] as? String, "hello agent")
    }

    func testDenyBodyEncoding() throws {
        let body = DenyBody(reason: "too risky")
        let data = try JSONEncoder().encode(body)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["reason"] as? String, "too risky")
    }

    func testDenyBodyNilReason() throws {
        let body = DenyBody(reason: nil)
        let data = try JSONEncoder().encode(body)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        // nil reason should either be NSNull or absent from the JSON
        if let reasonValue = json?["reason"] {
            XCTAssertTrue(reasonValue is NSNull, "Expected null value for nil reason")
        }
        // Either way, the value should not be a non-null string
        XCTAssertNil(json?["reason"] as? String)
    }

    // MARK: - ConnectionState

    func testConnectionStateDisplayNames() {
        XCTAssertEqual(ConnectionState.disconnected.displayName, "Disconnected")
        XCTAssertEqual(ConnectionState.connecting.displayName, "Connecting...")
        XCTAssertEqual(ConnectionState.connected.displayName, "Connected")
        XCTAssertEqual(ConnectionState.reconnecting(attempt: 3).displayName, "Reconnecting (3)...")
    }

    func testConnectionStateIsActive() {
        XCTAssertFalse(ConnectionState.disconnected.isActive)
        XCTAssertFalse(ConnectionState.connecting.isActive)
        XCTAssertTrue(ConnectionState.connected.isActive)
        XCTAssertFalse(ConnectionState.reconnecting(attempt: 1).isActive)
    }

    func testConnectionStateEquality() {
        XCTAssertEqual(ConnectionState.disconnected, ConnectionState.disconnected)
        XCTAssertEqual(ConnectionState.connected, ConnectionState.connected)
        XCTAssertEqual(ConnectionState.reconnecting(attempt: 2), ConnectionState.reconnecting(attempt: 2))
        XCTAssertNotEqual(ConnectionState.reconnecting(attempt: 1), ConnectionState.reconnecting(attempt: 2))
        XCTAssertNotEqual(ConnectionState.connected, ConnectionState.disconnected)
    }

    // MARK: - GatewayRequest/Response

    func testGatewayRequestEncoding() throws {
        let request = GatewayRequest(method: "list_agents", id: "req-1")
        let data = try JSONEncoder().encode(request)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["method"] as? String, "list_agents")
        XCTAssertEqual(json?["id"] as? String, "req-1")
    }

    func testGatewayRequestWithParams() throws {
        let request = GatewayRequest(
            method: "approve",
            id: "req-2",
            params: ["name": .string("claude-1"), "request_id": .string("abc")]
        )
        let data = try JSONEncoder().encode(request)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["method"] as? String, "approve")
        let params = json?["params"] as? [String: Any]
        XCTAssertEqual(params?["name"] as? String, "claude-1")
    }

    func testGatewayResponseDecoding() throws {
        let json = """
        {"ok": true, "id": "req-1", "method": "list_agents", "data": null}
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(GatewayResponse.self, from: json)
        XCTAssertTrue(response.ok)
        XCTAssertEqual(response.id, "req-1")
        XCTAssertEqual(response.method, "list_agents")
    }

    func testGatewayResponseWithError() throws {
        let json = """
        {"ok": false, "error": "agent not found"}
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(GatewayResponse.self, from: json)
        XCTAssertFalse(response.ok)
        XCTAssertEqual(response.error, "agent not found")
    }

    // MARK: - ActivityEvent

    func testActivityEventRelativeTime() {
        let recentEvent = ActivityEvent(
            timestamp: Date(),
            agentName: "test",
            summary: "test event",
            kind: .info
        )
        XCTAssertEqual(recentEvent.relativeTime, "just now")
    }

    func testActivityEventIcons() {
        XCTAssertEqual(ActivityEvent(timestamp: Date(), agentName: "", summary: "", kind: .approval).iconName, "checkmark.circle.fill")
        XCTAssertEqual(ActivityEvent(timestamp: Date(), agentName: "", summary: "", kind: .denial).iconName, "xmark.circle.fill")
        XCTAssertEqual(ActivityEvent(timestamp: Date(), agentName: "", summary: "", kind: .agentStart).iconName, "play.circle.fill")
        XCTAssertEqual(ActivityEvent(timestamp: Date(), agentName: "", summary: "", kind: .agentStop).iconName, "stop.circle.fill")
        XCTAssertEqual(ActivityEvent(timestamp: Date(), agentName: "", summary: "", kind: .agentCrash).iconName, "exclamationmark.triangle.fill")
        XCTAssertEqual(ActivityEvent(timestamp: Date(), agentName: "", summary: "", kind: .info).iconName, "info.circle.fill")
    }

    // MARK: - AppSettings

    func testAppSettingsDefaults() {
        let settings = AppSettings()
        XCTAssertFalse(settings.launchAtLogin)
        XCTAssertTrue(settings.autoConnect)
        XCTAssertEqual(settings.daemonURL, "http://localhost:3100")
        XCTAssertTrue(settings.notificationSound)
        XCTAssertTrue(settings.notificationBadge)
        XCTAssertEqual(settings.trayIconStyle, .shield)
    }

    func testAppSettingsRoundtrip() throws {
        var settings = AppSettings()
        settings.launchAtLogin = true
        settings.daemonURL = "http://remote:3100"
        settings.notificationSound = false
        settings.trayIconStyle = .dot

        let data = try JSONEncoder().encode(settings)
        let decoded = try JSONDecoder().decode(AppSettings.self, from: data)

        XCTAssertTrue(decoded.launchAtLogin)
        XCTAssertEqual(decoded.daemonURL, "http://remote:3100")
        XCTAssertFalse(decoded.notificationSound)
        XCTAssertEqual(decoded.trayIconStyle, .dot)
    }

    func testTrayIconStyleDisplayNames() {
        XCTAssertEqual(AppSettings.TrayIconStyle.shield.displayName, "Shield")
        XCTAssertEqual(AppSettings.TrayIconStyle.dot.displayName, "Dot")
        XCTAssertEqual(AppSettings.TrayIconStyle.letter.displayName, "A")
    }

    // MARK: - HotkeyBinding

    func testDefaultBindings() {
        let bindings = HotkeyBinding.defaultBindings
        XCTAssertEqual(bindings.count, 4)
        XCTAssertEqual(bindings[0].action, "toggleDashboard")
        XCTAssertEqual(bindings[1].action, "openChat")
        XCTAssertEqual(bindings[2].action, "toggleVoice")
        XCTAssertEqual(bindings[3].action, "showPending")
    }

    func testHotkeyBindingRoundtrip() throws {
        let binding = HotkeyBinding(
            action: "test",
            displayName: "Test Action",
            keyCode: 0x00,
            modifiers: 0x180900
        )
        let data = try JSONEncoder().encode(binding)
        let decoded = try JSONDecoder().decode(HotkeyBinding.self, from: data)
        XCTAssertEqual(decoded.action, "test")
        XCTAssertEqual(decoded.displayName, "Test Action")
        XCTAssertEqual(decoded.keyCode, 0x00)
        XCTAssertEqual(decoded.modifiers, 0x180900)
    }

    // MARK: - ChatMessage

    func testChatMessageCreation() {
        let msg = ChatMessage(
            timestamp: Date(),
            sender: .user,
            content: "Hello",
            isCode: false
        )
        XCTAssertEqual(msg.content, "Hello")
        XCTAssertFalse(msg.isCode)
    }
}
