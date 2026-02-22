import XCTest
@testable import AegisIOS

final class ModelsTests: XCTestCase {

    // MARK: - Agent Info Decoding

    func test_agent_info_decoding() throws {
        let json = """
        {
            "name": "claude-1",
            "status": "Pending",
            "tool": "ClaudeCode",
            "working_dir": "/tmp/work",
            "role": "coder",
            "restart_count": 0,
            "pending_count": 2,
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
        XCTAssertEqual(agent.pendingCount, 2)
        XCTAssertFalse(agent.attentionNeeded)
        XCTAssertFalse(agent.isOrchestrator)
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

    func testDecodeAgentInfoNilRole() throws {
        let json = """
        {
            "name": "agent-4",
            "status": "Stopped",
            "tool": "Generic",
            "working_dir": "/tmp",
            "restart_count": 0,
            "pending_count": 0,
            "attention_needed": false,
            "is_orchestrator": false
        }
        """.data(using: .utf8)!

        let agent = try JSONDecoder().decode(AgentInfo.self, from: json)
        XCTAssertNil(agent.role)
        XCTAssertEqual(agent.statusKind, .stopped)
    }

    func testAgentInfoIdentifiable() throws {
        let json = """
        {
            "name": "test-agent",
            "status": "Running",
            "tool": "ClaudeCode",
            "working_dir": "/tmp",
            "restart_count": 0,
            "pending_count": 0,
            "attention_needed": false,
            "is_orchestrator": false
        }
        """.data(using: .utf8)!

        let agent = try JSONDecoder().decode(AgentInfo.self, from: json)
        XCTAssertEqual(agent.id, "test-agent", "Agent id should equal name")
    }

    // MARK: - Pending Request Decoding

    func test_pending_request_decoding() throws {
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

    func testPendingPromptIdentifiable() {
        let prompt = PendingPrompt(
            requestId: "test-id", rawPrompt: "test", ageSecs: 0, agentName: "test"
        )
        XCTAssertEqual(prompt.id, "test-id", "Prompt id should equal requestId")
    }

    // MARK: - Invalid JSON

    func test_invalid_json_returns_error() {
        let malformedJSON = """
        { "name": "broken-agent", "status": }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(AgentInfo.self, from: malformedJSON)) { error in
            XCTAssertTrue(error is DecodingError, "Should throw a DecodingError for malformed JSON")
        }
    }

    func testMissingRequiredFieldsReturnsError() {
        let incompleteJSON = """
        { "name": "partial-agent" }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(AgentInfo.self, from: incompleteJSON)) { error in
            XCTAssertTrue(error is DecodingError, "Should throw a DecodingError for missing fields")
        }
    }

    func testEmptyJSONReturnsError() {
        let emptyJSON = "{}".data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(AgentInfo.self, from: emptyJSON))
    }

    // MARK: - Risk Level

    func testHighRiskDetection() {
        let prompt = PendingPrompt(
            requestId: "1", rawPrompt: "rm -rf /important/data", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(prompt.riskLevel, .high)

        let passwordPrompt = PendingPrompt(
            requestId: "2", rawPrompt: "Read password from config", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(passwordPrompt.riskLevel, .high)

        let sshPrompt = PendingPrompt(
            requestId: "3", rawPrompt: "Access .ssh/id_rsa file", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(sshPrompt.riskLevel, .high)

        let sudoPrompt = PendingPrompt(
            requestId: "4", rawPrompt: "Execute sudo command", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(sudoPrompt.riskLevel, .high)
    }

    func testMediumRiskDetection() {
        let prompt = PendingPrompt(
            requestId: "1", rawPrompt: "Write file to /tmp/output.txt", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(prompt.riskLevel, .medium)

        let installPrompt = PendingPrompt(
            requestId: "2", rawPrompt: "npm install express", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(installPrompt.riskLevel, .medium)

        let curlPrompt = PendingPrompt(
            requestId: "3", rawPrompt: "curl https://example.com/api", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(curlPrompt.riskLevel, .medium)
    }

    func testLowRiskDetection() {
        let prompt = PendingPrompt(
            requestId: "1", rawPrompt: "Read file contents", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(prompt.riskLevel, .low)

        let listPrompt = PendingPrompt(
            requestId: "2", rawPrompt: "List directory entries", ageSecs: 5, agentName: "test"
        )
        XCTAssertEqual(listPrompt.riskLevel, .low)
    }

    // MARK: - Status Kind

    func testStatusKindDisplayNames() {
        XCTAssertEqual(AgentStatusKind.running.displayName, "Running")
        XCTAssertEqual(AgentStatusKind.pending.displayName, "Pending")
        XCTAssertEqual(AgentStatusKind.stopped.displayName, "Stopped")
        XCTAssertEqual(AgentStatusKind.crashed.displayName, "Crashed")
        XCTAssertEqual(AgentStatusKind.failed.displayName, "Failed")
        XCTAssertEqual(AgentStatusKind.stopping.displayName, "Stopping")
        XCTAssertEqual(AgentStatusKind.disabled.displayName, "Disabled")
    }

    func testStatusKindIconNames() {
        XCTAssertEqual(AgentStatusKind.running.iconName, "circle.fill")
        XCTAssertEqual(AgentStatusKind.pending.iconName, "circle.dotted")
        XCTAssertEqual(AgentStatusKind.stopped.iconName, "circle")
        XCTAssertEqual(AgentStatusKind.crashed.iconName, "exclamationmark.circle.fill")
        XCTAssertEqual(AgentStatusKind.failed.iconName, "exclamationmark.circle.fill")
        XCTAssertEqual(AgentStatusKind.stopping.iconName, "circle.dotted")
        XCTAssertEqual(AgentStatusKind.disabled.iconName, "circle")
    }

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
        if case .int(let i) = decoded {
            XCTAssertEqual(i, 42)
        } else {
            XCTFail("Expected int value")
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
        let value = AnyCodableValue.array([.string("a"), .int(1)])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        if case .array(let arr) = decoded {
            XCTAssertEqual(arr.count, 2)
        } else {
            XCTFail("Expected array value")
        }
    }

    func testAnyCodableObjectRoundtrip() throws {
        let value = AnyCodableValue.object(["key": .string("val")])
        let data = try JSONEncoder().encode(value)
        let decoded = try JSONDecoder().decode(AnyCodableValue.self, from: data)
        if case .object(let dict) = decoded {
            XCTAssertEqual(dict.count, 1)
            if case .string(let v) = dict["key"] {
                XCTAssertEqual(v, "val")
            } else {
                XCTFail("Expected string value for key")
            }
        } else {
            XCTFail("Expected object value")
        }
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
        XCTAssertTrue(json?["reason"] is NSNull)
    }

    // MARK: - FleetStatus Decoding

    func testFleetStatusDecoding() throws {
        let json = """
        {
            "agents": [],
            "total_pending": 5
        }
        """.data(using: .utf8)!

        let status = try JSONDecoder().decode(FleetStatus.self, from: json)
        XCTAssertEqual(status.totalPending, 5)
        XCTAssertTrue(status.agents.isEmpty)
    }

    func testFleetStatusWithAgents() throws {
        let json = """
        {
            "agents": [
                {
                    "name": "a1",
                    "status": "Running",
                    "tool": "ClaudeCode",
                    "working_dir": "/tmp",
                    "restart_count": 0,
                    "pending_count": 1,
                    "attention_needed": false,
                    "is_orchestrator": false
                }
            ],
            "total_pending": 1
        }
        """.data(using: .utf8)!

        let status = try JSONDecoder().decode(FleetStatus.self, from: json)
        XCTAssertEqual(status.agents.count, 1)
        XCTAssertEqual(status.agents[0].name, "a1")
    }

    // MARK: - Chat Message

    func testChatMessageCreation() {
        let msg = ChatMessage(role: .user, content: "hello", timestamp: Date())
        XCTAssertEqual(msg.content, "hello")
        XCTAssertFalse(msg.id.uuidString.isEmpty)
    }

    func testChatMessageRoles() {
        let userMsg = ChatMessage(role: .user, content: "user input", timestamp: Date())
        let agentMsg = ChatMessage(role: .agent, content: "agent output", timestamp: Date())

        switch userMsg.role {
        case .user: break // expected
        case .agent: XCTFail("Expected user role")
        }

        switch agentMsg.role {
        case .agent: break // expected
        case .user: XCTFail("Expected agent role")
        }
    }

    // MARK: - Input Sanitizer

    func testSanitizerStripsControlChars() {
        let input = "hello\u{0001}world\u{007F}test"
        let sanitized = InputSanitizer.sanitize(input)
        XCTAssertEqual(sanitized, "helloworldtest")
    }

    func testSanitizerTrimsWhitespace() {
        let input = "  hello world  "
        let sanitized = InputSanitizer.sanitize(input)
        XCTAssertEqual(sanitized, "hello world")
    }

    func testSanitizerEmptyInput() {
        XCTAssertEqual(InputSanitizer.sanitize(""), "")
        XCTAssertEqual(InputSanitizer.sanitize("   "), "")
        XCTAssertEqual(InputSanitizer.sanitize("\n\t"), "")
    }

    func testSanitizerPreservesNormalText() {
        let input = "cargo build --release"
        XCTAssertEqual(InputSanitizer.sanitize(input), input)
    }

    // MARK: - Activity Entry

    func testActivityEntryTimeAgo() {
        let recent = ActivityEntry(
            agentName: "test",
            description: "test event",
            timestamp: Date()
        )
        XCTAssertTrue(recent.timeAgo.contains("s ago"))
    }
}
