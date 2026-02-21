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
            "num": .int(1)
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
        // nil reason should encode as null
        XCTAssertTrue(json?["reason"] is NSNull)
    }
}
