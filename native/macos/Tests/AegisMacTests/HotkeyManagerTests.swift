import XCTest
@testable import AegisMac

@MainActor
final class HotkeyManagerTests: XCTestCase {

    // MARK: - Key Description

    func testKeyDescriptionForKnownKeys() {
        XCTAssertEqual(HotkeyManager.keyDescription(keyCode: 0x00), "A")
        XCTAssertEqual(HotkeyManager.keyDescription(keyCode: 0x08), "C")
        XCTAssertEqual(HotkeyManager.keyDescription(keyCode: 0x09), "V")
        XCTAssertEqual(HotkeyManager.keyDescription(keyCode: 0x23), "P")
        XCTAssertEqual(HotkeyManager.keyDescription(keyCode: 0x01), "S")
        XCTAssertEqual(HotkeyManager.keyDescription(keyCode: 0x0C), "Q")
    }

    func testKeyDescriptionForUnknownKey() {
        let desc = HotkeyManager.keyDescription(keyCode: 0xFF)
        XCTAssertTrue(desc.contains("Key("))
    }

    // MARK: - Modifier Description

    func testModifierDescriptionEmpty() {
        let desc = HotkeyManager.modifierDescription(modifiers: 0)
        XCTAssertEqual(desc, "")
    }

    // MARK: - Shortcut Description

    func testShortcutDescriptionCombined() {
        // Test that shortcut description combines modifiers and key
        let desc = HotkeyManager.shortcutDescription(keyCode: 0x00, modifiers: 0)
        XCTAssertEqual(desc, "A")
    }

    // MARK: - Default Bindings

    func testDefaultBindingsHaveFourEntries() {
        let bindings = HotkeyBinding.defaultBindings
        XCTAssertEqual(bindings.count, 4)
    }

    func testDefaultBindingActions() {
        let actions = HotkeyBinding.defaultBindings.map(\.action)
        XCTAssertTrue(actions.contains("toggleDashboard"))
        XCTAssertTrue(actions.contains("openChat"))
        XCTAssertTrue(actions.contains("toggleVoice"))
        XCTAssertTrue(actions.contains("showPending"))
    }

    func testDefaultBindingDisplayNames() {
        let names = HotkeyBinding.defaultBindings.map(\.displayName)
        XCTAssertTrue(names.contains("Toggle Dashboard"))
        XCTAssertTrue(names.contains("Open Chat"))
        XCTAssertTrue(names.contains("Toggle Voice"))
        XCTAssertTrue(names.contains("Show Pending"))
    }

    // MARK: - Binding Identifiable

    func testBindingIdIsAction() {
        let binding = HotkeyBinding(
            action: "test",
            displayName: "Test",
            keyCode: 0x00,
            modifiers: 0
        )
        XCTAssertEqual(binding.id, "test")
    }

    // MARK: - Binding Codable

    func testBindingCodableRoundtrip() throws {
        let binding = HotkeyBinding(
            action: "custom",
            displayName: "Custom Action",
            keyCode: 0x12,
            modifiers: 0x100108
        )

        let data = try JSONEncoder().encode(binding)
        let decoded = try JSONDecoder().decode(HotkeyBinding.self, from: data)

        XCTAssertEqual(decoded.action, binding.action)
        XCTAssertEqual(decoded.displayName, binding.displayName)
        XCTAssertEqual(decoded.keyCode, binding.keyCode)
        XCTAssertEqual(decoded.modifiers, binding.modifiers)
    }

    func testMultipleBindingsCodableRoundtrip() throws {
        let bindings = HotkeyBinding.defaultBindings
        let data = try JSONEncoder().encode(bindings)
        let decoded = try JSONDecoder().decode([HotkeyBinding].self, from: data)
        XCTAssertEqual(decoded.count, bindings.count)
        for (original, restored) in zip(bindings, decoded) {
            XCTAssertEqual(original.action, restored.action)
            XCTAssertEqual(original.keyCode, restored.keyCode)
        }
    }
}
