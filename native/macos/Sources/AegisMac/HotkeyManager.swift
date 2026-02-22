import SwiftUI
import Carbon.HIToolbox

/// Manages global keyboard shortcuts for the Aegis app.
///
/// Uses NSEvent.addGlobalMonitorForEvents for global hotkey detection.
/// Default hotkeys:
/// - Cmd+Shift+A: Toggle dashboard
/// - Cmd+Shift+C: Open chat window
/// - Cmd+Shift+V: Toggle voice overlay
/// - Cmd+Shift+P: Show pending approvals
@MainActor
final class HotkeyManager: ObservableObject {
    /// Current hotkey bindings.
    @Published var bindings: [HotkeyBinding]

    /// Whether global hotkeys are enabled.
    @Published var isEnabled: Bool = true

    /// Global event monitor handle.
    private var globalMonitor: Any?

    /// Local event monitor handle (for when app is focused).
    private var localMonitor: Any?

    /// Callback for hotkey actions.
    var onAction: ((String) -> Void)?

    init() {
        // Load saved bindings or use defaults
        if let data = UserDefaults.standard.data(forKey: "aegis.hotkeys"),
           let saved = try? JSONDecoder().decode([HotkeyBinding].self, from: data) {
            self.bindings = saved
        } else {
            self.bindings = HotkeyBinding.defaultBindings
        }

        setupMonitors()
    }

    deinit {
        // Remove monitors inline since deinit is nonisolated
        if let monitor = globalMonitor {
            NSEvent.removeMonitor(monitor)
        }
        if let monitor = localMonitor {
            NSEvent.removeMonitor(monitor)
        }
    }

    // MARK: - Setup

    /// Install global and local event monitors.
    func setupMonitors() {
        removeMonitors()

        guard isEnabled else { return }

        // Global monitor (when app is not focused)
        globalMonitor = NSEvent.addGlobalMonitorForEvents(matching: .keyDown) { [weak self] event in
            Task { @MainActor in
                self?.handleKeyEvent(event)
            }
        }

        // Local monitor (when app is focused)
        localMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            Task { @MainActor in
                self?.handleKeyEvent(event)
            }
            return event
        }
    }

    /// Remove all event monitors.
    func removeMonitors() {
        if let monitor = globalMonitor {
            NSEvent.removeMonitor(monitor)
            globalMonitor = nil
        }
        if let monitor = localMonitor {
            NSEvent.removeMonitor(monitor)
            localMonitor = nil
        }
    }

    /// Handle a key event and check against registered bindings.
    private func handleKeyEvent(_ event: NSEvent) {
        let keyCode = event.keyCode
        let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)

        for binding in bindings {
            if keyCode == binding.keyCode && flags.rawValue == binding.modifiers {
                onAction?(binding.action)
                break
            }
        }
    }

    // MARK: - Configuration

    /// Update a binding for a specific action.
    func updateBinding(action: String, keyCode: UInt16, modifiers: UInt) {
        if let index = bindings.firstIndex(where: { $0.action == action }) {
            bindings[index].keyCode = keyCode
            bindings[index].modifiers = modifiers
            saveBindings()
        }
    }

    /// Reset all bindings to defaults.
    func resetToDefaults() {
        bindings = HotkeyBinding.defaultBindings
        saveBindings()
    }

    /// Toggle hotkeys on/off.
    func setEnabled(_ enabled: Bool) {
        isEnabled = enabled
        if enabled {
            setupMonitors()
        } else {
            removeMonitors()
        }
    }

    /// Save bindings to UserDefaults.
    private func saveBindings() {
        if let data = try? JSONEncoder().encode(bindings) {
            UserDefaults.standard.set(data, forKey: "aegis.hotkeys")
        }
    }

    // MARK: - Key Description Helpers

    /// Get a human-readable description of a key code.
    static func keyDescription(keyCode: UInt16) -> String {
        // Map common key codes to readable names
        let keyMap: [UInt16: String] = [
            0x00: "A", 0x01: "S", 0x02: "D", 0x03: "F",
            0x04: "H", 0x05: "G", 0x06: "Z", 0x07: "X",
            0x08: "C", 0x09: "V", 0x0B: "B", 0x0C: "Q",
            0x0D: "W", 0x0E: "E", 0x0F: "R", 0x10: "Y",
            0x11: "T", 0x12: "1", 0x13: "2", 0x14: "3",
            0x15: "4", 0x17: "5", 0x16: "6", 0x1A: "7",
            0x1C: "8", 0x19: "9", 0x1D: "0", 0x23: "P",
            0x25: "L", 0x26: "J", 0x28: "K", 0x2E: "M",
            0x2F: "N", 0x31: "Space",
        ]
        return keyMap[keyCode] ?? "Key(\(keyCode))"
    }

    /// Get a human-readable description of modifier flags.
    static func modifierDescription(modifiers: UInt) -> String {
        let flags = NSEvent.ModifierFlags(rawValue: modifiers)
        var parts: [String] = []
        if flags.contains(.command) { parts.append("Cmd") }
        if flags.contains(.shift) { parts.append("Shift") }
        if flags.contains(.option) { parts.append("Opt") }
        if flags.contains(.control) { parts.append("Ctrl") }
        return parts.joined(separator: "+")
    }

    /// Get a full shortcut description.
    static func shortcutDescription(keyCode: UInt16, modifiers: UInt) -> String {
        let mods = modifierDescription(modifiers: modifiers)
        let key = keyDescription(keyCode: keyCode)
        if mods.isEmpty {
            return key
        }
        return "\(mods)+\(key)"
    }
}
