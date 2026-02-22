import SwiftUI

/// Settings window using the macOS Settings scene.
///
/// Tabs: General, Hotkeys, Notifications, Connection, Appearance
struct SettingsWindow: View {
    @ObservedObject var fleetState: FleetState
    @ObservedObject var hotkeyManager: HotkeyManager
    @ObservedObject var notificationManager: NotificationManager

    @State private var settings = AppSettings.load()

    var body: some View {
        TabView {
            generalTab
                .tabItem {
                    Label("General", systemImage: "gear")
                }

            hotkeysTab
                .tabItem {
                    Label("Hotkeys", systemImage: "keyboard")
                }

            notificationsTab
                .tabItem {
                    Label("Notifications", systemImage: "bell")
                }

            connectionTab
                .tabItem {
                    Label("Connection", systemImage: "network")
                }

            appearanceTab
                .tabItem {
                    Label("Appearance", systemImage: "paintbrush")
                }
        }
        .frame(width: 500, height: 400)
    }

    // MARK: - General Tab

    private var generalTab: some View {
        Form {
            Section("Startup") {
                Toggle("Launch at Login", isOn: $settings.launchAtLogin)
                    .onChange(of: settings.launchAtLogin) { newValue in
                        AutoLaunchHelper.setEnabled(newValue)
                        settings.save()
                    }

                Toggle("Auto-connect to Daemon", isOn: $settings.autoConnect)
                    .onChange(of: settings.autoConnect) { _ in
                        settings.save()
                    }
            }

            Section("Data") {
                Button("Clear Activity History") {
                    fleetState.recentActivity.removeAll()
                }

                Button("Reset All Settings") {
                    settings = AppSettings()
                    settings.save()
                    hotkeyManager.resetToDefaults()
                }
                .foregroundStyle(.red)
            }

            Section("About") {
                HStack {
                    Text("Version")
                    Spacer()
                    Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding()
    }

    // MARK: - Hotkeys Tab

    private var hotkeysTab: some View {
        Form {
            Section("Global Shortcuts") {
                Toggle("Enable Global Hotkeys", isOn: $hotkeyManager.isEnabled)
                    .onChange(of: hotkeyManager.isEnabled) { newValue in
                        hotkeyManager.setEnabled(newValue)
                    }
            }

            Section("Keyboard Shortcuts") {
                ForEach(hotkeyManager.bindings) { binding in
                    HStack {
                        Text(binding.displayName)
                        Spacer()
                        Text(HotkeyManager.shortcutDescription(
                            keyCode: binding.keyCode,
                            modifiers: binding.modifiers
                        ))
                        .font(.system(.body, design: .monospaced))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.primary.opacity(0.06))
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                }
            }

            Section {
                Button("Reset to Defaults") {
                    hotkeyManager.resetToDefaults()
                }
            }
        }
        .padding()
    }

    // MARK: - Notifications Tab

    private var notificationsTab: some View {
        Form {
            Section("Status") {
                HStack {
                    Text("Notifications")
                    Spacer()
                    if notificationManager.isAuthorized {
                        Label("Authorized", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label("Not Authorized", systemImage: "xmark.circle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }

            Section("Preferences") {
                Toggle("Notification Sound", isOn: $settings.notificationSound)
                    .onChange(of: settings.notificationSound) { _ in
                        settings.save()
                    }

                Toggle("Badge on App Icon", isOn: $settings.notificationBadge)
                    .onChange(of: settings.notificationBadge) { _ in
                        settings.save()
                    }
            }

            Section("Notification Types") {
                Text("Pending Approvals: Notifications with Approve/Deny buttons")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Agent Crashes: Critical notifications with Restart button")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                Button("Open System Notification Settings") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.notifications") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
        }
        .padding()
    }

    // MARK: - Connection Tab

    private var connectionTab: some View {
        Form {
            Section("Daemon Connection") {
                TextField("Daemon URL:", text: $settings.daemonURL)
                    .textFieldStyle(.roundedBorder)
                    .onChange(of: settings.daemonURL) { newValue in
                        settings.save()
                        if let url = URL(string: newValue) {
                            fleetState.client.setBaseURL(url)
                        }
                    }

                Toggle("Use Unix Socket", isOn: $settings.useSocket)
                    .onChange(of: settings.useSocket) { _ in
                        settings.save()
                    }

                if settings.useSocket {
                    TextField("Socket Path:", text: $settings.socketPath)
                        .textFieldStyle(.roundedBorder)
                        .onChange(of: settings.socketPath) { _ in
                            settings.save()
                        }
                }
            }

            Section("Authentication") {
                let tokenManager = TokenManager()
                HStack {
                    Text("API Token")
                    Spacer()
                    if tokenManager.hasToken() {
                        Label("Configured", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    } else {
                        Label("Not Set", systemImage: "xmark.circle.fill")
                            .foregroundStyle(.orange)
                    }
                }

                HStack {
                    Button("Set Token...") {
                        promptForToken()
                    }
                    Button("Clear Token") {
                        tokenManager.clearToken()
                    }
                    .foregroundStyle(.red)
                }
            }

            Section("Status") {
                HStack {
                    Text("Connection")
                    Spacer()
                    HStack(spacing: 4) {
                        Circle()
                            .fill(fleetState.isConnected ? Color.green : Color.red)
                            .frame(width: 8, height: 8)
                        Text(fleetState.connectionState.displayName)
                            .foregroundStyle(.secondary)
                    }
                }

                Button("Test Connection") {
                    Task { await fleetState.refresh() }
                }

                Button("Auto-Discover Daemon") {
                    Task {
                        if let url = await DaemonClient.discoverDaemon() {
                            settings.daemonURL = url.absoluteString
                            settings.save()
                            fleetState.client.setBaseURL(url)
                            await fleetState.refresh()
                        }
                    }
                }
            }
        }
        .padding()
    }

    // MARK: - Appearance Tab

    private var appearanceTab: some View {
        Form {
            Section("Menu Bar Icon") {
                Picker("Icon Style:", selection: $settings.trayIconStyle) {
                    ForEach(AppSettings.TrayIconStyle.allCases, id: \.self) { style in
                        Text(style.displayName).tag(style)
                    }
                }
                .onChange(of: settings.trayIconStyle) { _ in
                    settings.save()
                }
            }

            Section("Theme") {
                Text("Aegis follows the system appearance setting.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Button("Open System Appearance Settings") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.preference.general") {
                        NSWorkspace.shared.open(url)
                    }
                }
            }
        }
        .padding()
    }

    // MARK: - Helpers

    private func promptForToken() {
        let alert = NSAlert()
        alert.messageText = "Set API Token"
        alert.informativeText = "Enter the daemon API token. This will be stored securely in your Keychain."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")

        let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        input.placeholderString = "API Token"
        alert.accessoryView = input

        if alert.runModal() == .alertFirstButtonReturn {
            let token = input.stringValue
            if !token.isEmpty {
                let manager = TokenManager()
                manager.setToken(token)
            }
        }
    }
}
