import SwiftUI

/// Settings view for configuring the daemon connection, authentication, and app preferences.
///
/// Security:
/// - Server URL is validated (HTTPS required, except localhost)
/// - API token is stored exclusively in the iOS Keychain
/// - Biometric authentication can be enabled to protect app access
/// - Connection test verifies the daemon is reachable
struct SettingsView: View {
    @EnvironmentObject var appState: AppState

    // Server configuration
    @AppStorage("server_url") private var serverURL: String = "http://localhost:3100"
    @State private var urlInput: String = ""
    @State private var urlValidationError: String?

    // Token (displayed as masked, stored in Keychain)
    @State private var tokenInput: String = ""
    @State private var hasToken: Bool = false

    // Connection test
    @State private var isTestingConnection: Bool = false
    @State private var connectionTestResult: ConnectionTestResult?

    // Preferences
    @AppStorage("biometric_enabled") private var biometricEnabled: Bool = false
    @AppStorage("notifications_enabled") private var notificationsEnabled: Bool = true

    // Biometric availability
    @State private var biometricAvailable: Bool = false
    @State private var biometricType: String = "Biometric"

    private let tokenManager = TokenManager()

    var body: some View {
        NavigationStack {
            Form {
                serverSection
                authSection
                connectionSection
                securitySection
                notificationSection
                aboutSection
            }
            .navigationTitle("Settings")
            .onAppear {
                urlInput = serverURL
                hasToken = tokenManager.hasToken()
                checkBiometricAvailability()
            }
        }
    }

    // MARK: - Server Section

    private var serverSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                TextField("Server URL", text: $urlInput)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.URL)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .onChange(of: urlInput) { newValue in
                        validateURL(newValue)
                    }

                if let error = urlValidationError {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }

                Button("Save URL") {
                    saveServerURL()
                }
                .disabled(urlValidationError != nil || urlInput.isEmpty)
                .buttonStyle(.bordered)
            }
        } header: {
            Label("Server", systemImage: "server.rack")
        } footer: {
            Text("HTTPS is required for remote servers. HTTP is only allowed for localhost.")
        }
    }

    // MARK: - Auth Section

    private var authSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    SecureField("API Token", text: $tokenInput)
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)

                    if hasToken {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                }

                HStack(spacing: 12) {
                    Button("Save Token") {
                        saveToken()
                    }
                    .disabled(tokenInput.isEmpty)
                    .buttonStyle(.bordered)

                    if hasToken {
                        Button("Remove Token") {
                            removeToken()
                        }
                        .buttonStyle(.bordered)
                        .tint(.red)
                    }
                }
            }
        } header: {
            Label("Authentication", systemImage: "key")
        } footer: {
            Text("The API token is stored securely in the iOS Keychain. It is never written to disk or shared.")
        }
    }

    // MARK: - Connection Section

    private var connectionSection: some View {
        Section {
            HStack {
                Circle()
                    .fill(appState.isConnected ? Color.green : Color.red)
                    .frame(width: 10, height: 10)
                Text(appState.isConnected ? "Connected" : "Disconnected")
                    .font(.body)

                Spacer()

                if isTestingConnection {
                    ProgressView()
                        .controlSize(.small)
                }
            }

            if let result = connectionTestResult {
                HStack {
                    Image(systemName: result.success ? "checkmark.circle" : "xmark.circle")
                        .foregroundStyle(result.success ? .green : .red)
                    Text(result.message)
                        .font(.caption)
                        .foregroundStyle(result.success ? .green : .red)
                }
            }

            Button("Test Connection") {
                testConnection()
            }
            .disabled(isTestingConnection)
        } header: {
            Label("Connection", systemImage: "network")
        }
    }

    // MARK: - Security Section

    private var securitySection: some View {
        Section {
            Toggle(isOn: $biometricEnabled) {
                HStack {
                    Image(systemName: biometricType == "Face ID" ? "faceid" : "touchid")
                    Text("Require \(biometricType)")
                }
            }
            .disabled(!biometricAvailable)

            if !biometricAvailable {
                Text("\(biometricType) is not available on this device")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Label("Security", systemImage: "lock.shield")
        } footer: {
            Text("When enabled, \(biometricType) is required each time you open Aegis.")
        }
    }

    // MARK: - Notification Section

    private var notificationSection: some View {
        Section {
            Toggle("Approval Notifications", isOn: $notificationsEnabled)
        } header: {
            Label("Notifications", systemImage: "bell")
        } footer: {
            Text("Receive notifications when agents request approval for actions.")
        }
    }

    // MARK: - About Section

    private var aboutSection: some View {
        Section {
            HStack {
                Text("Version")
                Spacer()
                Text("0.1.0")
                    .foregroundStyle(.secondary)
            }
            HStack {
                Text("Build")
                Spacer()
                Text("1")
                    .foregroundStyle(.secondary)
            }
        } header: {
            Label("About", systemImage: "info.circle")
        }
    }

    // MARK: - Actions

    private func validateURL(_ urlString: String) {
        if urlString.isEmpty {
            urlValidationError = nil
            return
        }
        if DaemonClient.validateServerURL(urlString) != nil {
            urlValidationError = nil
        } else {
            urlValidationError = "Invalid URL. Use https:// for remote servers, or http://localhost for development."
        }
    }

    private func saveServerURL() {
        guard let url = DaemonClient.validateServerURL(urlInput) else {
            urlValidationError = "Invalid URL"
            return
        }
        serverURL = urlInput
        appState.reconfigure(baseURL: url)
        urlValidationError = nil
    }

    private func saveToken() {
        let trimmed = tokenInput.trimmingCharacters(in: .whitespacesAndNewlines)
        if tokenManager.setToken(trimmed) {
            hasToken = true
            tokenInput = ""
        }
    }

    private func removeToken() {
        tokenManager.clearToken()
        hasToken = false
        tokenInput = ""
    }

    private func testConnection() {
        isTestingConnection = true
        connectionTestResult = nil
        Task {
            let error = await appState.testConnection()
            await MainActor.run {
                isTestingConnection = false
                if let error = error {
                    connectionTestResult = ConnectionTestResult(success: false, message: error)
                } else {
                    connectionTestResult = ConnectionTestResult(success: true, message: "Connection successful")
                }
            }
        }
    }

    private func checkBiometricAvailability() {
        let (available, type) = BiometricAuth.checkAvailability()
        biometricAvailable = available
        biometricType = type
    }
}

// MARK: - Connection Test Result

private struct ConnectionTestResult {
    let success: Bool
    let message: String
}
